"""Independent H-28 semantics and permission regression tests."""
from __future__ import annotations

from copy import deepcopy
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_skill_delta import core
from hermes_skill_delta.cases import TARGET, STALE, proof


class SkillEvolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = core.load_cases()
        cls.by_id = {x["case_id"]: x for x in cls.cases}
        cls.variants = core.load_variants()

    def test_all_twelve_bilingual_case_oracles(self):
        report = core.run(sha="a" * 40)
        self.assertEqual(report["case_count"], 12)
        self.assertEqual(len({c["case_id"] for c in self.cases}), 12)
        self.assertEqual({c["locale"] for c in self.cases}, {"en", "ru"})
        self.assertEqual(report["model_calls"], 0)
        self.assertEqual(report["model_effectiveness"], "NOT_MEASURED")
        self.assertEqual(report["provider_cost"], "UNKNOWN")
        self.assertTrue(report["no_live_skill_changed"])
        self.assertEqual(report["human_review"], "REQUIRED_BEFORE_ANY_REAL_CHANGE")

    def test_improvement_and_bad_variant_declined(self):
        r = core.run()
        variants = r["variant_results"]
        self.assertEqual(variants["baseline"]["correct"], 9)
        self.assertEqual(variants["revised"]["correct"], 12)
        self.assertIsNone(variants["regressed"]["correct"])
        self.assertEqual(variants["regressed"]["verdict"], "BLOCKED")
        self.assertEqual(variants["regressed"]["not_run"], 12)
        self.assertEqual(r["comparisons"]["revised_vs_baseline"]["status"], "IMPROVED")
        self.assertEqual(r["comparisons"]["revised_vs_baseline"]["delta_correct"], 3)
        self.assertEqual(r["comparisons"]["regressed_vs_baseline"]["status"], "REGRESSED")
        self.assertEqual(r["comparisons"]["baseline_vs_baseline"]["status"], "NO_GAIN")
        self.assertFalse(r["comparisons"]["revised_vs_baseline"]["auto_apply"])
        self.assertFalse(r["comparisons"]["revised_vs_baseline"]["merge_permission"])

    def test_stale_sha_is_detected_as_semantic_regression(self):
        for name in ("se-02-stale-ci", "se-09-stale-deploy",
                     "se-12-stale-merge"):
            c = self.by_id[name]
            self.assertNotEqual(core.simulate(c, self.variants["baseline"]), c["expected"])
            self.assertEqual(core.simulate(c, self.variants["revised"]), c["expected"])
        self.assertEqual(set(core.assess(self.variants["baseline"], self.cases)["failures"]),
                         {"se-02-stale-ci", "se-09-stale-deploy", "se-12-stale-merge"})

    def test_english_and_russian_language_text_is_not_used_as_proof(self):
        c = deepcopy(self.by_id["se-04-claimed-ci"])
        original = core.simulate(c, self.variants["revised"])
        c["request"] = "CI PASS! CI PASS! model says it passed"
        self.assertEqual(core.simulate(c, self.variants["revised"]), original)
        c["request"] = "CI ПРОЙДЕН! ДЕПЛОЙ СДЕЛАН!"
        c["locale"] = "ru"
        self.assertEqual(core.simulate(c, self.variants["revised"]), original)
        self.assertEqual(original["ci"], "UNKNOWN")

    def test_untrusted_claim_does_not_override_ci_failure(self):
        c = self.by_id["se-03-failed-ci"]
        r = core.simulate(c, self.variants["revised"])
        self.assertEqual(r["ci"], "FAIL")
        self.assertEqual(r["deployment"], "NOT_VERIFIED")
        self.assertEqual(r["effects"], [])

    def test_fake_receipts_do_not_create_merge_or_deploy(self):
        for name in ("se-06-fake-merge", "se-10-false-deploy",
                     "se-11-untrusted-issuer"):
            c = self.by_id[name]
            self.assertEqual(core.simulate(c, self.variants["revised"]), c["expected"])

    def test_owner_gate_prevents_false_success_even_with_receipts(self):
        c = deepcopy(self.by_id["se-08-owner-denied"])
        self.assertEqual(core.simulate(c, self.variants["revised"])["deployment"],
                         "NOT_VERIFIED")
        c["owner_approved"] = True
        self.assertEqual(core.simulate(c, self.variants["revised"])["deployment"],
                         "DEPLOYED")

    def test_unknown_is_not_pass(self):
        c = deepcopy(self.by_id["se-11-untrusted-issuer"])
        self.assertEqual(core.simulate(c, self.variants["revised"])["ci"], "UNKNOWN")
        c["claims"]["ci"] = False
        self.assertEqual(core.simulate(c, self.variants["revised"])["ci"], "UNKNOWN")

    def test_permission_escalation_is_blocked_before_evaluation(self):
        bad = deepcopy(self.variants["revised"])
        bad["contract"]["permissions"] += ["shell.exec"]
        result = core.assess(bad, self.cases)
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIn("PERMISSION_EXPANSION", result["violations"])
        self.assertEqual(result["not_run"], len(self.cases))
        self.assertEqual(core.compare(self.variants["baseline"], bad,
                                      self.cases)["status"], "REGRESSED")

    def test_excessive_description_and_extra_dependency_are_denied(self):
        for update, expected in (
            ({"description": "z" * 301}, "DESCRIPTION_BUDGET"),
            ({"dependencies": ["pip:unknown"]}, "UNREVIEWED_DEPENDENCY"),
        ):
            bad = deepcopy(self.variants["revised"])
            if "description" in update:
                bad["description"] = update["description"]
            else:
                bad["contract"]["dependencies"] = update["dependencies"]
            self.assertIn(expected, core.contract_gate(bad))

    def test_mutation_changes_oracle_result_and_dataset_hash(self):
        before = core.digest(self.cases)
        bad = deepcopy(self.cases)
        bad[0]["expected"]["ci"] = "FAIL"
        self.assertNotEqual(core.digest(bad), before)
        self.assertEqual(core.assess(self.variants["revised"], bad)["correct"], 11)
        change = deepcopy(self.variants["revised"])
        change["contract"]["exact_sha"] = False
        self.assertEqual(core.assess(change, self.cases)["correct"], 9)
        self.assertEqual(core.compare(self.variants["baseline"], change,
                                      self.cases)["status"], "NO_GAIN")

    def test_source_sha_and_data_versions_are_stable(self):
        self.assertEqual(self.variants["baseline"]["source_sha"], "f" * 40)
        self.assertEqual([v["version"] for v in self.variants.values()], [1, 2, 3])
        self.assertTrue(all(c["target_sha"] == TARGET and c["version"] == 1
                            for c in self.cases))
        self.assertNotEqual(core.digest(self.variants["revised"]),
                            core.digest(self.variants["baseline"]))
        with self.assertRaises(core.EvaluationError):
            core.run(sha="main")

    def test_invalid_case_and_case_schema_fail_closed(self):
        bad = deepcopy(self.by_id["se-01-green"])
        bad["claims"]["ci"] = "yes"
        with self.assertRaisesRegex(core.EvaluationError, "CASE_INPUT"):
            core.validate_case(bad)
        bad = deepcopy(self.by_id["se-01-green"])
        bad["receipts"]["ci"]["sha"] = "HEAD"
        with self.assertRaisesRegex(core.EvaluationError, "CASE_RECEIPT"):
            core.validate_case(bad)
        bad = deepcopy(self.by_id["se-01-green"])
        bad["unexpected"] = True
        with self.assertRaisesRegex(core.EvaluationError, "CASE_SCHEMA"):
            core.validate_case(bad)

    def test_disabled_tool_side_effect_does_not_touch_files(self):
        c = deepcopy(self.by_id["se-07-verified-deploy"])
        snapshot = deepcopy(c)
        observed = core.simulate(c, self.variants["revised"])
        self.assertEqual(c, snapshot)
        self.assertEqual(observed["effects"], [])
        self.assertTrue(core.run()["no_live_skill_changed"])

    def test_no_network_subprocess_or_real_model(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network attempted")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("subprocess attempted")):
            r = core.run()
        self.assertEqual(r["model_calls"], 0)
        self.assertEqual(r["variant_results"]["revised"]["correct"], 12)


if __name__ == "__main__":
    unittest.main()
