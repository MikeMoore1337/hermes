"""Independent mutation/negative tests for #476, synthetic-only."""
from __future__ import annotations
from copy import deepcopy
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_decision_eval import core


class AlternativesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c["case_id"]: c for c in core.load_cases()}

    def test_twelve_verified_and_explicit_model_limits(self):
        r = core.run(sha="f" * 40)
        self.assertEqual((r["case_count"], r["passed"]), (12, 12))
        self.assertEqual((r["chosen_incumbent"], r["chosen_revision"], r["chosen_synthesis"]), (10, 1, 1))
        self.assertEqual(len({x["case_id"] for x in r["cases"]}), 12)
        self.assertEqual(len({x["fixture_sha256"] for x in r["cases"]}), 12)
        self.assertEqual(r["model_calls"], 0)
        self.assertEqual(r["actual_model_quality"], "NOT_MEASURED")
        self.assertEqual(r["actual_latency"], "NOT_MEASURED")
        self.assertEqual(r["provider_cost"], "UNKNOWN")
        self.assertTrue(all(x["oracle"] == "PASS" and
                            x["approval_for_merge_or_deploy"] is False for x in r["cases"]))

    def test_made_up_defect_and_majority_cannot_override_proof(self):
        for name in ("ar-01-no-defect", "ar-05-false-majority"):
            with self.subTest(name=name):
                x = core.run_case(self.cases[name])
                self.assertEqual((x["winner"], x["stop_reason"]), ("A", "UNSUPPORTED_CLAIMS"))
                self.assertFalse(x["evaluations"]["B"]["eligible"])
                self.assertEqual(x["verified_delta"], 0)

    def test_required_facts_and_scope_are_hard_constraints(self):
        req = core.run_case(self.cases["ar-02-regressed-constraints"])
        self.assertEqual((req["winner"], req["stop_reason"]), ("A", "REQUIREMENT_REGRESSION"))
        self.assertIn("REQUIREMENT_REGRESSION", req["evaluations"]["B"]["reasons"])
        scope = core.run_case(self.cases["ar-07-scope-creep"])
        self.assertEqual((scope["winner"], scope["stop_reason"]), ("A", "SCOPE_VIOLATION"))
        self.assertIsNone(scope["evaluations"]["B"]["score"])

    def test_verified_improvements_require_positive_delta(self):
        for name, winner in (("ar-03-real-improvement", "B"),
                             ("ar-04-synthesis-wins", "AB")):
            with self.subTest(name=name):
                x = core.run_case(self.cases[name])
                self.assertEqual(x["winner"], winner)
                self.assertEqual(x["stop_reason"], "IMPROVEMENT_VERIFIED")
                self.assertGreater(x["verified_delta"], 0)

    def test_unverified_scientific_proof_and_no_gain_keep_a(self):
        x = core.run_case(self.cases["ar-06-unverified-sources"])
        self.assertEqual((x["winner"], x["stop_reason"]), ("A", "UNVERIFIED_EVIDENCE"))
        self.assertIsNone(x["evaluations"]["B"]["score"])
        x = core.run_case(self.cases["ar-08-no-gain"])
        self.assertEqual((x["winner"], x["stop_reason"], x["verified_delta"]),
                         ("A", "NO_PROVEN_GAIN", 0))

    def test_untrusted_judge_and_exhausted_budget_skip_challengers(self):
        for name, reason in (("ar-09-budget-exhausted", "BUDGET_EXHAUSTED"),
                             ("ar-10-untrusted-judge", "JUDGE_UNTRUSTED")):
            with self.subTest(name=name):
                x = core.run_case(self.cases[name])
                self.assertEqual((x["winner"], x["stop_reason"]), ("A", reason))
                self.assertEqual((x["review_budget_used"], x["iteration_count"]), (1, 0))
                self.assertEqual(x["evaluations"]["B"]["reasons"], ["NOT_RUN"])
                self.assertIsNone(x["evaluations"]["AB"]["score"])

    def test_step_limit_and_untrusted_approval(self):
        x = core.run_case(self.cases["ar-11-step-budget"])
        self.assertEqual((x["winner"], x["stop_reason"]), ("A", "STEP_BUDGET"))
        c = deepcopy(self.cases["ar-12-no-owner-approval"])
        a = core.choose(c)
        for x in c["candidates"].values():
            x["claimed_approval"] = not x["claimed_approval"]
            x["self_score"] = 99
        b = core.choose(c)
        self.assertEqual((a["winner"], a["stop_reason"]), (b["winner"], b["stop_reason"]))

    def test_blind_order_invariance_even_on_ties(self):
        orders = (("A", "B", "AB"), ("AB", "B", "A"),
                  ("B", "A", "AB"), ("B", "AB", "A"))
        for c in core.load_cases():
            before = core.choose(c)
            for order in orders:
                after = core.choose(c, permutation=order)
                self.assertEqual((before["winner"], before["stop_reason"]),
                                 (after["winner"], after["stop_reason"]))
        with self.assertRaises(core.EvalError):
            core.choose(self.cases["ar-01-no-defect"], permutation=("A", "B", "B"))

    def test_independent_oracle_detects_mutated_expected_and_candidates(self):
        original = self.cases["ar-03-real-improvement"]
        self.assertEqual(core.run_case(original)["oracle"], "PASS")
        for mutation in ("expected", "proof", "facts"):
            c = deepcopy(original)
            if mutation == "expected":
                c["expected"]["winner"] = "AB"
            elif mutation == "proof":
                c["candidates"]["B"]["proofs"] = []
            else:
                c["candidates"]["B"]["claims"].remove("root_cause")
                c["candidates"]["B"]["proofs"].remove("proof:root_cause")
            with self.subTest(mutation=mutation):
                self.assertEqual(core.run_case(c)["oracle"], "FAIL")

    def test_invalid_fixture_and_unknown_sha_fail_closed(self):
        for field, changed in (("budget", True), ("base_sha", "main"),
                               ("judge", "approve-anything")):
            c = deepcopy(self.cases["ar-01-no-defect"])
            c[field] = changed
            with self.assertRaises(core.EvalError):
                core.validate(c)
        c = deepcopy(self.cases["ar-03-real-improvement"])
        c["candidates"]["A"]["claims"].append("reproduce")
        with self.assertRaises(core.EvalError):
            core.validate(c)
        with self.assertRaises(core.EvalError):
            core.run(sha="main")
        c = deepcopy(self.cases["ar-01-no-defect"])
        prior = core.sha256(c)
        c["truth"]["working"] += 1
        self.assertNotEqual(prior, core.sha256(c))

    def test_no_real_devices_subprocess_or_network(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            x = core.run()
        self.assertEqual(x["passed"], 12)
        self.assertEqual(x["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
