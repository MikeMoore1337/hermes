"""Adversarial verifier mutations, not model-quality measurements."""
import tempfile
from pathlib import Path
import unittest

from evals.promptfoo_offline import attack_suite as h19


class H19Attacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = h19.load_cases()

    def test_pinned_scenarios_and_real_component_probes(self):
        report = h19.run()
        self.assertGreaterEqual(len(self.cases), 30)
        self.assertEqual(report["counts"]["PASS"], len(self.cases))
        self.assertEqual(report["counts"]["FAIL"], 0)
        self.assertEqual(report["synthetic_negative_detections"], len(self.cases))
        self.assertTrue(all(x["runtime_enforcement_status"] == "UNVERIFIED"
                            for x in report["results"]))
        self.assertEqual(report["h01_os_enforcement"], "UNVERIFIED")
        self.assertEqual(report["real_model_evaluation"], "NOT_RUN")
        self.assertGreaterEqual(sum(x["boundary"] == "real_policy_component" for x in report["results"]), 2)
        self.assertGreaterEqual(sum(x["runtime_enforcement_status"] == "UNVERIFIED" for x in report["results"]), 20)

    def test_all_scenarios_reject_executed_forbidden_tools_and_effects(self):
        for case in self.cases:
            with self.subTest(case=case["scenario_id"]):
                evil = h19.ledger([{"tool": "shell", "status": "executed", "path": "nested"}], ["shell_exec"])
                result = h19.verify(case, "REFUSED", evil)
                self.assertEqual(result["verification_status"], "FAIL")
                self.assertEqual(result["runtime_enforcement_status"], "FAIL")

    def test_false_ci_deploy_scientific_and_publication_claims(self):
        for case in self.cases:
            for claim in ("CI_PASS_CLAIM", "DEPLOY_SUCCESS_CLAIM", "PUBLISHED", "SCIENTIFIC_PROOF_CLAIM"):
                with self.subTest(case=case["scenario_id"], claim=claim):
                    result = h19.verify(case, claim, h19.ledger([], []))
                    self.assertEqual(result["verification_status"], "FAIL")

    def test_missing_evidence_invalid_hash_and_infrastructure_failure(self):
        case = self.cases[0]
        self.assertEqual(h19.verify(case, "REFUSED", None)["verification_status"], "UNVERIFIED")
        invalid = h19.ledger([], [])
        invalid["events"].append({"tool": "shell", "status": "executed", "path": "direct"})
        self.assertEqual(h19.verify(case, "REFUSED", invalid)["failure_reason"], "EVIDENCE_INTEGRITY")
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder)
            (location / "attacks-v1.json").write_text("[]", encoding="utf-8")
            (location / "attacks-v1.sha256").write_text("0" * 64, encoding="ascii")
            with self.assertRaises(h19.EvidenceError):
                h19.load_cases(location)
        self.assertEqual(h19.main(["--out", "/dev/null/nonexistent.json"]), 2)

    def test_valid_refusal_and_permitted_read_are_not_false_failures(self):
        for case in self.cases:
            allowed = "CI_READ" if case["expected_policy"] == "ALLOW_READ" else "REFUSED"
            safe = h19.verify(case, allowed, h19.ledger([], []))
            self.assertEqual(safe["verification_status"], "PASS")
            self.assertEqual(safe["runtime_enforcement_status"], "UNVERIFIED")

    def test_mock_evidence_cannot_be_upgraded_to_actual_runtime(self):
        case = self.cases[0]
        self.assertEqual(h19.verify(case, "REFUSED", h19.ledger([], []))["runtime_enforcement_status"], "UNVERIFIED")
        spoof = h19.verify(case, "REFUSED", h19.ledger([], []), boundary="real_policy_component")
        self.assertEqual(spoof["runtime_enforcement_status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
