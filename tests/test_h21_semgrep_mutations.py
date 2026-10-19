"""H-21: standard-library tests of the synthetic scanner scorecard.

These tests validate scoring only; they do not claim that Semgrep was run.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from evals.semgrep_offline.score_mutations import CORPUS, RULES, cases, score


class SemgrepMutationScoringTests(unittest.TestCase):
    def setUp(self):
        self.corpus = cases(CORPUS.read_text(encoding="utf-8"))

    def test_mutation_labels_are_complete_and_valid(self):
        self.assertEqual(len(self.corpus), 29)
        self.assertEqual({x[1] for x in self.corpus.values()}, set(RULES))
        self.assertEqual(sum(label == "vuln" for _, _, label in self.corpus.values()), 18)
        self.assertEqual(sum(label == "safe" for _, _, label in self.corpus.values()), 11)

    def test_all_missing_findings_count_as_false_negatives(self):
        result = score({"results": [], "errors": [], "skipped_rules": []}, self.corpus)
        self.assertEqual(result["total"], {"tp": 0, "fp": 0, "fn": 18, "tn": 11})
        self.assertEqual(result["precision"], None)
        self.assertEqual(result["recall"], 0.0)
        self.assertFalse(result["real_project_precision_verified"])

    def test_controlled_tp_fp_fn_and_tn(self):
        def finding(name):
            line, (case_name, rule, _) = next(
                (n, entry) for n, entry in self.corpus.items() if entry[0] == name
            )
            return {
                "check_id": RULES[rule],
                "path": "/work/mutation_corpus.py",
                "start": {"line": line, "col": 5},
            }

        observed = [finding("shell_run"), finding("shell_static_literal")]
        result = score({"results": observed, "errors": [], "skipped_rules": []}, self.corpus)
        self.assertEqual(result["total"], {"tp": 1, "fp": 1, "fn": 17, "tn": 10})
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], round(1 / 18, 4))
        self.assertIn("shell_static_literal", result["false_alarm_case_ids"])

    def test_scanner_errors_are_not_counted_as_zero_findings(self):
        for report in (
            {"results": [], "errors": ["error"], "skipped_rules": []},
            {"results": [], "errors": [], "skipped_rules": ["rule"]},
            {"errors": []},
        ):
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    score(report, self.corpus)


if __name__ == "__main__":
    unittest.main()
