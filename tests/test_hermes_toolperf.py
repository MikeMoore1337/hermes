"""H-26: independent offline oracles for nine tool-efficiency failure modes."""
from __future__ import annotations

from copy import deepcopy
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_toolperf import core


class ToolperfContractTests(unittest.TestCase):
    def setUp(self):
        self.cases = core.load_cases()
        self.index = {c["task_id"]: c for c in self.cases}

    def test_nine_versioned_distinct_cases_and_sha256(self):
        self.assertEqual(len(self.cases), 9)
        self.assertEqual(len(self.index), 9)
        self.assertTrue(all(c["version"] == 1 for c in self.cases))
        self.assertTrue(all(len(core.fixture_sha256(c)) == 64 for c in self.cases))
        changed = deepcopy(self.cases[0])
        changed["candidate"].append({"op": "claim", "success": True})
        self.assertNotEqual(core.fixture_sha256(self.cases[0]),
                            core.fixture_sha256(changed))

    def test_candidates_prove_expected_state_and_observations(self):
        report = core.run(sha="a" * 40)
        self.assertEqual(report["candidate_passed"], 9)
        self.assertEqual(report["repository_sha"], "a" * 40)
        for row in report["results"]:
            with self.subTest(row=row["task_id"]):
                self.assertEqual(row["candidate"]["status"], "PASS")
                self.assertIn(row["verdict"], ("FIXED", "IMPROVED"))
                self.assertIsNone(row["candidate"]["tokens"])
                self.assertIsNone(row["candidate"]["model"])
                self.assertIsNone(row["candidate"]["actual_cost"])
                self.assertLessEqual(row["candidate"]["output_bytes"], 128)
        self.assertEqual(report["live_tool_latency"], "NOT_MEASURED")

    def test_repeated_patch_is_not_silently_idempotent(self):
        row = core.run_case(self.index["tp-02-duplicate-patch"])
        self.assertEqual(row["baseline"]["status"], "FAIL")
        self.assertIn("PATCH_MISMATCH", row["baseline"]["error_classes"])
        self.assertEqual(row["baseline"]["retries"], 1)
        self.assertEqual(row["candidate"]["status"], "PASS")

    def test_ambiguous_patch_and_wrong_case_fail(self):
        for ident, reason in (
            ("tp-03-ambiguous-patch", "AMBIGUOUS_PATCH"),
            ("tp-04-case-sensitive-path", "PATH_OUT_OF_SCOPE"),
        ):
            with self.subTest(ident=ident):
                row = core.run_case(self.index[ident])
                self.assertIn(reason, row["baseline"]["error_classes"])

    def test_hidden_file_requires_real_read_not_claim(self):
        row = core.run_case(self.index["tp-05-hidden-file"])
        self.assertIn("MISSING_READ_RECEIPT", row["baseline"]["error_classes"])
        self.assertIn("FALSE_SUCCESS_CLAIM", row["baseline"]["error_classes"])
        self.assertEqual(row["candidate"]["status"], "PASS")

    def test_output_bounded_for_large_stdout_and_chunked_file(self):
        for ident in ("tp-06-large-output", "tp-09-large-file-read"):
            row = core.run_case(self.index[ident])
            self.assertIn("OUTPUT_LIMIT", row["baseline"]["error_classes"])
            self.assertEqual(row["candidate"]["status"], "PASS")
            self.assertLessEqual(row["candidate"]["output_bytes"], 128)

    def test_scope_and_inline_script_are_rejected_without_side_effects(self):
        for ident, reason in (
            ("tp-07-multiple-directories", "PATH_OUT_OF_SCOPE"),
            ("tp-08-inline-script", "INLINE_SCRIPT_DENIED"),
        ):
            row = core.run_case(self.index[ident])
            self.assertIn(reason, row["baseline"]["error_classes"])
            self.assertEqual(row["candidate"]["status"], "PASS")

    def test_false_success_from_wrong_state_is_rejected(self):
        case = deepcopy(self.index["tp-07-multiple-directories"])
        case["candidate"] = [{"op": "claim", "success": True}]
        row = core.run_case(case)
        self.assertEqual(row["candidate"]["status"], "FAIL")
        self.assertIn("STATE_MISMATCH", row["candidate"]["error_classes"])
        self.assertIn("FALSE_SUCCESS_CLAIM", row["candidate"]["error_classes"])

    def test_extra_tools_fail_call_budget_even_if_state_is_correct(self):
        case = deepcopy(self.index["tp-02-duplicate-patch"])
        case["candidate"] = [
            {"op": "write", "path": "src/task.txt", "content": "new\n"},
            {"op": "claim", "success": True},
            {"op": "claim", "success": True},
        ]
        row = core.run_case(case)
        self.assertIn("EXCESS_TOOL_CALLS", row["candidate"]["error_classes"])
        self.assertIn("FALSE_SUCCESS_CLAIM", row["candidate"]["error_classes"])

    def test_invalid_scope_traversal_and_fixture_fail_closed(self):
        case = deepcopy(self.index["tp-02-duplicate-patch"])
        case["candidate"] = [
            {"op": "write", "path": "../secrets", "content": "x"},
        ]
        self.assertIn("INVALID_PATH", core.run_case(case)["candidate"]["error_classes"])
        case = deepcopy(self.index["tp-02-duplicate-patch"])
        case["initial_files"] = {"../outside": "secret"}
        with patch.object(core, "CASES", [case] * 9):
            with self.assertRaises(core.ToolperfError):
                core.load_cases()
        with self.assertRaises(core.ToolperfError):
            core.run(sha="not-a-sha")

    def test_no_real_network_subprocess_or_host_file_reads(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network attempted")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("subprocess attempted")):
            report = core.run()
        self.assertEqual(report["candidate_passed"], 9)

    def test_report_format_records_unknown_live_performance(self):
        report = core.run(sha="b" * 40)
        text = core.markdown(report)
        self.assertIn("NOT_MEASURED", text)
        self.assertIn("tp-09-large-file-read", text)
        self.assertIn("candidate PASS: 9", text)


if __name__ == "__main__":
    unittest.main()
