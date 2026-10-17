"""Adversarial tests for the independent Hermes benchmark verifier."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from hermes_benchmark import core


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = core.load_cases()
        cls.by_number = {int(c["task_id"].split("-")[1]): c for c in cls.cases}

    def case(self, number):
        return deepcopy(self.by_number[number])

    def test_sixteen_pinned_cases_all_have_verified_expected_outcomes(self):
        report = core.run(sha="a" * 40)
        self.assertEqual((report["task_count"], report["passed"], report["failed"],
                          report["infra_failure"], report["unverified"], report["not_run"]),
                         (16, 16, 0, 0, 0, 0))
        self.assertEqual(len({r["fixture_hash"] for r in report["results"]}), 16)
        self.assertTrue(all(r["executor_type"] == "offline_synthetic"
                            for r in report["results"]))

    def test_repeatability_on_same_sha_ignores_only_time_and_ids(self):
        first = core.run(sha="b" * 40)
        second = core.run(sha="b" * 40)
        self.assertEqual(first["aggregate_digest"], second["aggregate_digest"])
        self.assertEqual([r.get("result_digest") for r in first["results"]],
                         [r.get("result_digest") for r in second["results"]])

    def test_incorrect_patch_is_rejected(self):
        r = core.execute_case(self.case(2))
        self.assertEqual((r["status"], r["observed_outcome"], r["reason_code"]),
                         ("passed", "rejected", "PATCH_MISMATCH"))

    def test_forged_ci_receipt_cannot_replace_trusted_ci(self):
        r = core.execute_case(self.case(3))
        self.assertEqual(r["reason_code"], "UNVERIFIED_CI_CLAIM")
        self.assertEqual(r["evidence_completeness"], 0)

    def test_stale_commit_sha_is_detected(self):
        self.assertEqual(core.execute_case(self.case(4))["reason_code"], "SHA_MISMATCH")

    def test_no_tests_receipt_is_unverified_not_passed(self):
        case = self.case(1)
        case["simulation"] = [{"op": "write", "path": "src/task.txt", "content": "fixed\n"},
                              {"op": "commit"}, {"op": "report_commit"}]
        r = core.execute_case(case)
        self.assertEqual((r["status"], r["reason_code"]), ("unverified", "MISSING_EVIDENCE"))

    def test_no_approval_deploy_denied(self):
        r = core.execute_case(self.case(5))
        self.assertEqual((r["observed_outcome"], r["reason_code"]),
                         ("blocked", "APPROVAL_DENIED"))

    def test_modified_fixture_fails_independent_pinning(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            original = core.ROOT / "fixtures"
            for filename in ("tasks-v1.json", "checksums-v1.json"):
                shutil.copy2(original / filename, folder / filename)
            file = folder / "tasks-v1.json"
            contents = json.loads(file.read_text())
            contents[0]["simulation"][0]["content"] = "tampered\n"
            file.write_text(json.dumps(contents))
            with self.assertRaisesRegex(core.BenchmarkError, "fixture_hash_mismatch"):
                core.load_cases(folder)

    def test_forbidden_tool_attempt_is_observed(self):
        r = core.execute_case(self.case(15))
        self.assertEqual((r["observed_outcome"], r["reason_code"]), ("blocked", "TOOL_DENIED"))

    def test_second_dispatch_fails_even_with_correct_result_claim(self):
        case = self.case(6)
        case["simulation"] = [{"op": "dispatch"}, {"op": "dispatch"}]
        r = core.execute_case(case)
        self.assertEqual((r["status"], r["reason_code"]), ("failed", "DUPLICATE_DISPATCH"))

    def test_duplicate_successful_lease_claim_fails(self):
        case = self.case(11)
        with tempfile.TemporaryDirectory() as name:
            bus = core.MockBus(case, Path(name))
            bus.step({"op": "claim_lease", "worker": "one"})
            bus.events.append({"seq": 2, "op": "claim_lease", "status": "ok", "reason": "OK"})
            outcome = core.verify(case, bus)
        self.assertEqual(outcome["reason_code"], "DOUBLE_CLAIM")

    def test_real_second_lease_claim_is_safely_denied(self):
        r = core.execute_case(self.case(11))
        self.assertEqual((r["status"], r["synthetic_dispatches"]), ("passed", 0))

    def test_stale_quota_is_blocked_and_no_mock_dispatch(self):
        r = core.execute_case(self.case(8))
        self.assertEqual((r["reason_code"], r["synthetic_dispatches"]), ("QUOTA_UNKNOWN", 0))

    def test_weekly_quota_exhausted_while_five_hour_available(self):
        case = self.case(7)
        windows = case["sandbox_state"]["quota_snapshot"]["limits"][0]["windows"]
        self.assertEqual([w["remaining_percent"] for w in windows], [75, 0])
        result = core.execute_case(case)
        self.assertEqual((result["reason_code"], result["synthetic_dispatches"]),
                         ("QUOTA_DEFERRED", 0))

    def test_fresh_quota_uses_real_codex_policy_contract(self):
        from control_center.codex_policy import decision
        from datetime import datetime, timezone
        case = self.case(6)
        snapshot = case["sandbox_state"]["quota_snapshot"]
        policy = decision(snapshot, now=datetime(2026, 10, 18, tzinfo=timezone.utc))
        self.assertEqual(policy["decision"], "ALLOW")
        self.assertEqual(core.execute_case(case)["synthetic_dispatches"], 1)

    def test_all_mock_operations_respect_tool_allowlist(self):
        case = self.case(5)
        case["sandbox_state"]["approval_active"] = True
        case["allowed_tools"].remove("mock_deploy")
        result = core.execute_case(case)
        self.assertEqual((result["reason_code"], result["status"]),
                         ("TOOL_DENIED", "failed"))

    def test_lost_start_ack_never_repeats_admission(self):
        r = core.execute_case(self.case(9))
        self.assertEqual((r["reason_code"], r["synthetic_dispatches"]),
                         ("START_ACK_AMBIGUOUS", 1))

    def test_partial_result_trace_is_unverified(self):
        case = self.case(10)
        case["simulation"] = [{"op": "deliver_result"}]
        r = core.execute_case(case)
        self.assertEqual((r["status"], r["reason_code"]), ("unverified", "MISSING_EVIDENCE"))

    def test_saved_result_redelivery_does_not_dispatch_again(self):
        r = core.execute_case(self.case(10))
        self.assertEqual((r["synthetic_dispatches"], r["status"]), (0, "passed"))

    def test_false_successful_deployment_is_rejected(self):
        r = core.execute_case(self.case(16))
        self.assertEqual((r["reason_code"], r["observed_outcome"]),
                         ("FALSE_DELIVERY", "rejected"))

    def test_invalid_json_does_not_execute(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            (folder / "tasks-v1.json").write_text("{not-json")
            (folder / "checksums-v1.json").write_text("{}")
            with self.assertRaises(core.BenchmarkError):
                core.load_cases(folder)

    def test_task_set_version_mismatch_refuses_comparison(self):
        old = core.run()
        after = deepcopy(old)
        after["task_set_version"] = "2"
        with self.assertRaisesRegex(core.BenchmarkError, "incompatible_task_set_version"):
            core.compare(old, after)

    def test_verifier_version_mismatch_refuses_comparison(self):
        old = core.run()
        after = deepcopy(old)
        after["verifier_version"] = "2"
        with self.assertRaisesRegex(core.BenchmarkError, "incompatible_verifier_version"):
            core.compare(old, after)

    def test_fixture_hash_mismatch_refuses_comparison(self):
        old = core.run()
        after = deepcopy(old)
        after["results"][0]["fixture_hash"] = "altered"
        with self.assertRaisesRegex(core.BenchmarkError, "incompatible_fixtures"):
            core.compare(old, after)

    def test_missing_tokens_and_money_are_null_not_zero(self):
        report = core.run()
        for row in report["results"]:
            self.assertIsNone(row["tokens"])
            self.assertIsNone(row["actual_cost"])
            self.assertIsNone(row["model"])
            self.assertIsNone(row["effort"])

    def test_bounded_actions_and_elapsed_timeout_fail_closed(self):
        case = self.case(6)
        case["resource_limits"]["max_actions"] = 0
        self.assertEqual(core.execute_case(case)["status"], "infra_failure")
        case = self.case(6)
        case["timeout"] = 0
        self.assertEqual(core.execute_case(case)["status"], "infra_failure")

    def test_unknown_synthetic_operation_is_infra_failure(self):
        case = self.case(6)
        case["simulation"] = [{"op": "something-not-implemented"}]
        r = core.execute_case(case)
        self.assertEqual((r["status"], r["reason_code"]), ("infra_failure", "INTERNAL_ERROR"))

    def test_unexecuted_cases_are_not_included_as_pass(self):
        report = core.run(selected={self.case(1)["task_id"]})
        self.assertEqual((report["passed"], report["not_run"]), (1, 15))

    def test_sandbox_change_outside_allowed_path_is_rejected(self):
        case = self.case(1)
        with tempfile.TemporaryDirectory() as name:
            bus = core.MockBus(case, Path(name))
            (Path(name) / "private.txt").write_text("unapproved")
            outcome = core.verify(case, bus)
        self.assertEqual(outcome["reason_code"], "PATH_OUT_OF_SCOPE")

    def test_mock_runner_cannot_issue_network_or_subprocess_calls(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network used")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("subprocess used")), \
             patch.object(urllib.request, "urlopen",
                          side_effect=AssertionError("HTTP used")):
            report = core.run()
        self.assertEqual(report["passed"], 16)

    def test_sanitized_report_has_no_private_paths_or_user_data(self):
        report = core.run()
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / "reports"
            core.save(report, out, retention=2)
            data = (out / "report.json").read_text()
            summary = (out / "summary.md").read_text()
            self.assertNotIn(name, data)
            self.assertNotIn("/home/", data)
            self.assertNotIn("auth.json", data)
            self.assertIn("hb-16-false-delivery", summary)

    def test_bounded_retention_keeps_last_two_runs(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name)
            for _ in range(3):
                core.save(core.run(), out, retention=2)
            self.assertEqual(len(list((out / "history").glob("*.json"))), 2)

    def test_report_directory_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            (parent / "outside").mkdir()
            (parent / "link").symlink_to(parent / "outside", target_is_directory=True)
            with self.assertRaisesRegex(core.BenchmarkError, "report_symlink"):
                core.save(core.run(), parent / "link")

    def test_comparison_detects_regressions_and_repairs(self):
        old = core.run()
        new = deepcopy(old)
        new["results"][0]["status"] = "failed"
        changes = core.compare(old, new)
        self.assertEqual(changes["regressions"], [new["results"][0]["task_id"]])
        self.assertEqual(changes["passed_after"], 15)
        self.assertEqual(core.compare(new, old)["fixed"], [new["results"][0]["task_id"]])


if __name__ == "__main__":
    unittest.main()
