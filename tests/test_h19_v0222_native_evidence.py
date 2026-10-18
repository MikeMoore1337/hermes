"""No AI, Docker or external service is run by these contract unit tests."""
import io
import json
from unittest import TestCase
from unittest.mock import Mock, patch

from scripts import h19_v0222_native_evidence as evidence
from scripts import verify_v0221_native_tool_policy as policy
from scripts import verify_v0222_immutable as image


def packet(mode):
    cases = {name: {"exception": False, "executor_reached": False}
             for name in policy.REQUIRED_CASES}
    if mode == "original":
        for name in ("direct_terminal", "direct_alias", "agent_stale_native",
                     "agent_full_loop", "request_hook_error", "pre_hook_error",
                     "approval_error", "execution_hook_error", "registry_policy_error"):
            cases[name]["executor_reached"] = True
    else:
        cases["direct_allowed"]["executor_reached"] = True
        cases["execution_arg_recheck"].update(
            executor_reached=True, modified_approval_seen=True)
        cases["subagent_scope"].update(
            terminal_in_child=False, terminal_in_disabled=True)
    cases["execute_code_nested_scope"].update(
        executor_reached=True,
        nested_terminal_allowed=mode == "original",
        nested_web_search_allowed=True)
    cases["parallel_policy"].update(
        executor_reached=True,
        restricted_executor_reached=mode == "original",
        allowed_executor_reached=True)
    return json.dumps({
        "schema": policy.SCHEMA, "mode": mode, "cases": cases,
        "secret_exposed": False, "model_executed": False, "real_tool_executed": False,
    }).encode()


def observations(*, original=None, patched=None, os_probe=None):
    original = original or packet("original")
    patched = patched or packet("patched")
    os_probe = os_probe or {
        "nonroot": True, "network_egress_probe_denied": True,
        "runtime_path_write_denied": True, "docker_socket_absent": True,
        "shell_binary_present": True, "credentials_injected": False,
    }
    records = [
        json.dumps(["docker.io/nousresearch/hermes-agent@" + image.IMAGE_DIGEST]).encode() + b"|amd64",
        json.dumps({"fields": {"commit": image.EXPECTED_SOURCE},
                    "keys": ["commit"], "python": "3.14.7"}).encode(),
        ("sha256:" + "a" * 64 + "|amd64").encode(),
        original, patched, json.dumps(os_probe).encode(),
    ]
    return Mock(side_effect=[Mock(returncode=0, stdout=item) for item in records])


class NativeEvidenceTests(TestCase):
    def test_synthetic_executor_traces_from_pinned_code_are_scored(self):
        runner = observations()
        status, report = evidence.run(runner=runner)
        self.assertEqual(status, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["native_case_count"], len(policy.REQUIRED_CASES))
        self.assertTrue(report["original_native_dispatch_gap_observed"])
        self.assertTrue(report["patched_native_policy_bounded"])
        self.assertEqual(report["os_probe_status"], "PASS")
        self.assertFalse(report["full_runtime_permission_enforcement_verified"])
        self.assertFalse(report["shell_execution_denial_verified"])
        self.assertEqual(report["real_model_evaluation"], "NOT_RUN")
        self.assertFalse(report["resident_agent_allowed"])
        self.assertEqual(runner.call_count, 6)

    def test_incomplete_patch_or_observed_network_access_is_fail(self):
        original = packet("original")
        patched = json.loads(packet("patched"))
        patched["cases"]["direct_terminal"]["executor_reached"] = True
        status, report = evidence.run(runner=observations(
            original=original, patched=json.dumps(patched).encode()))
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["patched_native_policy_bounded"])
        status, report = evidence.run(runner=observations(os_probe={
            "nonroot": True, "network_egress_probe_denied": False,
            "runtime_path_write_denied": True, "docker_socket_absent": True,
            "shell_binary_present": True, "credentials_injected": False}))
        self.assertEqual(status, 1)
        self.assertEqual(report["os_probe_status"], "FAIL")

    def test_invalid_or_missing_metadata_fails_closed(self):
        runner = observations()
        runner.side_effect = [Mock(returncode=0, stdout=b"garbage|amd64")]
        status, report = evidence.run(runner=runner)
        self.assertEqual(status, 2)
        self.assertEqual(report["status"], "INFRA_FAILURE")
        self.assertFalse(report["resident_agent_allowed"])

    def test_real_commands_have_no_host_mount_or_network(self):
        _, _, origin = image.commands()
        _, derivative = image.patched_commands()
        for cmd in (origin, derivative):
            self.assertIn("--network", cmd)
            self.assertIn("none", cmd)
            self.assertIn("--read-only", cmd)
            self.assertIn("--pull=never", cmd)
            self.assertIn("65534:65534", cmd)
            self.assertNotIn("--privileged", cmd)
            self.assertNotIn("--volume", cmd)
            self.assertNotIn("--env-file", cmd)
            self.assertNotIn("--network=host", cmd)

    def test_default_no_execution(self):
        with patch.object(evidence, "run") as real:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(evidence.main([]), 0)
            real.assert_not_called()
        self.assertIn("NOT_RUN", out.getvalue())


if __name__ == "__main__":
    import unittest
    unittest.main()
