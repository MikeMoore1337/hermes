"""No-network Docker command contract and fail-closed synthetic JSON tests."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import probe_h18_ssh_network_denial as probe


def packet(**changes):
    data = {
        "schema": probe.SCHEMA,
        "test_net_connect_errno": 101,
        "tested_names": ["terminal", "process"],
        "native_executor_reached": False,
        "registry_dispatch_reached": False,
        "process_spawn_attempted": False,
        "all_execution_boundaries_mocked": True,
        "model_or_real_ssh_executed": False,
    }
    data.update(changes)
    return json.dumps(data).encode()


class SSHDenyTest(unittest.TestCase):
    def test_synthetic_network_and_native_denials_do_not_grant_go(self):
        r = probe.parse(packet())
        self.assertEqual(r["status"], "NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS")
        self.assertTrue(r["os_network_none_egress_denied"])
        self.assertTrue(r["native_and_process_mock_boundaries_unreached"])
        for k in ("resident_agent_allowed", "production_os_policy_verified",
                  "mcp_tool_enforcement_verified", "all_native_tools_verified"):
            self.assertFalse(r[k])

    def test_non_denial_network_result_is_not_pass(self):
        for number in (0, 110, 111, -1):
            with self.subTest(number=number):
                r = probe.parse(packet(test_net_connect_errno=number))
                self.assertEqual(r["status"], "DENIAL_BOUNDARY_NOT_PROVEN")

    def test_reaching_native_executor_fails(self):
        for key in ("native_executor_reached", "registry_dispatch_reached",
                    "process_spawn_attempted", "model_or_real_ssh_executed"):
            with self.subTest(key=key):
                self.assertEqual(probe.parse(packet(**{key: True}))["status"],
                                 "DENIAL_BOUNDARY_NOT_PROVEN")

    def test_insufficient_mocking_fails(self):
        self.assertEqual(probe.parse(packet(all_execution_boundaries_mocked=False))["status"],
                         "DENIAL_BOUNDARY_NOT_PROVEN")

    def test_schema_or_cases_rejected(self):
        for payload in (packet(schema="wrong"), packet(tested_names=["terminal"]),
                        packet(unknown=True), packet(test_net_connect_errno="101")):
            with self.subTest(payload=payload[:65]):
                with self.assertRaises(probe.ProbeDenied):
                    probe.parse(payload)

    def test_duplicate_json_key_and_too_large_rejected(self):
        with self.assertRaisesRegex(probe.ProbeDenied, "duplicate_json_key"):
            probe.parse(b'{"x":1,"x":2}')
        with self.assertRaises(probe.ProbeDenied):
            probe.parse(b"x" * (probe.MAX_JSON_BYTES + 1))

    def test_exact_docker_network_identity_resource_guard(self):
        inspect, run = probe.commands()
        self.assertEqual(inspect[:4], ["docker", "image", "inspect", probe.IMAGE])
        for tokens in (("--pull=never",), ("--network", "none"), ("--read-only",),
                       ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
                       ("--user", "65534:65534")):
            self.assertIn(tokens[0], run)
            if len(tokens) > 1:
                self.assertEqual(run[run.index(tokens[0]) + 1], tokens[1])
        self.assertNotIn("--volume", run)
        self.assertNotIn("-v", run)
        self.assertNotIn("--privileged", run)
        self.assertEqual(run[-3:], ["-B", "-c", probe.INSPECTOR])
        self.assertIn("192.0.2.1", probe.INSPECTOR)
        self.assertIn("patch.object(subprocess, \"Popen\"", probe.INSPECTOR)

    def test_observe_routed_through_runner_only(self):
        def runner(args, **kwargs):
            if args[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(args, 0, (probe.IMAGE + "|linux|amd64\n").encode(), b"")
            return subprocess.CompletedProcess(args, 0, packet(), b"")
        r = probe.observe(runner)
        self.assertEqual(r["status"], "NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS")

    def test_wrong_image_identity_cannot_pass(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b"sha256:fake|linux|amd64", b""))
        with self.assertRaisesRegex(probe.ProbeDenied, "wrong_image_identity"):
            probe.observe(runner)
        self.assertEqual(runner.call_count, 1)

    def test_docker_failure_denied_without_logs(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 1, b"PRIVATE_BLOB", b"PRIVATE_TOKEN"))
        with self.assertRaises(probe.ProbeDenied):
            probe.observe(runner)

    def test_cli_default_no_docker(self):
        with patch.object(probe, "observe", side_effect=AssertionError("must not run")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(probe.main([]), 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")

    def test_cli_invalid_evidence_no_pass_no_leak(self):
        out = io.StringIO()
        with patch.object(probe, "observe", side_effect=probe.ProbeDenied("PRIVATE_CODE")):
            with contextlib.redirect_stdout(out):
                self.assertEqual(probe.main(["--execute"]), 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertFalse(result["resident_agent_allowed"])
        self.assertNotIn("PRIVATE_CODE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
