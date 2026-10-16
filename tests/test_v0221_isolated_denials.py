"""Offline OS isolation evidence must reject omissions and never authorize AI."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_isolated_denials as check
from scripts.verify_v0221_local_image import IMAGE

META = json.dumps([IMAGE]).encode() + b"|amd64"


def packet(*, override=None, shell=True):
    checks = {name: True for name in check.REQUIRED}
    if override:
        checks.update(override)
    return json.dumps({
        "schema": "hermes-v0221-offline-os-negatives-v1",
        "checks": checks,
        "shell_spawn_possible": shell,
    }).encode()


class OSIsolationContracts(unittest.TestCase):
    def test_no_real_docker_without_explicit_opt_in(self):
        with patch.object(check, "observe") as observe:
            self.assertEqual(check.main([]), 0)
        observe.assert_not_called()

    def test_actual_tool_surface_is_explicitly_unverified_even_if_os_passes(self):
        result = check.verify(packet())
        self.assertEqual(result["checks_total"], 8)
        self.assertEqual(result["checks_passed"], 8)
        self.assertEqual(result["status"], "OFFLINE_SANDBOX_DENIALS_PASS_SHELL_AVAILABLE")
        self.assertTrue(result["shell_spawn_possible"])
        self.assertFalse(result["hermes_tool_permissions_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_denials_fail_closed_when_broken(self):
        for name in check.REQUIRED:
            with self.subTest(name=name):
                result = check.verify(packet(override={name: False}))
                self.assertEqual(result["failed_checks"], [name])
                self.assertEqual(result["status"], "OFFLINE_SANDBOX_DENIALS_FAIL")
                self.assertFalse(result["resident_agent_allowed"])

    def test_schema_duplicates_missing_unknown_or_invalid_types_denied(self):
        samples = [
            b"{}",
            b'{"schema":"a","schema":"b","checks":{},"shell_spawn_possible":false}',
            packet(override={"unknown": True}),
            packet(override={"nonroot": "true"}),
            packet().replace(b'"nonroot": true,', b""),
            packet().replace(b'"shell_spawn_possible": true',
                             b'"shell_spawn_possible": 1'),
        ]
        for raw in samples:
            with self.subTest(size=len(raw)):
                with self.assertRaises(check.SecurityProbeDenied):
                    check.verify(raw)

    def test_pinned_docker_cmd_still_enforces_nonroot_cpu_memory_network(self):
        inspect, run = check.commands()
        self.assertIn(IMAGE, inspect)
        self.assertIn(IMAGE, run)
        for item in ("--pull=never", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--memory", "256m",
                     "--user", "65534:65534", "--pids-limit", "25"):
            self.assertIn(item, run)
        for item in ("--privileged", "--mount", "-v", "--env-file"):
            self.assertNotIn(item, run)

    def test_real_command_nonzero_never_claims_permission_checks(self):
        for failing_call in (1, 2):
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                return Mock(
                    returncode=1 if len(calls) == failing_call else 0,
                    stdout=META if len(calls) == 1 else packet(),
                )
            with self.subTest(failing_call=failing_call):
                with self.assertRaises(check.SecurityProbeDenied):
                    check.observe(runner)

    def test_successful_mocked_process_still_returns_no_go(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return Mock(returncode=0, stdout=META if len(calls) == 1 else packet())
        result = check.observe(runner)
        self.assertEqual(calls, list(check.commands()))
        self.assertFalse(result["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
