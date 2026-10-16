"""Synthetic contract tests: no real models, tools or Docker are executed."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_native_tool_scope as check
from scripts.verify_v0221_local_image import IMAGE

META = json.dumps([IMAGE]).encode() + b"|amd64"


def evidence(*, listed=False, reached=True, mocked=True, synthetic=True):
    return json.dumps({
        "schema": "hermes-v0221-native-tool-scope-v1",
        "terminal_listed": listed,
        "native_dispatch_reached": reached,
        "mocked_executor": mocked,
        "synthetic_response": synthetic,
    }).encode()


class NativeToolScopeContracts(unittest.TestCase):
    def test_default_never_starts_docker(self):
        with patch.object(check, "observe") as observed:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(check.main([]), 0)
        observed.assert_not_called()
        self.assertIn("NOT_EXECUTED", output.getvalue())

    def test_observed_gap_is_not_full_agent_security_claim(self):
        result = check.validate(evidence())
        self.assertEqual(result["status"], "DIRECT_NATIVE_SCOPE_GAP_OBSERVED")
        self.assertFalse(result["terminal_listed"])
        self.assertTrue(result["native_dispatch_reached"])
        self.assertFalse(result["full_agent_surface_verified"])
        self.assertFalse(result["real_tool_executed"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_enforced_scope_still_does_not_grant_runtime_go(self):
        result = check.validate(evidence(reached=False, synthetic=False))
        self.assertEqual(result["status"], "DIRECT_NATIVE_SCOPE_BLOCK_OBSERVED")
        self.assertFalse(result["resident_agent_allowed"])

    def test_unexpected_tool_listing_refuses_positive_result(self):
        result = check.validate(evidence(listed=True, reached=True))
        self.assertEqual(result["status"], "UNEXPECTED_TOOL_SCOPE")
        self.assertFalse(result["resident_agent_allowed"])

    def test_incomplete_untrusted_or_false_evidence_is_rejected(self):
        cases = [
            b"{}", b"[]", b"\xff",
            b'{"schema":"a","schema":"b"}',
            evidence(mocked=False), evidence().replace(b"true", b"1", 1),
            evidence().replace(b"terminal_listed", b"unknown_key"),
            evidence().replace(b"hermes-v0221-native-tool-scope-v1", b"fake-v1"),
        ]
        for item in cases:
            with self.subTest(data_size=len(item)):
                with self.assertRaises(check.NativeScopeDenied):
                    check.validate(item)

    def test_docker_command_never_runs_real_tool_or_network(self):
        inspect, run = check.commands()
        self.assertIn(IMAGE, inspect)
        self.assertIn(IMAGE, run)
        for word in ("--pull=never", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "no-new-privileges",
                     "--user", "65534:65534", "--pids-limit", "25",
                     "HERMES_HOME=/tmp/hermes"):
            self.assertIn(word, run)
        for forbidden in ("--privileged", "--mount", "-v", "--env-file"):
            self.assertNotIn(forbidden, run)
        self.assertIn('patch.object(model_tools, "_execute_tool"', run[-1])
        self.assertIn('"SYNTHETIC_NO_EXEC"', run[-1])

    def test_image_identity_checked_before_probe(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return Mock(returncode=0, stdout=META if len(calls) == 1 else evidence())
        outcome = check.observe(runner=runner)
        self.assertEqual(outcome["status"], "DIRECT_NATIVE_SCOPE_GAP_OBSERVED")
        self.assertEqual([call[0] for call in calls], list(check.commands()))
        self.assertEqual(calls[1][1]["stdout_limit"], 4096)
        self.assertEqual(calls[1][1]["timeout"], 45)

    def test_image_mismatch_and_child_error_fail_closed(self):
        for case in ("metadata_invalid", "inspector_failed"):
            with self.subTest(case=case):
                calls = []
                def runner(command, **kwargs):
                    calls.append(command)
                    if len(calls) == 1:
                        return Mock(returncode=0, stdout=b"[]|amd64" if case == "metadata_invalid" else META)
                    return Mock(returncode=1, stdout=evidence())
                with self.assertRaises(check.NativeScopeDenied):
                    check.observe(runner=runner)

    def test_successful_probe_exits_two(self):
        with patch.object(check, "observe", return_value=check.validate(evidence())):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(check.main(["--execute"]), 2)
        self.assertFalse(json.loads(output.getvalue())["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
