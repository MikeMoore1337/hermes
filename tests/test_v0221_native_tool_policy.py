"""Contract tests for the bounded v0.22.1 native tool-policy proof."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_native_tool_policy as check
from scripts.verify_v0221_local_image import IMAGE


def packet(mode: str) -> bytes:
    cases = {
        name: {"exception": False, "executor_reached": False}
        for name in check.REQUIRED_CASES
    }
    if mode == "original":
        for name in (
            "direct_terminal", "direct_alias", "agent_stale_native",
            "agent_full_loop",
            "request_hook_error", "pre_hook_error", "approval_error",
            "execution_hook_error", "registry_policy_error",
        ):
            cases[name]["executor_reached"] = True
    else:
        cases["direct_allowed"]["executor_reached"] = True
        cases["execution_arg_recheck"].update(
            executor_reached=True, modified_approval_seen=True,
        )
        cases["subagent_scope"].update(
            terminal_in_child=False, terminal_in_disabled=True,
        )
    cases["execute_code_nested_scope"].update(
        executor_reached=True,
        nested_terminal_allowed=mode == "original",
        nested_web_search_allowed=True,
    )
    cases["parallel_policy"].update(
        executor_reached=True,
        restricted_executor_reached=mode == "original",
        allowed_executor_reached=True,
    )
    return json.dumps({
        "cases": cases,
        "mode": mode,
        "model_executed": False,
        "real_tool_executed": False,
        "schema": check.SCHEMA,
        "secret_exposed": False,
    }, sort_keys=True).encode()


class NativeToolPolicyContracts(unittest.TestCase):
    def test_default_never_starts_docker(self):
        with patch.object(check, "observe") as observed:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(check.main([]), 0)
        observed.assert_not_called()
        self.assertIn("NOT_EXECUTED", output.getvalue())

    def test_patched_contract_requires_baseline_and_allowed_paths(self):
        result = check.validate(packet("original"), packet("patched"))
        self.assertEqual(result["status"], "PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS")
        self.assertTrue(result["original_low_level_gap_reproduced"])
        self.assertTrue(result["patched_checked_paths_blocked"])
        self.assertTrue(result["allowed_synthetic_paths_work"])
        self.assertTrue(result["full_agent_surface_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_positive_result_is_refused_when_a_blocked_case_reaches_executor(self):
        raw = json.loads(packet("patched"))
        raw["cases"]["direct_terminal"]["executor_reached"] = True
        result = check.validate(packet("original"), json.dumps(raw).encode())
        self.assertEqual(result["status"], "NATIVE_TOOL_POLICY_EVIDENCE_INCOMPLETE")
        self.assertFalse(result["resident_agent_allowed"])

    def test_malformed_or_secret_bearing_evidence_fails_closed(self):
        secret = json.loads(packet("patched"))
        secret["secret_exposed"] = "SYNTHETIC_SECRET_DO_NOT_PRINT"
        for raw in (
            b"{}",
            b'{"mode":"original","mode":"patched"}',
            json.dumps(secret).encode(),
        ):
            with self.subTest(size=len(raw)):
                with self.assertRaises(check.NativePolicyDenied) as error:
                    check.validate(packet("original"), raw)
                self.assertNotIn("SYNTHETIC_SECRET_DO_NOT_PRINT", str(error.exception))

    def test_docker_command_is_pinned_and_isolated(self):
        inspect, run = check.commands(check.PATCHED_IMAGE)
        run_text = " ".join(run)
        self.assertEqual(inspect[3], check.PATCHED_IMAGE)
        for word in (
            "--pull=never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "no-new-privileges", "--user",
            "65534:65534", "--cpus", "0.5", "--memory", "768m",
            "--pids-limit", "64", "noexec", "HERMES_HOME=/tmp/hermes",
        ):
            self.assertIn(word, run_text)
        for forbidden in ("--privileged", "--mount", "-v", "--env-file", "docker.sock"):
            self.assertNotIn(forbidden, run)
        self.assertNotIn("OPENAI_API_KEY", run_text)
        self.assertEqual(run[-1], check.INSPECTOR)

    def test_observe_checks_both_images_before_accepting_result(self):
        pinned_meta = (
            json.dumps([IMAGE]).encode() + b"|amd64"
        )
        patched_meta = b"[]|sha256:local-derivative|amd64"
        responses = [
            Mock(returncode=0, stdout=pinned_meta),
            Mock(returncode=0, stdout=packet("original")),
            Mock(returncode=0, stdout=patched_meta),
            Mock(returncode=0, stdout=packet("patched")),
        ]
        runner = Mock(side_effect=responses)
        result = check.observe(runner=runner)
        self.assertEqual(result["status"], "PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS")
        self.assertEqual(runner.call_count, 4)
        self.assertEqual(runner.call_args_list[0].args[0][3], IMAGE)
        self.assertEqual(runner.call_args_list[2].args[0][3], check.PATCHED_IMAGE)


if __name__ == "__main__":
    unittest.main()
