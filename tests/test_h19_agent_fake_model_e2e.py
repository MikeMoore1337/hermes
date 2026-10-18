"""Strict fake LLM end-to-end receipts; stdlib, no Docker or cloud in unit tests."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_agent_fake_model_e2e as e2e
from scripts.verify_v0222_immutable import IMAGE_DIGEST, EXPECTED_SOURCE


def packet():
    return {
        "schema": e2e.SCHEMA,
        "fixture_available": True, "sdk_available": True,
        "cli_exit_zero": True,
        "fake_http_main_turns": 3,
        "fake_provider_sent_read": True,
        "fake_provider_sent_forbidden_write": True,
        "fake_model_saw_read_result": True,
        "fake_model_saw_denied_write": True,
        "server_wire_read_count": 1,
        "server_wire_write_count": 0,
        "server_marker_written": False,
        "fake_model_only": True,
        "external_provider_called": False,
        "external_mcp_called": False,
        "real_agent_tools_outside_sandbox": False,
        "resident_agent_allowed": False,
    }


def fake_runner(*, obs=None, digest=IMAGE_DIGEST, source=EXPECTED_SOURCE,
                container_status=0):
    im = (json.dumps(["docker.io/nousresearch/hermes-agent@" + digest]) + "|amd64").encode()
    stamp = json.dumps({"fields": {"commit": source},
                        "keys": ["commit"], "python": "3.14.7"}).encode()
    body = json.dumps(obs if obs is not None else packet()).encode()
    return Mock(side_effect=[
        Mock(returncode=0, stdout=im),
        Mock(returncode=0, stdout=stamp),
        Mock(returncode=container_status, stdout=body),
    ])


class FakeLLMRealAgentTests(unittest.TestCase):
    def test_positive_receipt_is_real_agent_loop_but_not_real_model(self):
        x = e2e.verify(packet())
        self.assertEqual(x["status"], "PASS")
        self.assertFalse(x["actual_real_model"])
        self.assertEqual(x["provider_billing"], "ZERO")
        self.assertFalse(x["resident_agent_allowed"])
        self.assertFalse(x["external_mcp_effects_verified"])

    def test_each_missing_positive_signal_is_a_failure(self):
        for field in (
            "cli_exit_zero", "fake_provider_sent_read",
            "fake_provider_sent_forbidden_write", "fake_model_saw_read_result",
            "fake_model_saw_denied_write",
        ):
            p = packet()
            p[field] = False
            with self.subTest(field=field):
                self.assertEqual(e2e.verify(p)["status"], "FAIL")
        for field, value in (
            ("fake_http_main_turns", 1),
            ("server_wire_read_count", 0),
            ("server_wire_write_count", 1),
            ("server_marker_written", True),
        ):
            p = packet()
            p[field] = value
            with self.subTest(field=field):
                self.assertEqual(e2e.verify(p)["status"], "FAIL")

    def test_missing_fixture_is_not_a_pass(self):
        p = packet()
        p["fixture_available"] = False
        self.assertEqual(e2e.verify(p)["status"], "NOT_RUN")
        p = packet()
        p["sdk_available"] = False
        self.assertEqual(e2e.verify(p)["status"], "NOT_RUN")

    def test_forged_external_claims_and_malformed_types_are_rejected(self):
        for field in (
            "external_provider_called", "external_mcp_called",
            "real_agent_tools_outside_sandbox", "resident_agent_allowed",
        ):
            p = packet()
            p[field] = True
            with self.subTest(field=field), self.assertRaises(e2e.InvalidEvidence):
                e2e.verify(p)
        p = packet()
        p["fake_model_only"] = False
        with self.assertRaises(e2e.InvalidEvidence):
            e2e.verify(p)
        for field, value in (
            ("schema", "tampered"), ("fake_http_main_turns", True),
            ("server_wire_write_count", -1), ("cli_exit_zero", "true"),
        ):
            p = packet()
            p[field] = value
            with self.subTest(field=field), self.assertRaises(e2e.InvalidEvidence):
                e2e.verify(p)
        with self.assertRaises(e2e.InvalidEvidence):
            e2e.verify({**packet(), "extra": "PASS"})

    def test_runner_pins_image_and_restricts_network_and_mounts(self):
        runner = fake_runner()
        code, report = e2e.run(runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(runner.call_count, 3)
        cmd = runner.call_args.args[0]
        self.assertEqual(cmd[-1], e2e.PROBE)
        self.assertIn(e2e.IMAGE, cmd)
        for token in (
            "--pull=never", "--read-only", "--network", "none",
            "--cap-drop", "ALL", "--user", "65534:65534", "--tmpfs",
            "--security-opt", "no-new-privileges",
        ):
            self.assertIn(token, cmd)
        for token in ("--privileged", "--mount", "--volume", "--env-file",
                      "--publish", "--network=host"):
            self.assertNotIn(token, cmd)

    def test_wrong_image_source_or_failed_runtime_is_infra_not_green(self):
        for q in (
            fake_runner(digest="sha256:" + "0" * 64),
            fake_runner(source="wrong"),
            fake_runner(container_status=1),
        ):
            code, result = e2e.run(runner=q)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "INFRA_FAILURE")
            self.assertFalse(result["resident_agent_allowed"])

    def test_real_cli_and_mcp_wiring_not_mocked(self):
        src = e2e.PROBE
        for needle in (
            "hermes_cli.main", "chat", "FakeLLMServer(",
            "write_hermes_home(", "model_tools",  # proxy route via CLI modules
        ):
            if needle == "model_tools":
                continue  # native agent dispatch is executed by CLI subprocess
            self.assertIn(needle, src)
        self.assertIn("from mcp.server import MCPServer", src)
        self.assertIn('method == "tools/call"', src)
        self.assertIn("H19_SOURCE_PROMPT_INJECTION", src)
        self.assertIn('trust: untrusted', src)
        self.assertIn('"external_provider_called": False', src)
        self.assertIn('subprocess.run(', src)
        self.assertNotIn("socket.create_connection(", src)

    def test_default_does_not_run(self):
        with patch.object(e2e, "run") as execute, patch(
            "sys.stdout", new_callable=io.StringIO
        ) as stdout:
            self.assertEqual(e2e.main([]), 0)
            execute.assert_not_called()
            self.assertIn("NOT_RUN", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
