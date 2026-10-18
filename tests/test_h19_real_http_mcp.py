"""Offline strict real HTTP MCP evidence contracts: no SDK, Docker or provider in unit CI."""
from __future__ import annotations
import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_real_http_mcp as h
from scripts.verify_v0222_immutable import IMAGE_DIGEST, EXPECTED_SOURCE


def packet(mode="original"):
    upstream = mode == "original"
    return {
        "schema": h.SCHEMA,
        "mode": mode,
        "sdk_available": True,
        "server_bound_loopback": True,
        "transport": "http_streamable",
        "registered_tools": 3,
        "read_result_valid": True,
        "read_wire_after_allowed": 1,
        "write_wire_after_denial": 0,
        "write_marker_after_denial": False,
        "write_wire_after_approval": 1,
        "write_marker_after_approval": True,
        "read_wire_after_scope_deny": 2 if upstream else 1,
        "write_wire_after_scope_deny": 2 if upstream else 1,
        "write_marker_after_scope_deny": upstream,
        "spoofed_read_wire_after_denial": 1 if upstream else 0,
        "spoofed_read_marker_after_denial": upstream,
        "spoofed_read_prompt_calls": 0 if upstream else 1,
        "spoofed_read_result_valid": upstream,
        "unvetted_read_wire_after_denial": 1,
        "unvetted_read_prompt_calls": 0 if upstream else 1,
        "external_mcp_called": False,
        "real_model_called": False,
        "resident_agent_allowed": False,
    }


def fake_runner(original=None, patched=None, *, image=IMAGE_DIGEST,
                stamp=EXPECTED_SOURCE, candidate="sha256:" + "b" * 64):
    meta = (json.dumps(["docker.io/nousresearch/hermes-agent@" + image]) + "|amd64").encode()
    revision = json.dumps({
        "fields": {"commit": stamp}, "keys": ["commit"], "python": "3.14.7",
    }).encode()
    responses = [
        meta, revision, (candidate + "|amd64").encode(),
        json.dumps(original if original is not None else packet()).encode(),
        json.dumps(patched if patched is not None else packet("patched")).encode(),
    ]
    return Mock(side_effect=[Mock(returncode=0, stdout=part) for part in responses])


class HttpMCPPolicyTests(unittest.TestCase):
    def test_genuine_loopback_http_server_and_tool_boundary_source(self):
        probe = h.PROBE
        compile(probe, "<h19-http-real-mcp>", "exec")
        for part in (
            "from mcp.server import MCPServer",
            "from mcp_types import ToolAnnotations",
            "source.streamable_http_app()",
            "import uvicorn",
            'server_socket.bind(("127.0.0.1", 0))',
            '"transport": "http"',
            'request.get("method") == "tools/call"',
            "register_mcp_servers(",
            "model_tools.handle_function_call(",
            "request_elicitation_consent",
            "marker.write_text(",
            "spoof_marker.write_text(",
            "read_only_hint=True, destructive_hint=False",
            'inbound_names.count("disguised")',
        ):
            self.assertIn(part, probe)
        self.assertNotIn("https://", probe)
        self.assertNotIn("requests.post(", probe)

    def test_individual_original_and_patched_policy_are_distinguished(self):
        a = h.validate(packet(), expected_mode="original")
        b = h.validate(packet("patched"), expected_mode="patched")
        self.assertEqual(a["status"], "PASS")
        self.assertEqual(b["status"], "PASS")
        self.assertTrue(a["observations"]["write_marker_after_scope_deny"])
        self.assertFalse(b["observations"]["write_marker_after_scope_deny"])
        self.assertTrue(a["observations"]["spoofed_read_marker_after_denial"])
        self.assertFalse(b["observations"]["spoofed_read_marker_after_denial"])
        self.assertEqual(b["observations"]["spoofed_read_prompt_calls"], 1)
        self.assertEqual(b["observations"]["unvetted_read_prompt_calls"], 1)

    def test_mutations_of_all_critical_wire_or_permission_signals_fail(self):
        for mode in ("original", "patched"):
            cases = (
                ("server_bound_loopback", False),
                ("registered_tools", 1),
                ("read_result_valid", False),
                ("read_wire_after_allowed", 0),
                ("write_wire_after_denial", 1),
                ("write_marker_after_denial", True),
                ("write_wire_after_approval", 0),
                ("write_marker_after_approval", False),
                ("read_wire_after_scope_deny", 0),
                ("write_wire_after_scope_deny", 0),
                ("write_marker_after_scope_deny", mode != "original"),
                ("spoofed_read_wire_after_denial", 0),
                ("spoofed_read_marker_after_denial", False),
                ("spoofed_read_prompt_calls", 1),
                ("spoofed_read_result_valid", mode != "original"),
                ("unvetted_read_wire_after_denial", 0),
                ("unvetted_read_prompt_calls", 1 if mode == "original" else 0),
            )
            for field, value in cases:
                altered = packet(mode)
                altered[field] = value
                with self.subTest(mode=mode, field=field):
                    self.assertEqual(
                        h.validate(altered, expected_mode=mode)["status"], "FAIL")

    def test_no_real_model_external_mcp_or_go_can_be_claimed(self):
        for field in ("external_mcp_called", "real_model_called",
                      "resident_agent_allowed"):
            altered = packet()
            altered[field] = True
            with self.subTest(field=field), self.assertRaises(h.ReceiptInvalid):
                h.validate(altered, expected_mode="original")
        for field, value in (
            ("registered_tools", True),
            ("write_wire_after_approval", True),
            ("write_marker_after_denial", 0),
            ("sdk_available", "true"),
            ("transport", "stdio"),
            ("mode", "patched"),
        ):
            altered = packet()
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(h.ReceiptInvalid):
                h.validate(altered, expected_mode="original")
        altered = packet()
        altered["extra_claim"] = "PASS"
        with self.assertRaises(h.ReceiptInvalid):
            h.validate(altered, expected_mode="original")

    def test_optional_sdk_absence_is_not_evidence_of_success(self):
        p = packet()
        for key in p:
            if key in ("schema", "mode", "transport"):
                continue
            if isinstance(p[key], bool):
                p[key] = False
            else:
                p[key] = 0
        self.assertEqual(h.validate(p, expected_mode="original")["status"], "NOT_RUN")
        p["write_wire_after_approval"] = 1
        with self.assertRaises(h.ReceiptInvalid):
            h.validate(p, expected_mode="original")

    def test_exact_pinned_run_commands_are_fenced(self):
        runner = fake_runner()
        code, report = h.execute(runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(runner.call_count, 5)
        self.assertEqual(h.verify_report(report), "PASS")
        for call in runner.call_args_list[-2:]:
            cmd = call.args[0]
            self.assertEqual(cmd[-1], h.PROBE)
            for token in ("--network", "none", "--read-only", "--cap-drop",
                          "ALL", "--user", "65534:65534", "--pull=never",
                          "--security-opt", "no-new-privileges", "--pids-limit"):
                self.assertIn(token, cmd)
            for forbidden in ("--privileged", "--mount", "--volume", "--env-file",
                              "--publish", "--network=host"):
                self.assertNotIn(forbidden, cmd)
        self.assertIn(h.IMAGE, runner.call_args_list[-2].args[0])
        self.assertIn("hermes-v0222-native-policy-candidate:20261016",
                      runner.call_args_list[-1].args[0])
        self.assertFalse(report["resident_agent_allowed"])
        self.assertFalse(report["full_resident_runtime_verified"])
        self.assertTrue(report["untrusted_annotation_spoof_gap_observed"])
        self.assertTrue(report["patched_spoof_blocked_on_wire"])

    def test_false_patch_deny_causes_fail_and_readback_rejects_lies(self):
        bad = packet("patched")
        bad["write_wire_after_scope_deny"] = 2
        code, evidence = h.execute(runner=fake_runner(patched=bad))
        self.assertEqual(code, 1)
        self.assertEqual(evidence["status"], "FAIL")
        self.assertEqual(h.verify_report(evidence), "FAIL")
        evidence["status"] = "PASS"
        with self.assertRaises(h.ReceiptInvalid):
            h.verify_report(evidence)

    def test_malformed_image_and_source_do_not_run_any_tools(self):
        for params in (
            {"image": "sha256:" + "0" * 64},
            {"stamp": "fake"},
            {"candidate": "not-a-valid-image"},
        ):
            with self.subTest(params=params):
                code, result = h.execute(runner=fake_runner(**params))
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "INFRA_FAILURE")
                self.assertFalse(result["resident_agent_allowed"])

    def test_readback_must_reject_injected_external_go(self):
        _, report = h.execute(runner=fake_runner())
        for key, forged in (
            ("status", "FAIL"),
            ("resident_agent_allowed", True),
            ("full_external_mcp_enforcement_verified", True),
            ("real_model_evaluation", "PASS"),
            ("untrusted_annotation_spoof_gap_observed", False),
            ("patched_spoof_blocked_on_wire", False),
            ("patched_derivative_id", "sha256:" + "0" * 10),
            ("upstream_stamp", "forged"),
        ):
            alternate = json.loads(json.dumps(report))
            alternate[key] = forged
            with self.subTest(key=key), self.assertRaises(h.ReceiptInvalid):
                h.verify_report(alternate)
        alternate = json.loads(json.dumps(report))
        alternate["patched"]["write_wire_after_denial"] = 1
        with self.assertRaises(h.ReceiptInvalid):
            h.verify_report(alternate)

    def test_default_does_not_execute_docker(self):
        with patch.object(h, "execute") as work, patch(
                "sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(h.main([]), 0)
            self.assertIn("NOT_RUN", out.getvalue())
            work.assert_not_called()


if __name__ == "__main__":
    unittest.main()
