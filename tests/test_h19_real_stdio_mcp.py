"""H-19 real MCP stdio evidence contract; zero real Docker/SDK in unit tests."""
import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_real_stdio_mcp as mcp
from scripts.verify_v0222_immutable import IMAGE_DIGEST, EXPECTED_SOURCE


def payload(*, sdk="AVAILABLE", mode="original"):
    available = sdk == "AVAILABLE"
    return {
        "schema": mcp.SCHEMA,
        "sdk": sdk,
        "mode": mode,
        "registration": "OK" if available else "NOT_RUN",
        "read_result": "OK" if available else "NOT_RUN",
        "write_denied_result": "OK" if available else "NOT_RUN",
        "write_approved_result": "OK" if available else "NOT_RUN",
        "server_write_after_denial": False if available else None,
        "server_write_after_approval": "H19_MCP_WRITE_OK" if available else None,
        "real_protocol": available, "agent_dispatch": available,
        "actual_external_mcp": False, "real_provider": False,
        "real_agent_resident": False,
        "sdk_server_import": "PASS" if available else "NOT_RUN",
        "registered_tool_count": 4 if available else 0,
        "discovery_errors_observed": False,
        "wire_read_after_read": 1 if available else None,
        "wire_write_after_denial": 0 if available else None,
        "wire_write_after_approval": 1 if available else None,
        "wire_read_after_scope_denied": (2 if mode == "original" else 1) if available else None,
        "wire_write_after_scope_denied": (2 if mode == "original" else 1) if available else None,
        "scope_denied_write_marker": (mode == "original") if available else None,
        "wire_write_after_cancel": 1 if available else None,
        "wire_write_after_approval_error": 1 if available else None,
        "wire_write_after_post_approval_deny": 1 if available else None,
        "wire_unannotated_write_after_denial": 0 if available else None,
        "spoofed_read_wire_after_denial": (1 if mode == "original" else 0) if available else None,
        "spoofed_read_marker_after_denial": (mode == "original") if available else None,
        "spoofed_read_prompt_calls": (0 if mode == "original" else 1) if available else None,
    }


def fake_runner(*, observation=None, image=None, source=None, result_code=0):
    image = image or IMAGE_DIGEST
    source = source or EXPECTED_SOURCE
    values = [
        (json.dumps(["docker.io/nousresearch/hermes-agent@" + image]) + "|amd64").encode(),
        json.dumps({"fields": {"commit": source},
                    "keys": ["commit"], "python": "3.14.7"}).encode(),
        json.dumps(observation if observation is not None else payload()).encode(),
    ]
    return Mock(side_effect=[
        Mock(returncode=0, stdout=values[0]),
        Mock(returncode=0, stdout=values[1]),
        Mock(returncode=result_code, stdout=values[2]),
    ])



def fake_runner_compare(*, old=None, new=None):
    image_id = (json.dumps(["docker.io/nousresearch/hermes-agent@" + IMAGE_DIGEST]) + "|amd64").encode()
    stamp = json.dumps({"fields": {"commit": EXPECTED_SOURCE},
                        "keys": ["commit"], "python": "3.14.7"}).encode()
    derivative_id = ("sha256:" + "b" * 64 + "|amd64").encode()
    responses = (
        image_id, stamp, derivative_id,
        json.dumps(old if old is not None else payload()).encode(),
        json.dumps(new if new is not None else payload(mode="patched")).encode(),
    )
    return Mock(side_effect=[Mock(returncode=0, stdout=part) for part in responses])


class RealStdioMCPTests(unittest.TestCase):
    def test_real_wire_observation_is_only_local_and_partial(self):
        evidence = mcp.validate(payload())
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["mode"], "isolated_real_mcp_stdio_with_local_server")
        self.assertEqual(evidence["real_model_evaluation"], "NOT_RUN")
        self.assertFalse(evidence["full_mcp_permission_enforcement_verified"])
        self.assertFalse(evidence["external_mcp_effects_verified"])
        self.assertFalse(evidence["resident_agent_allowed"])

    def test_missing_sdk_is_not_an_inference_of_security(self):
        out = mcp.validate(payload(sdk="UNAVAILABLE"))
        self.assertEqual(out["status"], "NOT_RUN")
        code, report = mcp.capture(runner=fake_runner(observation=payload(sdk="UNAVAILABLE")))
        self.assertEqual(code, 3)
        self.assertEqual(report["status"], "NOT_RUN")

    def test_mutations_are_fail_or_invalid_not_pass(self):
        for field, bad in (
            ("registration", "MISSING_TOOLS"),
            ("read_result", "FAILED"),
            ("write_denied_result", "FAILED"),
            ("write_approved_result", "FAILED"),
            ("server_write_after_denial", True),
            ("server_write_after_approval", None),
            ("real_protocol", False),
            ("agent_dispatch", False),
            ("wire_read_after_read", 0),
            ("wire_write_after_denial", 1),
            ("wire_write_after_approval", 0),
            ("wire_read_after_scope_denied", 0),
            ("wire_write_after_scope_denied", 0),
            ("scope_denied_write_marker", False),
            ("wire_write_after_cancel", 2),
            ("wire_write_after_approval_error", 2),
            ("wire_write_after_post_approval_deny", 2),
            ("wire_unannotated_write_after_denial", 1),
        ):
            bad_case = payload()
            bad_case[field] = bad
            with self.subTest(field=field):
                self.assertEqual(mcp.validate(bad_case)["status"], "FAIL")
        for key in ("actual_external_mcp", "real_provider", "real_agent_resident"):
            bad_case = payload()
            bad_case[key] = True
            with self.subTest(key=key), self.assertRaises(mcp.EvidenceDenied):
                mcp.validate(bad_case)
        for key in ("schema", "sdk"):
            bad_case = payload()
            bad_case[key] = "forged"
            with self.subTest(key=key), self.assertRaises(mcp.EvidenceDenied):
                mcp.validate(bad_case)
        bad_case = payload()
        bad_case["unexpected"] = "PASS"
        with self.assertRaises(mcp.EvidenceDenied):
            mcp.validate(bad_case)

    def test_runner_proves_digest_and_no_egress(self):
        run = fake_runner()
        code, report = mcp.capture(runner=run)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(run.call_count, 3)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[-1], mcp.PROBE)
        self.assertIn(mcp.IMAGE, cmd)
        for x in ("--pull=never", "--network", "none", "--read-only",
                  "--cap-drop", "ALL", "--user", "65534:65534",
                  "--security-opt", "no-new-privileges"):
            self.assertIn(x, cmd)
        for forbidden in ("--privileged", "--mount", "--volume",
                          "--env-file", "--publish", "--network=host"):
            self.assertNotIn(forbidden, cmd)

    def test_refuse_wrong_identity_and_server_failure(self):
        for value in (fake_runner(image="sha256:" + "0" * 64),
                      fake_runner(source="forged"),
                      fake_runner(result_code=1)):
            with self.subTest(value=value):
                code, r = mcp.capture(runner=value)
                self.assertEqual(code, 2)
                self.assertEqual(r["status"], "INFRA_FAILURE")
                self.assertFalse(r["resident_agent_allowed"])

    def test_default_does_not_run(self):
        with patch.object(mcp, "capture") as run, patch(
            "sys.stdout", new_callable=io.StringIO
        ) as out:
            self.assertEqual(mcp.main([]), 0)
            self.assertIn("NOT_RUN", out.getvalue())
            run.assert_not_called()


    def test_patched_mcp_scope_must_deny_even_with_approval(self):
        result = mcp.validate(payload(mode="patched"))
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["observations"]["scope_denied_write_marker"])
        for field, bad in (
            ("wire_write_after_scope_denied", 2),
            ("wire_read_after_scope_denied", 2),
            ("scope_denied_write_marker", True),
            ("wire_write_after_approval_error", 2),
            ("wire_unannotated_write_after_denial", 1),
            ("wire_write_after_post_approval_deny", 2),
            ("wire_write_after_cancel", 2),
        ):
            altered = payload(mode="patched")
            altered[field] = bad
            with self.subTest(field=field):
                self.assertEqual(mcp.validate(altered)["status"], "FAIL")

    def test_sdk_absence_is_not_a_partial_success(self):
        missing = payload(sdk="UNAVAILABLE")
        missing["wire_write_after_scope_denied"] = 0
        with self.assertRaises(mcp.EvidenceDenied):
            mcp.validate(missing)
        changed = payload()
        changed["mode"] = "unknown"
        with self.assertRaises(mcp.EvidenceDenied):
            mcp.validate(changed)

    def test_compare_runner_uses_two_disposable_immutable_paths(self):
        runner = fake_runner_compare()
        code, report = mcp.compare_isolated(runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(runner.call_count, 5)
        original = runner.call_args_list[3].args[0]
        patched = runner.call_args_list[4].args[0]
        self.assertIn(mcp.IMAGE, original)
        self.assertIn("hermes-v0222-native-policy-candidate:20261016", patched)
        for cmd in (original, patched):
            self.assertEqual(cmd[-1], mcp.PROBE)
            for token in ("--pull=never", "--network", "none", "--read-only",
                          "--cap-drop", "ALL", "--user", "65534:65534"):
                self.assertIn(token, cmd)
            for token in ("--privileged", "--mount", "--volume",
                          "--env-file", "--publish", "--network=host"):
                self.assertNotIn(token, cmd)
        self.assertFalse(report["resident_agent_allowed"])

    def test_compare_detects_forged_modes_and_effects(self):
        cases = (
            (payload(), {**payload(mode="patched"), "wire_write_after_scope_denied": 2}),
            (payload(mode="patched"), payload(mode="patched")),
            (payload(), payload(mode="original")),
        )
        for first, second in cases:
            with self.subTest(first=first["mode"], second=second["mode"]):
                code, report = mcp.compare_isolated(
                    runner=fake_runner_compare(old=first, new=second))
                self.assertNotEqual(code, 0)
                self.assertIn(report["status"], ("FAIL", "INFRA_FAILURE"))
                self.assertFalse(report["resident_agent_allowed"])

    def test_sdk_and_trust_gate_are_really_invoked(self):
        source = mcp.PROBE
        self.assertIn("SERVER = r" + "'" * 3, source)
        self.assertIn("from mcp.server import MCPServer", source)
        self.assertIn("from mcp_types import ToolAnnotations", source)
        self.assertIn("register_mcp_servers", source)
        self.assertIn("model_tools.handle_function_call", source)
        self.assertIn("request_elicitation_consent", source)
        self.assertIn("marker.read_text", source)
        self.assertIn('method == "tools/call"', source)
        self.assertIn('WIRE_LOG.open("a"', source)
        self.assertIn('wire().count("mark")', source)
        self.assertIn("server_write_after_denial", source)
        self.assertNotIn("requests.post(", source)
        self.assertNotIn("http://", source)


if __name__ == "__main__":
    unittest.main()
