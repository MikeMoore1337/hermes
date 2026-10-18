"""H-19 real MCP stdio evidence contract; zero real Docker/SDK in unit tests."""
import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_real_stdio_mcp as mcp
from scripts.verify_v0222_immutable import IMAGE_DIGEST, EXPECTED_SOURCE


def payload(*, sdk="AVAILABLE"):
    available = sdk == "AVAILABLE"
    return {
        "schema": mcp.SCHEMA,
        "sdk": sdk,
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
        "registered_tool_count": 2 if available else 0,
        "discovery_errors_observed": False,
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

    def test_sdk_and_trust_gate_are_really_invoked(self):
        source = mcp.PROBE
        self.assertIn("from mcp.server.fastmcp import FastMCP", source)
        self.assertIn("register_mcp_servers", source)
        self.assertIn("model_tools.handle_function_call", source)
        self.assertIn("request_elicitation_consent", source)
        self.assertIn("marker.read_text", source)
        self.assertIn("server_write_after_denial", source)
        self.assertNotIn("requests.post(", source)
        self.assertNotIn("http://", source)


if __name__ == "__main__":
    unittest.main()
