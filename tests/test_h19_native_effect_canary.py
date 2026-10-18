"""H-19 independent physical-effect receipt integrity and false-positive controls."""
from __future__ import annotations
import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_native_effect_canary as probe
from scripts.verify_v0222_immutable import IMAGE_DIGEST, EXPECTED_SOURCE


def packet(mode, *, overrides=None):
    overrides = overrides or {}
    rows = []
    for name, policy in probe.CASES.items():
        should_effect = bool(mode == "original" or policy == "ALLOW_STUB")
        if name in overrides:
            should_effect = overrides[name]
        rows.append({
            "scenario_id": name,
            "callback_count": int(should_effect),
            "effect_count": int(should_effect),
            "effect_sha256": probe.MARKER_SHA256 if should_effect else None,
            "handler_exception": False,
            "result_text_exposed": False,
        })
    return json.dumps({
        "schema": probe.SCHEMA, "mode": mode, "rows": rows,
        "actual_agent_tools_executed": False, "real_mcp_called": False,
        "provider_called": False, "production_accessed": False,
    }).encode()


def fake_runner(*, old=None, new=None, good_identity=True):
    digest = IMAGE_DIGEST if good_identity else "sha256:" + "0" * 64
    metadata = (json.dumps(["docker.io/nousresearch/hermes-agent@" + digest]) + "|amd64").encode()
    stamp = json.dumps({"fields": {"commit": EXPECTED_SOURCE},
                        "keys": ["commit"], "python": "3.14.7"}).encode()
    replies = [metadata, stamp, ("sha256:" + "b" * 64 + "|amd64").encode(),
               old if old is not None else packet("original"),
               new if new is not None else packet("patched")]
    return Mock(side_effect=[Mock(returncode=0, stdout=item) for item in replies])


class PhysicalCanaryTests(unittest.TestCase):
    def test_pinned_six_paths_positive_and_negative(self):
        result = probe.compare(packet("original"), packet("patched"),
                               derivative_id="sha256:" + "b" * 64)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["scenario_count"], 6)
        self.assertEqual(result["physical_effect_canary_count"], 6)
        self.assertTrue(all(x["verification_status"] == "PASS" for x in result["checks"]))
        self.assertFalse(result["full_mcp_permission_enforcement_verified"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["real_mcp_called"])
        self.assertEqual(result["real_model_evaluation"], "NOT_RUN")

    def test_malicious_mutations_are_detected_per_path(self):
        for name in probe.CASES:
            if probe.CASES[name] == "DENY":
                new = packet("patched", overrides={name: True})
            else:
                new = packet("patched", overrides={name: False})
            with self.subTest(case=name):
                result = probe.compare(packet("original"), new,
                                       derivative_id="sha256:" + "b" * 64)
                self.assertEqual(result["status"], "FAIL")
                failed = [x for x in result["checks"] if x["verification_status"] == "FAIL"]
                self.assertEqual(len(failed), 1)

    def test_original_negative_controls_must_reproduce_gap(self):
        for name in probe.CASES:
            original = packet("original", overrides={name: False})
            with self.subTest(case=name):
                r = probe.compare(original, packet("patched"),
                                  derivative_id="sha256:" + "b" * 64)
                self.assertEqual(r["status"], "FAIL")

    def test_modified_missing_or_forged_evidence_fails_closed(self):
        obj = json.loads(packet("patched"))
        variants = []
        for manipulation in ("missing", "duplicate", "tamper_count", "tamper_digest",
                             "model", "mcp", "response", "injected"):
            val = json.loads(packet("patched"))
            if manipulation == "missing":
                val["rows"].pop()
            elif manipulation == "duplicate":
                val["rows"][0] = val["rows"][1]
            elif manipulation == "tamper_count":
                val["rows"][0]["effect_count"] = 1
            elif manipulation == "tamper_digest":
                val["rows"][0]["effect_sha256"] = "a" * 64
            elif manipulation == "model":
                val["provider_called"] = True
            elif manipulation == "mcp":
                val["real_mcp_called"] = True
            elif manipulation == "response":
                val["rows"][0]["result_text_exposed"] = True
            else:
                val["rows"][0]["untrusted_extra"] = "PASS"
            variants.append(val)
        for variant in variants:
            with self.subTest(variant=variant["rows"][0].get("scenario_id")):
                with self.assertRaises(probe.CanaryError):
                    probe.parse_packet(json.dumps(variant).encode(), "patched")
        self.assertEqual(set(obj), {"schema", "mode", "rows",
                         "actual_agent_tools_executed", "real_mcp_called",
                         "provider_called", "production_accessed"})

    def test_runner_uses_pinned_docker_and_never_real_tools(self):
        fn = fake_runner()
        code, result = probe.execute(runner=fn)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(fn.call_count, 5)
        calls = [x.args[0] for x in fn.call_args_list]
        for cmd in calls[-2:]:
            self.assertEqual(cmd[-1], probe.INSPECTOR)
            for arg in ("--network", "none", "--read-only", "--pull=never",
                        "--user", "65534:65534", "--cap-drop", "ALL"):
                self.assertIn(arg, cmd)
            for forbidden in ("--privileged", "--volume", "--mount",
                              "--env-file", "--publish", "--network=host"):
                self.assertNotIn(forbidden, cmd)
        self.assertIn("tempfile.TemporaryDirectory", probe.INSPECTOR)
        self.assertIn('patch.object(model_tools, "_execute_tool"', probe.INSPECTOR)

    def test_runner_infrastructure_fails_on_wrong_image_and_missing_probe(self):
        code, report = probe.execute(runner=fake_runner(good_identity=False))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "INFRA_FAILURE")
        code, report = probe.execute(runner=fake_runner(new=b"{}"))
        self.assertEqual(code, 2)
        self.assertFalse(report["resident_agent_allowed"])

    def test_default_never_runs_real_docker(self):
        with patch.object(probe, "execute") as executor:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(probe.main([]), 0)
                self.assertIn("NOT_RUN", out.getvalue())
        executor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
