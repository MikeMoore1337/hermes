"""No v0.22.2 metadata or synthetic native test may declare resident GO."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from scripts import verify_v0222_immutable as audit


class ImmutableReleaseTests(unittest.TestCase):
    def test_default_is_zero_execution(self):
        with patch.object(audit, "observe") as observer:
            self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()

    def test_docker_is_exact_amd64_offline_and_nonroot(self):
        inspect, stamp, native = audit.commands()
        self.assertIn(audit.IMAGE, inspect)
        for command in (stamp, native):
            self.assertIn(audit.IMAGE, command)
            for flag in ("--pull=never", "--network", "none", "--read-only",
                         "--cap-drop", "ALL", "--user", "65534:65534",
                         "--memory", "768m", "--pids-limit", "64"):
                self.assertIn(flag, command)
            for forbidden in ("--privileged", "--env-file", "--mount",
                              "--publish", "--volume", "--network=host"):
                self.assertNotIn(forbidden, command)
        self.assertNotEqual(stamp[-1], native[-1])

    def test_patched_derivative_remains_offline_and_nonroot(self):
        inspect, probe = audit.patched_commands()
        self.assertIn(audit.PATCHED_IMAGE, inspect)
        self.assertIn(audit.PATCHED_IMAGE, probe)
        self.assertIn("HERMES_SCOPE_PROBE_MODE=patched", probe)
        for flag in ("--network", "none", "--read-only", "--cap-drop",
                     "ALL", "--user", "65534:65534", "--pull=never"):
            self.assertIn(flag, probe)
        for forbidden in ("--privileged", "--env-file", "--mount", "-v"):
            self.assertNotIn(forbidden, probe)

    def test_digest_and_architecture_must_match(self):
        line = (json.dumps(["docker.io/nousresearch/hermes-agent@" + audit.IMAGE_DIGEST])
                + "|amd64").encode()
        self.assertTrue(audit.image_identity(line))
        self.assertFalse(audit.image_identity(line.replace(b"amd64", b"arm64")))
        self.assertFalse(audit.image_identity(line.replace(
            audit.IMAGE_DIGEST.encode(), b"sha256:" + b"0" * 64)))
        self.assertFalse(audit.image_identity(b"not-json|amd64"))

    def test_observed_stamp_is_not_source_to_build_attestation(self):
        stamp = audit.stamp_details(json.dumps({
            "fields": {"commit": audit.EXPECTED_SOURCE},
            "keys": ["commit"], "python": "3.14.7",
        }).encode())
        self.assertTrue(stamp["matches_source"])
        decision = audit.evaluate(True, stamp, {
            "direct_terminal_executor_reached": False,
            "model_executed": False, "real_tool_executed": False,
        })
        self.assertFalse(decision["source_to_image_attested"])
        self.assertFalse(decision["resident_agent_allowed"])

    def test_synthetic_tool_gap_never_grants_resident(self):
        outcome = audit.evaluate(True, {"matches_source": True}, {
            "direct_terminal_executor_reached": True,
            "model_executed": False, "real_tool_executed": False,
        })
        self.assertEqual(outcome["status"], "OFFLINE_V0222_GAP_OBSERVED")
        self.assertFalse(outcome["resident_agent_allowed"])

    def test_invalid_stamp_fails_closed(self):
        for raw in (b"{}", b"not-json", b"[]"):
            self.assertFalse(audit.stamp_details(raw)["matches_source"])


if __name__ == "__main__":
    unittest.main()
