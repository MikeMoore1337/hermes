"""The approved pinned Hermes digest is not release-parity verified."""
from __future__ import annotations
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HermessImagePinContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((ROOT / "deploy/hermes-image-provenance.json").read_text())

    def test_immutable_digest_is_not_latest(self) -> None:
        data = self.manifest
        self.assertRegex(data["image"], r"^nousresearch/hermes-agent@sha256:[0-9a-f]{64}$")
        self.assertEqual(data["observed_image_id"], "sha256:" + data["image"].rsplit(":", 1)[-1])
        self.assertEqual(data["architecture"], "amd64")

    def test_source_commit_mismatch_keeps_resident_agent_disallowed(self) -> None:
        data = self.manifest
        self.assertNotEqual(data["reported_embedded_commit"], data["upstream_release_tag_commit"])
        self.assertEqual(data["known_commits_behind_release"], 39)
        self.assertFalse(data["source_release_parity_verified"])
        self.assertFalse(data["permanent_agent_runtime_approved"])

    def test_bounded_agent_uses_exact_pinned_digest(self) -> None:
        source = (ROOT / "scripts/agent_turn_probe.py").read_text()
        self.assertIn(self.manifest["image"], source)
        self.assertIn("--pull=never", source)
        self.assertIn("hermes-agent-test", source)
        self.assertIn("--cap-drop", source)
        self.assertNotIn(":latest", source)

    def test_documented_approval_flag_risk_and_release_history(self) -> None:
        report = (ROOT / "docs/audits/H-01-image-provenance-2026-10-14.md").read_text()
        self.assertIn("tools/approval_yolo.py", report)
        self.assertIn("39", report)
        self.assertIn("NO-GO", report)


if __name__ == "__main__":
    unittest.main()
