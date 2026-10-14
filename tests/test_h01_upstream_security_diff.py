"""H-01: security evidence is a fail-closed NO-GO for resident upstream agent."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIFF = ROOT / "deploy/hermes-upstream-security-diff.json"
IMAGE = ROOT / "deploy/hermes-image-provenance.json"
REPORT = ROOT / "docs/audits/H-01-upstream-security-diff-2026-10-14.md"


class UpstreamSecurityDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.diff = json.loads(DIFF.read_text(encoding="utf-8"))
        cls.image = json.loads(IMAGE.read_text(encoding="utf-8"))

    def test_compared_sha_and_direction_match_pinned_metadata(self):
        data, image = self.diff, self.image
        self.assertEqual(data["upstream_repository"], "NousResearch/hermes-agent")
        self.assertEqual(data["installed_embedded_source_sha"], image["reported_embedded_commit"])
        self.assertEqual(data["official_release_git_sha"], image["upstream_release_tag_commit"])
        self.assertEqual(data["official_release_tag"], image["upstream_release_tag"])
        self.assertEqual(data["ahead_by"], 39)
        self.assertEqual(data["behind_by"], 0)
        self.assertGreaterEqual(data["total_files_changed"], 54)
        self.assertIn(
            image["reported_embedded_commit"] + "..." + image["upstream_release_tag_commit"],
            data["link"],
        )

    def test_unknown_sbom_parity_and_publisher_keeps_resident_no_go(self):
        data = self.diff
        self.assertTrue(data["observed_registry_digest_match"])
        for gate in ("source_release_parity_verified", "sbom_verified",
                     "publisher_provenance_verified", "resident_agent_approved"):
            with self.subTest(gate=gate):
                self.assertIs(data[gate], False)
        self.assertIs(self.image["permanent_agent_runtime_approved"], False)
        self.assertEqual(data["safe_next_stage"],
                         "offline_source_diff_and_negative_permission_tests_only")

    def test_all_privilege_and_release_review_surfaces_are_named(self):
        data = self.diff
        for path in (
            "tools/approval_yolo.py", "gateway/slash_commands.py",
            "gateway/run_agent_cache.py", "gateway/run_turn.py",
            "hermes_cli/cli_session_mixin.py", "hermes_cli/cli_commands_mixin.py",
            "tests/hermes_cli/test_cli_yolo_resume_persistence.py",
            "tui_gateway/methods_session.py", "run_agent.py",
        ):
            with self.subTest(path=path):
                self.assertIn(path, data["approval_review_required"])
        for file in (".github/workflows/docker.yml",
                     ".github/workflows/stable-release.yml",
                     "plugin-catalog/commandcode-oauth.yaml"):
            self.assertIn(file, data["release_review_required"])

    def test_neither_one_shot_nor_registry_digest_claims_approval(self):
        data = self.diff
        for disputed in (
            "official_registry_digest_implies_source_parity",
            "one_todo_tool_turn_approves_resident_service",
            "yolo_mode_restoration_is_reviewed_safe",
        ):
            self.assertIn(disputed, data["blocked_claims"])
        text = REPORT.read_text(encoding="utf-8")
        self.assertIn("NO-GO", text)
        self.assertIn("39", text)
        self.assertIn("tools/approval_yolo.py", text)
        self.assertIn("SBOM", text)


if __name__ == "__main__":
    unittest.main()
