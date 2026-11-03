"""H-632 static acceptance tests; synthetic data only, no network or Docker."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from scripts.h632_ecc_acceptance import EXPECTED_PROFILE, snapshot, validate_plan


def plan(destinations):
    return {"dryRun": True, "plan": {
        "target": "hermes", "targetRoot": "/test-home/.hermes",
        "installStatePath": "/test-home/.hermes/ecc-install-state.json",
        "selectedModuleIds": sorted(EXPECTED_PROFILE),
        "operations": [{"destinationPath": d} for d in destinations],
    }}


class ECC632GuardTests(unittest.TestCase):
    def test_original_minimal_plan_accepts_bounded_skill_files(self):
        p = plan(["/test-home/.hermes/skills/verification-loop/SKILL.md",
                  "/test-home/.hermes/AGENTS.md",
                  "/test-home/.hermes/mcp-configs/servers.json"])
        self.assertEqual(validate_plan(p)["operations"], 3)

    def test_outside_home_is_rejected(self):
        with self.assertRaises(AssertionError):
            validate_plan(plan(["/etc/passwd", "/test-home/.hermes/skills/a/SKILL.md"]))

    def test_traversal_is_rejected(self):
        with self.assertRaises(AssertionError):
            validate_plan(plan(["/test-home/.hermes/../unsafe", "/test-home/.hermes/skills/a/SKILL.md"]))

    def test_active_hooks_are_rejected(self):
        with self.assertRaises(AssertionError):
            validate_plan(plan(["/test-home/.hermes/hooks/protect.json", "/test-home/.hermes/skills/a/SKILL.md"]))

    def test_live_mcp_config_is_rejected(self):
        with self.assertRaises(AssertionError):
            validate_plan(plan(["/test-home/.hermes/.mcp.json", "/test-home/.hermes/skills/a/SKILL.md"]))

    def test_hook_module_is_rejected(self):
        p = plan(["/test-home/.hermes/skills/a/SKILL.md"])
        p["plan"]["selectedModuleIds"].append("hooks-runtime")
        with self.assertRaises(AssertionError):
            validate_plan(p)

    def test_snapshot_detects_changes_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            f = root / "file.txt"
            f.write_text("before", encoding="utf-8")
            first = snapshot(root)
            (root / "link").symlink_to(f)
            self.assertEqual(snapshot(root), first)
            f.write_text("after", encoding="utf-8")
            self.assertNotEqual(snapshot(root), first)



class ProductionDeployGuardTests(unittest.TestCase):
    """Source-only changes cannot trigger production without manual dispatch."""

    @staticmethod
    def _workflow():
        return (Path(__file__).resolve().parents[1] /
                ".github/workflows/production-deploy.yml").read_text(encoding="utf-8")

    def test_ecc_and_h585_merges_cannot_trigger_deploy(self):
        workflow = self._workflow()
        events = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(events.strip(), "workflow_dispatch:")
        self.assertIn("if: github.event_name == 'workflow_dispatch'", workflow)

    def test_manual_release_still_requires_current_main_and_both_checks(self):
        workflow = self._workflow()
        self.assertIn('if [[ "$current" != "$TARGET_SHA" ]]', workflow)
        self.assertIn('"$quality" == success && "$ui" == success', workflow)
        self.assertIn("Manual dispatch refused: required SHA-scoped checks not green", workflow)


if __name__ == "__main__":
    unittest.main()
