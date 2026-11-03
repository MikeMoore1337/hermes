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
    """Execute the real production-deploy decision block with a fake gh command."""

    @staticmethod
    def _script():
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/production-deploy.yml").read_text(encoding="utf-8")
        marker = "      - name: Keep H-585 and H-632 source-only commits out of resident production"
        chunk = workflow.split(marker, 1)[1].split("        run: |\n", 1)[1]
        chunk = chunk.split("\n      - name:", 1)[0]
        return "\n".join(line[10:] if line.startswith("          ") else line
                         for line in chunk.splitlines())

    def _decision(self, filenames):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text("#!/bin/sh\nprintf '%s\\n' \"$H632_TEST_FILES\"\n", encoding="utf-8")
            gh.chmod(0o755)
            output = root / "out"
            summary = root / "summary"
            env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                   "GH_TOKEN": "synthetic", "GITHUB_REPOSITORY": "example/test",
                   "TARGET_SHA": "0" * 40, "GITHUB_OUTPUT": str(output),
                   "GITHUB_STEP_SUMMARY": str(summary),
                   "H632_TEST_FILES": "\n".join(filenames)}
            p = subprocess.run(["bash", "-c", self._script()], env=env,
                               capture_output=True, text=True, timeout=5, check=False)
            return p.returncode, output.read_text() if output.exists() else "", (
                summary.read_text() if summary.exists() else "")

    def test_ecc_only_skips_production(self):
        rc, output, summary = self._decision([
            "scripts/h632_ecc_acceptance.py",
            "tests/test_h632_ecc_acceptance.py",
            ".github/workflows/h632-ecc-original-acceptance.yml",
            ".github/workflows/production-deploy.yml",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("skip=true", output)
        self.assertIn("H632_SOURCE_ONLY_NO_RESIDENT_DEPLOY=PASS", summary)

    def test_existing_h585_exemption_kept(self):
        rc, output, summary = self._decision(["scripts/h585_srt_pilot.py"])
        self.assertEqual(rc, 0)
        self.assertIn("skip=true", output)
        self.assertIn("H585_SOURCE_ONLY_NO_RESIDENT_DEPLOY=PASS", summary)

    def test_mixed_production_changes_must_not_skip(self):
        for paths in (
            ["scripts/h632_ecc_acceptance.py", "agent/agent.py"],
            [".github/workflows/production-deploy.yml"],
            ["docs/other.md"],
        ):
            with self.subTest(paths=paths):
                rc, output, _ = self._decision(paths)
                self.assertEqual(rc, 0)
                self.assertNotIn("skip=true", output)

    def test_empty_and_oversized_diff_fail_closed(self):
        rc, output, _ = self._decision([])
        self.assertNotEqual(rc, 0)
        self.assertNotIn("skip=true", output)
        rc, output, _ = self._decision(["scripts/h632_ecc_acceptance.py"] * 10)
        self.assertEqual(rc, 0)
        self.assertNotIn("skip=true", output)


if __name__ == "__main__":
    unittest.main()
