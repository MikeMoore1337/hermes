"""H-632 static acceptance tests; synthetic data only, no network or Docker."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from scripts.h632_ecc_acceptance import (
    EXPECTED_PROFILE, cleanup_ephemeral_ecc_cache, digest, snapshot, validate_plan,
)


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


class ConfinedCacheCleanupTests(unittest.TestCase):
    """Only an H-632-created cache file inside a disposable HOME may be removed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h632-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.cache = self.home / ".claude" / "ecc" / "state.db"
        self.cache.parent.mkdir(parents=True)
        self.cache.write_bytes(b"synthetic-state-db-not-personal")
        self.observed = {".claude/ecc/state.db": digest(self.cache.read_bytes())}

    def test_only_single_owned_cache_file_removed(self):
        extra = self.home / "unrelated.txt"
        extra.write_text("preserve", encoding="utf-8")
        report = cleanup_ephemeral_ecc_cache(self.home, {}, self.observed)
        self.assertEqual(report["scope"], "disposable-H632-HOME-only")
        self.assertEqual(report["path"], ".claude/ecc/state.db")
        self.assertFalse(self.cache.exists())
        self.assertTrue(self.cache.parent.is_dir())
        self.assertEqual(extra.read_text(encoding="utf-8"), "preserve")

    def test_existing_file_is_not_owned_by_acceptance(self):
        with self.assertRaises(ValueError):
            cleanup_ephemeral_ecc_cache(self.home, self.observed, self.observed)
        self.assertTrue(self.cache.is_file())

    def test_drifted_cache_is_refused(self):
        self.cache.write_bytes(b"modified-other-data")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            cleanup_ephemeral_ecc_cache(self.home, {}, self.observed)
        self.assertTrue(self.cache.is_file())

    def test_symlinked_cache_is_refused(self):
        destination = Path(self.tmp.name) / "other-file"
        destination.write_bytes(b"other-synthetic-file")
        self.cache.unlink()
        self.cache.symlink_to(destination)
        with self.assertRaisesRegex(ValueError, "Unsafe cache file"):
            cleanup_ephemeral_ecc_cache(self.home, {}, self.observed)
        self.assertEqual(destination.read_bytes(), b"other-synthetic-file")

    def test_symlinked_parent_is_refused(self):
        other = Path(self.tmp.name) / "unrelated-dir"
        other.mkdir()
        (other / "state.db").write_bytes(b"synthetic")
        self.cache.unlink()
        self.cache.parent.rmdir()
        self.cache.parent.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Unsafe cache parent"):
            cleanup_ephemeral_ecc_cache(self.home, {},
                                        {".claude/ecc/state.db": digest(b"synthetic")})
        self.assertTrue((other / "state.db").is_file())

    def test_hardlink_is_refused(self):
        link = Path(self.tmp.name) / "hardlink"
        link.hardlink_to(self.cache)
        with self.assertRaisesRegex(ValueError, "Unsafe cache file"):
            cleanup_ephemeral_ecc_cache(self.home, {}, self.observed)
        self.assertTrue(link.is_file())

    def test_optimized_python_rejects_entire_acceptance_runner(self):
        import subprocess
        import sys
        p = subprocess.run([sys.executable, "-O", "-m", "scripts.h632_ecc_acceptance",
                            "--preflight", "--ecc-root", "/nonexistent-H632",
                            "--out", "/nonexistent-H632/report.json"],
                           capture_output=True, text=True, check=False, timeout=8)
        self.assertEqual(p.returncode, 2)
        self.assertIn("refusing -O", p.stderr)

    def test_checks_cannot_be_stripped_with_python_optimization(self):
        import subprocess
        import sys
        command = (
            "import sys; from pathlib import Path; "
            "from scripts.h632_ecc_acceptance import cleanup_ephemeral_ecc_cache; "
            "cleanup_ephemeral_ecc_cache(Path(sys.argv[1]), "
            "{'.claude/ecc/state.db':'preexisting'}, "
            "{'.claude/ecc/state.db':'preexisting'})"
        )
        executed = subprocess.run([sys.executable, "-O", "-c", command, str(self.home)],
                                  capture_output=True, text=True, check=False, timeout=8)
        self.assertNotEqual(executed.returncode, 0)
        self.assertIn("Cache is not exclusively test-created", executed.stderr)
        self.assertTrue(self.cache.is_file())

    def test_non_disposable_home_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="ordinary-") as directory:
            user_home = Path(directory) / "home"
            user_home.mkdir()
            with self.assertRaisesRegex(ValueError, "Not an H-632"):
                cleanup_ephemeral_ecc_cache(user_home, {}, self.observed)




if __name__ == "__main__":
    unittest.main()
