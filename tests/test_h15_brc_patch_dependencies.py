"""H-15: fail-closed pinned upstream dependency update regression tests."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_patch_dependencies import (
    apply, validate_lock, ORIGINAL, PATCHED, UPSTREAM_SHA,
)
from scripts.h15_remote_commander_candidate_audit import AuditError


class H15DependencyFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "pnpm-workspace.yaml").write_text(ORIGINAL)
        (self.root / "pnpm-lock.yaml").write_text(
            ("somepackage@1.0.0:\n" * 100)
        )

    def fake_git(self, sha=UPSTREAM_SHA):
        return patch(
            "scripts.h15_brc_patch_dependencies.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["git"], returncode=0, stdout=sha + "\n"
            ),
        )

    def test_pinned_override_applied_once_only(self):
        with self.fake_git():
            result = apply(self.root)
        self.assertEqual(result["packages"]["@modelcontextprotocol/sdk"], "1.31.0")
        self.assertEqual(result["packages"]["proxy-addr"], "2.0.8")
        self.assertFalse(result["production_approved"])
        self.assertEqual((self.root / "pnpm-workspace.yaml").read_text(), PATCHED)
        with self.fake_git():
            with self.assertRaisesRegex(AuditError, "unreviewed_dependency_configuration"):
                apply(self.root)

    def test_wrong_upstream_sha_refused(self):
        with self.fake_git("a" * 40):
            with self.assertRaisesRegex(AuditError, "wrong_upstream_revision"):
                apply(self.root)
        self.assertEqual((self.root / "pnpm-workspace.yaml").read_text(), ORIGINAL)

    def test_mutated_workspace_and_symlink_refused(self):
        path = self.root / "pnpm-workspace.yaml"
        path.write_text(ORIGINAL + "unknown: 1\n")
        with self.fake_git():
            with self.assertRaisesRegex(AuditError, "unreviewed_dependency_configuration"):
                apply(self.root)
        path.unlink()
        real = self.root / "real"
        real.write_text(ORIGINAL)
        path.symlink_to(real)
        with self.fake_git():
            with self.assertRaisesRegex(AuditError, "unsafe_pnpm_workspace"):
                apply(self.root)

    def test_pnpm_lock_must_contain_only_patched_versions(self):
        (self.root / "pnpm-workspace.yaml").write_text(PATCHED)
        path = self.root / "pnpm-lock.yaml"
        path.write_text(
            "  '@modelcontextprotocol/sdk@1.31.0':\n"
            "  proxy-addr@2.0.8:\n"
            + " unrelated: installed\n" * 200
        )
        validate_lock(self.root)
        path.write_text(path.read_text() + "  proxy-addr@2.0.7:\n")
        with self.assertRaisesRegex(AuditError, "vulnerable_version_remains"):
            validate_lock(self.root)
        path.unlink()
        with self.assertRaisesRegex(AuditError, "unsafe_pnpm_lockfile"):
            validate_lock(self.root)


if __name__ == "__main__":
    unittest.main()
