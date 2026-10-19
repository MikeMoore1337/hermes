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
        self.assertEqual(result["packages"]["undici"], "6.28.1")
        self.assertEqual(result["packages"]["sharp"], "0.35.5")
        for override in (
            "'brace-expansion@^1.0.0': 1.1.21",
            "'brace-expansion@^2.0.0': 2.1.7",
            "'brace-expansion@^5.0.0': 5.0.12",
        ):
            self.assertIn(override, result["source_revision"] and PATCHED)
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

    def test_offline_patch_bundle_includes_lock_and_workspace(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/h15-remote-commander-candidate.yml").read_text()
        start = workflow.index("      - name: Build verified offline patch bundle")
        end = workflow.index("      - name: Preserve owner-selfhosted MIT fork patch artifact", start)
        section = workflow[start:end]
        self.assertIn("          pnpm-lock.yaml\n", section)
        self.assertIn("          pnpm-workspace.yaml\n", section)
        self.assertIn('git -C "$replay" apply --check "$bundle/hermes-brc.patch"', section)
        self.assertIn('cmp "$bundle/hermes-brc.patch" "$RUNNER_TEMP/replayed-brc.patch"', section)

    def test_pnpm_lock_must_contain_only_patched_versions(self):
        (self.root / "pnpm-workspace.yaml").write_text(PATCHED)
        path = self.root / "pnpm-lock.yaml"
        path.write_text(
            "  '@modelcontextprotocol/sdk@1.31.0':\n"
            "  proxy-addr@2.0.8:\n"
            "  undici@6.28.1:\n"
            "  sharp@0.35.5:\n"
            "  brace-expansion@1.1.21:\n"
            "  brace-expansion@2.1.7:\n"
            "  brace-expansion@5.0.12:\n"
            + " unrelated: installed\n" * 200
        )
        validate_lock(self.root)
        path.write_text(path.read_text() + "  proxy-addr@2.0.7:\n")
        with self.assertRaisesRegex(AuditError, "vulnerable_version_remains"):
            validate_lock(self.root)
        path.unlink()
        with self.assertRaisesRegex(AuditError, "unsafe_pnpm_lockfile"):
            validate_lock(self.root)

    def test_reject_stale_versions_in_every_major(self):
        (self.root / "pnpm-workspace.yaml").write_text(PATCHED)
        path = self.root / "pnpm-lock.yaml"
        fixed = (
            "  '@modelcontextprotocol/sdk@1.31.0':\\n"
            "  proxy-addr@2.0.8:\\n"
            "  undici@6.28.1:\\n"
            "  sharp@0.35.5:\\n"
            "  brace-expansion@1.1.21:\\n"
            "  brace-expansion@2.1.7:\\n"
            "  brace-expansion@5.0.12:\\n"
            + " neutral@1.0.0:\\n" * 150
        )
        for package, version in (
            ("undici", "6.28.0"), ("sharp", "0.34.5"),
            ("brace-expansion", "1.1.18"),
            ("brace-expansion", "2.1.4"),
            ("brace-expansion", "5.0.9"),
        ):
            with self.subTest(package=package, version=version):
                path.write_text(fixed + f"  {package}@{version}:\\n")
                with self.assertRaisesRegex(AuditError, "vulnerable_version_remains"):
                    validate_lock(self.root)
        for package, version in (
            ("brace-expansion", "1.1.21"),
            ("brace-expansion", "2.1.7"),
            ("brace-expansion", "5.0.12"),
        ):
            with self.subTest(package=package, version=version):
                path.write_text(fixed.replace(f"  {package}@{version}:\\n", ""))
                with self.assertRaisesRegex(AuditError, "fixed_brace_expansion_branch_absent"):
                    validate_lock(self.root)


if __name__ == "__main__":
    unittest.main()
