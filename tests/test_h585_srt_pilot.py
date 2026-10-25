"""Fail-closed checks for #585. No network, sandbox or host config needed."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.h585_srt_pilot import CHECKS, check, prepare, verify


def record(value: bool = True) -> dict:
    return {
        "schema": "h585-sandbox-comparison-v1",
        "probe_executed": True,
        "checks": {name: value for name in CHECKS},
        "child_checks": {name: value for name in CHECKS},
    }


class H585SafetyProbeTests(unittest.TestCase):
    def test_positive_synthetic_verdict(self):
        verify(record())

    def test_one_failed_parent_or_child_boundary_rejected(self):
        for level in ("checks", "child_checks"):
            for name in CHECKS:
                with self.subTest(level=level, name=name):
                    report = record()
                    report[level][name] = False
                    with self.assertRaisesRegex(ValueError, "failed"):
                        verify(report)

    def test_never_confuse_missing_or_incomplete_with_pass(self):
        for change in (
            {"probe_executed": False},
            {"schema": "unrecognized"},
            {"child_checks": {}},
            {"checks": None},
        ):
            with self.subTest(change=change):
                report = record()
                report.update(change)
                with self.assertRaises(ValueError):
                    verify(report)

    def test_parent_execution_without_sandbox_fails_negative_oracle(self):
        with tempfile.TemporaryDirectory(prefix="h585-unittest-") as folder:
            root = Path(folder) / "fixtures"
            prepare(root)
            raw = check(root / "workspace", root / "private", root / "protected", "127.0.0.1", 1)
            self.assertTrue(raw["workspace_write"])
            self.assertTrue(raw["protected_read"])
            self.assertFalse(raw["protected_write_denied"])
            self.assertFalse(raw["private_read_denied"])
            self.assertFalse(raw["symlink_private_read_denied"])
            report = record()
            report["checks"] = raw
            with self.assertRaises(ValueError):
                verify(report)

    def test_only_research_scope_can_bypass_automatic_production(self):
        source = Path(".github/workflows/production-deploy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("id: h585_scope", source)
        self.assertIn("if: steps.h585_scope.outputs.skip != 'true'", source)
        self.assertIn("*) source_only=false", source)
        self.assertIn("saw_pilot=false", source)
        self.assertIn('"$source_only" == true && "$saw_pilot" == true', source)
        self.assertIn("scripts/h585_srt_pilot.py", source)
        self.assertIn(".github/workflows/h585-srt-isolated.yml", source)

    @unittest.skipUnless(shutil.which("bash"), "requires bash for actual deploy guard")
    def test_deploy_scope_guard_real_bash_negative_cases(self):
        workflow = Path(".github/workflows/production-deploy.yml").read_text(
            encoding="utf-8"
        )
        section = workflow.split("      - name: Keep H-585 research-only merges", 1)[1]
        section = section.split("      - name: Verify current main", 1)[0]
        body = section.split("        run: |\n", 1)[1]
        script = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in body.splitlines()
        )
        with tempfile.TemporaryDirectory(prefix="h585-guard-") as d:
            temp = Path(d)
            fake_gh = temp / "gh"
            fake_gh.write_text('#!/bin/sh\ncat "$GH_SYNTHETIC_CHANGED"\n', encoding="utf-8")
            fake_gh.chmod(0o755)
            cases = (
                (["scripts/h585_srt_pilot.py", "docs/operations/H-585-SRT-COMPARISON.md",
                  ".github/workflows/production-deploy.yml"], True, 0),
                (["scripts/h585_srt_pilot.py", "control_center/app.py"], False, 0),
                ([".github/workflows/production-deploy.yml"], False, 0),
                ([], False, 1),
            )
            for i, (paths, allowed, exit_status) in enumerate(cases):
                with self.subTest(case=i):
                    changed = temp / "changed.txt"
                    changed.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
                    out = temp / "github-output.txt"
                    out.write_text("", encoding="utf-8")
                    env = os.environ.copy()
                    env.update({
                        "PATH": str(temp) + os.pathsep + env.get("PATH", ""),
                        "GH_SYNTHETIC_CHANGED": str(changed),
                        "GITHUB_REPOSITORY": "MikeMoore1337/hermes",
                        "TARGET_SHA": "synthetic-no-network",
                        "GITHUB_OUTPUT": str(out),
                        "GITHUB_STEP_SUMMARY": str(temp / "summary.md"),
                    })
                    completed = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", script],
                        env=env, text=True, capture_output=True, timeout=5,
                    )
                    self.assertEqual(completed.returncode, exit_status, completed.stderr)
                    self.assertEqual("skip=true" in out.read_text(encoding="utf-8"), allowed)

    def test_fixture_initialization_cannot_replace_existing_content(self):
        with tempfile.TemporaryDirectory(prefix="h585-unittest-") as folder:
            root = Path(folder) / "fixtures"
            root.mkdir()
            (root / "not-ours.txt").write_text("must remain", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "nonempty"):
                prepare(root)
            self.assertEqual((root / "not-ours.txt").read_text(), "must remain")


if __name__ == "__main__":
    unittest.main()
