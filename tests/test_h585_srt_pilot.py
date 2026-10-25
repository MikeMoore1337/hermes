"""Fail-closed checks for #585. No network, sandbox or host config needed."""
from __future__ import annotations

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
