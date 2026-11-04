"""Hermes H632 fixture guard tests. Only synthetic data and disposable HOME."""
import tempfile
import unittest
from pathlib import Path

from scripts.h632_full_verification import (
    checked_node_coverage, prepare, run, root_checked, security_scan,
)


class SixPhaseSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h632-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "home/fixture/h632-sixphase"
        self.root.mkdir(parents=True)

    def test_prepare_makes_synthetic_project_and_only_one_expected_change(self):
        self.assertEqual(prepare(self.root)["status"], "PREPARED")
        self.assertTrue((self.root / ".git").is_dir())
        self.assertEqual(security_scan(self.root)["issues"], 0)

    def test_cannot_overwrite_preexisting_owner_file(self):
        p = self.root / "file.txt"
        p.write_text("owner data")
        with self.assertRaisesRegex(ValueError, "empty"):
            prepare(self.root)
        self.assertEqual(p.read_text(), "owner data")

    def test_wrong_root_fails_closed(self):
        wrong = self.root.parent / "unexpected"
        wrong.mkdir()
        with self.assertRaisesRegex(ValueError, "isolated H632"):
            root_checked(wrong)

    def test_symlink_root_fails_closed(self):
        link = self.root.parent / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            root_checked(link)

    def test_fake_secret_rejected(self):
        prepare(self.root)
        src = self.root / "src/math.js"
        src.write_text(src.read_text() + "// sk-AAAAAAAAAAAAAAAA\n")
        with self.assertRaisesRegex(AssertionError, "Security scan rejected"):
            security_scan(self.root)

    def test_unprepared_run_rejected(self):
        with self.assertRaisesRegex(ValueError, "not prepared"):
            run(self.root, "/does-not-exist.js")

    def test_node_test_summary_accepts_old_and_new_prefix(self):
        for prefix in ("#", "ℹ"):
            output = (f"{prefix} tests 2\n{prefix} pass 2\n"
                      f"{prefix} all files | 100.00 | 100.00 | 100.00 |\n")
            self.assertEqual(checked_node_coverage(output), 100.0)

    def test_node_test_summary_rejects_missing_tests_and_low_coverage(self):
        with self.assertRaisesRegex(AssertionError, "pass"):
            checked_node_coverage("# tests 2\n# pass 1\n# all files | 100.00\n")
        with self.assertRaisesRegex(AssertionError, "coverage"):
            checked_node_coverage("ℹ tests 2\nℹ pass 2\nℹ all files | 79.99\n")

    def test_failed_typecheck_cannot_create_success_marker_or_be_reused(self):
        prepare(self.root)
        with self.assertRaisesRegex(AssertionError, "Phase 2 failed"):
            run(self.root, "/does-not-exist.js")
        self.assertFalse((self.root / "h632-six-phase-proof.txt").exists())
        self.assertEqual((self.root / "h632-six-phase-receipt.json").is_file(), True)
        with self.assertRaisesRegex(ValueError, "No reuse"):
            run(self.root, "/does-not-exist.js")


if __name__ == "__main__":
    unittest.main()
