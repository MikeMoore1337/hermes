"""Negative guards and real synthetic RED/GREEN for H632 model-written source."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h632_model_authored_tdd import (
    MARKER, check_fix, check_root, check_tests, execute, source,
)

GOOD_TESTS = (
    "from calc import add\n\n"
    "def test_add_positive():\n"
    "    assert add(20, 22) == 42\n\n"
    "def test_add_negative():\n"
    "    assert add(-2, 3) == 1\n"
)
GOOD_FIX = "def add(a: int, b: int) -> int:\n    return a + b\n"


class SourceGates(unittest.TestCase):
    def test_valid_model_authored_test_and_fix_syntax(self):
        check_tests(GOOD_TESTS)
        check_fix(GOOD_FIX)
        self.assertEqual(source(GOOD_FIX), GOOD_FIX)
        fence = chr(96) * 3
        self.assertEqual(source(fence + "python\n" + GOOD_FIX + fence), GOOD_FIX)

    def test_code_fence_extra_prose_and_empty_rejected(self):
        fence = chr(96) * 3
        for invalid in ("", "some explanation", fence + "python\n" + GOOD_FIX,
                        GOOD_FIX + "\n" + fence + "evil"):
            with self.subTest(invalid=invalid[:15]):
                with self.assertRaises((ValueError, SyntaxError)):
                    check_fix(source(invalid))

    def test_imports_and_side_effects_are_rejected(self):
        poisoned = (
            "import subprocess\n" + GOOD_TESTS,
            GOOD_TESTS.replace("from calc import add", "from os import system"),
            GOOD_TESTS.replace("assert add(20, 22) == 42",
                               "assert __import__('os').system('id') == 0"),
            GOOD_TESTS.replace("def test_add_positive():",
                               "@print('side effect')\ndef test_add_positive():"),
            GOOD_TESTS.replace("def test_add_negative():",
                               "def test_add_negative() -> __import__('os').system('id'):"),
            GOOD_TESTS.replace("assert add(-2, 3) == 1", "assert add(-2, 3) == 0"),
        )
        for item in poisoned:
            with self.subTest(item=item[:60]):
                with self.assertRaises((ValueError, SyntaxError)):
                    check_tests(item)

    def test_fix_must_be_pure_correct_addition(self):
        invalid = (
            "import os\n" + GOOD_FIX,
            GOOD_FIX.replace("a + b", "a - b"),
            GOOD_FIX.replace("a + b", "__import__('os').system('id')"),
            GOOD_FIX.replace("    return", "    print('hi')\n    return"),
            GOOD_FIX.replace("a: int", "a: __import__('os').system('id')"),
        )
        for item in invalid:
            with self.subTest(item=item[:50]):
                with self.assertRaises((ValueError, SyntaxError)):
                    check_fix(item)


class TestModelWrittenLifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h632-model-code-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "test-home/fixture/h632-model-authored-tdd"
        self.root.parent.mkdir(parents=True)

    def test_real_model_written_red_then_green_with_git_checkpoints(self):
        fix_called = []

        def tests_from_model():
            self.assertFalse((self.root / "test_calc.py").exists())
            return GOOD_TESTS

        def fix_from_model():
            fix_called.append(True)
            self.assertTrue((self.root / "test_calc.py").exists())
            commit_count = subprocess.run(
                ["git", "-C", str(self.root), "rev-list", "--count", "HEAD"],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(commit_count.stdout.strip(), "2")  # RED committed first
            return GOOD_FIX

        receipt = execute(self.root, tests_from_model, fix_from_model)
        self.assertEqual(fix_called, [True])
        self.assertEqual(receipt["status"], "PASS_MODEL_WRITTEN_RED_GREEN")
        self.assertEqual(receipt["red"]["exit"], 1)
        self.assertEqual(len(receipt["red"]["errors"]), 2)
        self.assertEqual(receipt["green"], {"exit": 0, "count": 2, "errors": []})
        self.assertEqual(receipt["return_coverage_percent"], 100)
        self.assertEqual(len(receipt["git_checkpoints"]), 3)
        self.assertEqual((self.root / "h632-model-authored-proof.txt").read_text(), MARKER)

    def test_invalid_model_test_never_invokes_fix_or_writes_pass_marker(self):
        def should_not_run():
            self.fail("Implementation model must NOT be queried before valid RED")
        with self.assertRaises(ValueError):
            execute(self.root, lambda: GOOD_TESTS.replace("== 42", "== 43"),
                    should_not_run)
        self.assertFalse((self.root / "h632-model-authored-proof.txt").exists())

    def test_unapproved_fix_does_not_write_pass_marker(self):
        with self.assertRaises(ValueError):
            execute(self.root, lambda: GOOD_TESTS,
                    lambda: GOOD_FIX.replace("a + b", "a - b"))
        self.assertFalse((self.root / "h632-model-authored-proof.txt").exists())

    def test_preexisting_user_file_not_overwritten(self):
        self.root.mkdir()
        original = self.root / "owner.txt"
        original.write_text("owner")
        with self.assertRaises(ValueError):
            execute(self.root, lambda: GOOD_TESTS, lambda: GOOD_FIX)
        self.assertEqual(original.read_text(), "owner")

    def test_symlinked_disposable_parent_is_rejected(self):
        original = self.root.parent
        original.rmdir()
        actual = Path(self.temporary.name) / "separate"
        actual.mkdir()
        original.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            check_root(self.root)


if __name__ == "__main__":
    unittest.main()
