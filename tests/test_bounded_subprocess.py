"""Real negative subprocess tests, never use Docker or credentials."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scripts.bounded_subprocess import BoundedProcessError, run_bounded


def spawn(script: str, **kwargs):
    return run_bounded([sys.executable, "-B", "-c", script],
                       timeout=kwargs.pop("timeout", 3),
                       stdout_limit=kwargs.pop("stdout_limit", 8192),
                       stderr_limit=kwargs.pop("stderr_limit", 8192),
                       **kwargs)


class BoundedSubprocessTests(unittest.TestCase):
    def test_stdout_at_limit_passes(self):
        result = spawn("import sys;sys.stdout.write('x'*8192)")
        self.assertEqual(len(result.stdout), 8192)
        self.assertEqual(result.stderr, b"")

    def test_stdout_overflow_is_rejected_and_not_returned(self):
        with self.assertRaisesRegex(BoundedProcessError, "output_limit_exceeded"):
            spawn("import sys;sys.stdout.write('PRIVATE'*50000);sys.stdout.flush()",
                  stdout_limit=4096)

    def test_stderr_overflow_is_rejected_without_secret_leak(self):
        with self.assertRaises(BoundedProcessError) as caught:
            spawn("import sys;sys.stderr.write('SECRET_TOKEN'*50000);sys.stderr.flush()",
                  stderr_limit=4096)
        self.assertIn("output_limit_exceeded", str(caught.exception))
        self.assertNotIn("SECRET", str(caught.exception))

    def test_simultaneous_stdout_stderr_flood_has_no_deadlock(self):
        start = time.monotonic()
        with self.assertRaises(BoundedProcessError):
            spawn("import os;os.write(1,b'x'*200000);os.write(2,b'y'*200000)",
                  stdout_limit=4096, stderr_limit=4096)
        self.assertLess(time.monotonic() - start, 5)

    def test_timeout_kills_child(self):
        with self.assertRaisesRegex(BoundedProcessError, "child_timeout"):
            spawn("import time;time.sleep(20)", timeout=0.15)

    def test_zero_output_is_valid(self):
        self.assertEqual(spawn("pass").stdout, b"")

    def test_nonzero_exit_fails_closed(self):
        with self.assertRaisesRegex(BoundedProcessError, "child_nonzero_exit"):
            spawn("raise SystemExit(5)")

    def test_start_error_fails_closed(self):
        with self.assertRaisesRegex(BoundedProcessError, "child_start_failed"):
            run_bounded(["hermes_command_that_does_not_exist_20261015"],
                        timeout=1, stdout_limit=100)

    def test_invalid_utf8_stdout_denied(self):
        with self.assertRaisesRegex(BoundedProcessError, "invalid_output_encoding"):
            spawn("import os;os.write(1,b'\\xff')")

    def test_invalid_utf8_stderr_denied(self):
        with self.assertRaisesRegex(BoundedProcessError, "invalid_output_encoding"):
            spawn("import os;os.write(2,b'\\xff')")

    def test_secret_stderr_is_never_returned(self):
        result = spawn("import sys;sys.stderr.write('SECRET_TOKEN')")
        self.assertEqual(result.stderr, b"")
        self.assertNotIn("SECRET_TOKEN", str(result))

    def test_reject_invalid_budgets(self):
        for value in (0, -1, 1_000_001, True):
            with self.subTest(limit=value):
                with self.assertRaisesRegex(BoundedProcessError, "invalid_subprocess_budget"):
                    run_bounded([sys.executable], timeout=1, stdout_limit=value)

    def test_child_process_tree_terminated_when_parent_times_out(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "child-out.txt")
            child_code = ("import pathlib,time;time.sleep(1);"
                          f"pathlib.Path({marker!r}).write_text('escaped')")
            parent_code = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
                "time.sleep(30)"
            )
            with self.assertRaisesRegex(BoundedProcessError, "child_timeout"):
                spawn(parent_code, timeout=0.2)
            time.sleep(1.1)
            self.assertFalse(Path(marker).exists(), "grandchild escaped termination")


if __name__ == "__main__":
    unittest.main()
