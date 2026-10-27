"""Original Harness2 upstream is only an optional external CLI integration."""
from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "harness2_upstream.sh"


class Harness2UpstreamContractTests(unittest.TestCase):
    def test_exact_original_pin_and_no_optimizer_or_model_invocation(self):
        content = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("1cfe254e8d25b15f37048c3730134686abe60335", content)
        self.assertIn("https://github.com/google-research/harness2.git", content)
        self.assertNotIn('"$BIN/harness2" ', content)
        self.assertNotIn('"$BIN/harness2-judge"', content)
        self.assertNotIn("codex exec", content)
        self.assertIn('"$BIN/harness2-report"', content)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "POSIX Bash required")
    def test_help_syntax_and_fail_closed_when_missing(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home}
            help_result = subprocess.run(["bash", str(SCRIPT), "--help"],
                                         capture_output=True, text=True, env=env, timeout=10)
            self.assertEqual(0, help_result.returncode)
            fail = subprocess.run(["bash", str(SCRIPT), "check", "--bench", "lab"],
                                  capture_output=True, text=True, env=env, timeout=10)
            self.assertEqual(2, fail.returncode)
            self.assertIn("not installed", fail.stderr)


if __name__ == "__main__":
    unittest.main()
