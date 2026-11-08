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


    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "POSIX Bash required")
    def test_pinned_status_rejects_modified_tracked_upstream(self):
        # Synthetic Git CLI only: no checkout, no benchmark, no model execution.
        pin = "1cfe254e8d25b15f37048c3730134686abe60335"
        origin = "https://github.com/google-research/harness2.git"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            install = home / ".local/share/ai-development-toolkit" / ("harness2-" + pin)
            source = install / "source"
            binary = install / ".venv/bin"
            fake_bin = home / "bin"
            source.mkdir(parents=True)
            binary.mkdir(parents=True)
            fake_bin.mkdir()
            (install / ".adt-original-harness2").write_text(pin + "\n", encoding="utf-8")
            for cli in ("harness2-check", "harness2-report", "harness2-setup"):
                wrapper = binary / cli
                wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                wrapper.chmod(0o755)
            git = fake_bin / "git"
            git.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *'rev-parse HEAD'*) printf '%s\\n' '" + pin + "' ;;\n"
                "  *'remote get-url origin'*) printf '%s\\n' '" + origin + "' ;;\n"
                "  *'diff --no-ext-diff --quiet HEAD --'*) exit \"${H629_FAKE_GIT_DIFF_RC:-0}\" ;;\n"
                "  *'ls-files --others -z --'*) exit 0 ;;\n"
                "  *) exit 99 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            git.chmod(0o755)
            for rc, expected in ((0, 0), (1, 2), (128, 2)):
                with self.subTest(git_diff_return_code=rc):
                    env = {
                        **os.environ,
                        "HOME": str(home),
                        "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                        "H629_FAKE_GIT_DIFF_RC": str(rc),
                    }
                    result = subprocess.run(
                        ["bash", str(SCRIPT), "status"], capture_output=True, text=True,
                        env=env, timeout=10,
                    )
                    self.assertEqual(expected, result.returncode, result.stderr)
                    if rc == 0:
                        self.assertIn("HARNESS2_UPSTREAM=PINNED", result.stdout)
                    else:
                        self.assertIn("tracked checkout differs", result.stderr)
                        self.assertNotIn("HARNESS2_UPSTREAM=PINNED", result.stdout)

            # A permitted original CLI must never read the checkout's existing
            # __pycache__ files and must clean its temporary isolated cache.
            wrapper = binary / "harness2-check"
            wrapper.write_text(
                "#!/bin/sh" + chr(10)
                + 'echo "PYCACHE=$PYTHONPYCACHEPREFIX"' + chr(10)
                + 'echo "DONTWRITE=$PYTHONDONTWRITEBYTECODE"' + chr(10),
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            safe_env = {
                **os.environ,
                "HOME": str(home),
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                "H629_FAKE_GIT_DIFF_RC": "0",
            }
            cli = subprocess.run(
                ["bash", str(SCRIPT), "check", "--bench", "jb"], capture_output=True,
                text=True, env=safe_env, timeout=10,
            )
            self.assertEqual(0, cli.returncode, cli.stderr)
            self.assertIn("DONTWRITE=1", cli.stdout)
            cache = next(line.partition("=")[2] for line in cli.stdout.splitlines()
                         if line.startswith("PYCACHE="))
            self.assertTrue(cache.startswith("/tmp/hermes-h2-pycache."), cache)
            self.assertFalse(Path(cache).exists(), "temporary Python bytecode cache leaked")


if __name__ == "__main__":
    unittest.main()
