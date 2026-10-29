"""Offline launcher preparation: preserve staging, cleanup and all private bytes."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_windows_launcher_patch as subject

FIXTURE = ("# preserved private configuration\n" + subject.RUN +
           "    docker run --pids-limit 96\n" +
           "    try { Stage-ExistingCredentials } finally { Stop-OwnedContainer }" +
           subject.RUN_END + "\n    docker run --pids-limit 96\n}\n").encode()


class LauncherPatchTests(unittest.TestCase):
    def patched(self, data=FIXTURE):
        with patch.object(subject, "SOURCE_SHA256", hashlib.sha256(data).hexdigest()):
            return subject.prepare(data)

    def test_both_create_sites_have_init_limits_and_oom_protection(self):
        result = self.patched().decode()
        self.assertEqual(result.count("--init --pids-limit 128 --oom-kill-disable=false"), 2)
        self.assertNotIn("--pids-limit 96", result)
        self.assertIn("Stage-ExistingCredentials", result)
        self.assertIn("finally { Stop-OwnedContainer }", result)

    def test_run_lock_covers_start_staging_and_cleanup(self):
        result = self.patched().decode()
        self.assertLess(result.index("[IO.FileShare]::None"), result.index("docker run"))
        self.assertLess(result.index("Stop-OwnedContainer"), result.index("$runtimeLock.Dispose()"))
        self.assertEqual(result.count("$runtimeLock.Dispose()"), 1)

    def test_unexpected_source_and_structure_are_refused(self):
        with self.assertRaisesRegex(subject.PatchRefused, "SOURCE_HASH_MISMATCH"):
            subject.prepare(FIXTURE)
        bad = FIXTURE.replace(b"--pids-limit 96", b"--pids-limit 97", 1)
        with self.assertRaisesRegex(subject.PatchRefused, "SOURCE_STRUCTURE_MISMATCH"):
            self.patched(bad)

    def test_preserves_crlf_and_other_bytes(self):
        result = self.patched(FIXTURE.replace(b"\n", b"\r\n"))
        self.assertNotIn(b"\n", result.replace(b"\r\n", b""))
        self.assertTrue(result.startswith(b"# preserved private configuration\r\n"))

    def test_does_not_overwrite_source_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "original.ps1", Path(directory) / "candidate.ps1"
            source.write_bytes(FIXTURE)
            with patch.object(subject, "SOURCE_SHA256", hashlib.sha256(FIXTURE).hexdigest()):
                subject.write_candidate(source, output)
                saved = output.read_bytes()
                with self.assertRaises(FileExistsError):
                    subject.write_candidate(source, output)
                with self.assertRaisesRegex(subject.PatchRefused, "OUTPUT_PATH"):
                    subject.write_candidate(source, source)
            self.assertEqual(source.read_bytes(), FIXTURE)
            self.assertEqual(output.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
