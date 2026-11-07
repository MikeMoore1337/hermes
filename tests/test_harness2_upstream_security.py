"""Fail-closed negative cases for optional Harness² metadata import; synthetic only."""
from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import harness2_upstream_manifest as h2  # noqa: E402


class Harness2ImportSecurityTests(unittest.TestCase):
    def make_install(self, home: Path) -> Path:
        install = home / ".local/share/ai-development-toolkit" / ("harness2-" + h2.PIN)
        (install / "source").mkdir(parents=True)
        (install / ".adt-original-harness2").write_text(h2.PIN + "\n", encoding="utf-8")
        return install

    def git_identity(self, *, sha: str = h2.PIN, origin: str = h2.ORIGIN):
        return [subprocess.CompletedProcess([], 0, sha + "\n"),
                subprocess.CompletedProcess([], 0, origin + "\n"),
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0, stdout=b"")]

    def test_corrupt_utf8_install_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            marker = self.make_install(home) / ".adt-original-harness2"
            marker.write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(h2.UpstreamRejected, "PINNED_SOURCE_NOT_INSTALLED"):
                h2.read_external_summary("runs/ns/task/summary.json", home=home)

    def test_io_error_never_discloses_sensitive_absolute_path(self):
        private_path = "/PRIVATE-CREDENTIAL-LOCATION/secret.json"
        err = PermissionError(13, "Permission denied", private_path)
        stderr = io.StringIO()
        with patch.object(h2, "read_external_summary", side_effect=err), patch.object(
            sys, "argv", ["manifest", "runs/ns/task/summary.json"]
        ), patch.object(sys, "stderr", stderr):
            self.assertEqual(h2.main(), 2)
        self.assertIn("HARNESS2_SUMMARY_REJECTED: FILE_ACCESS_FAILED", stderr.getvalue())
        self.assertNotIn(private_path, stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_wrong_git_sha_and_forged_origin_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            self.make_install(home)
            for identity in (self.git_identity(sha="0" * 40),
                             self.git_identity(origin="https://example.test/forged.git")):
                with self.subTest(identity=identity), patch.object(
                    h2.subprocess, "run", side_effect=identity
                ), self.assertRaisesRegex(h2.UpstreamRejected, "UPSTREAM_IDENTITY_MISMATCH"):
                    h2.read_external_summary("runs/ns/task/summary.json", home=home)

    def test_dirty_or_unverifiable_tracked_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            self.make_install(home)
            for git_rc in (1, 128):
                with self.subTest(returncode=git_rc):
                    commands = self.git_identity()
                    commands[-2] = subprocess.CompletedProcess([], git_rc)
                    with patch.object(h2.subprocess, "run", side_effect=commands):
                        with self.assertRaisesRegex(h2.UpstreamRejected, "UPSTREAM_SOURCE_DIRTY"):
                            h2.read_external_summary("runs/ns/task/summary.json", home=home)

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX")
    def test_symlinked_runs_root_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as home_folder, tempfile.TemporaryDirectory() as outside:
            home = Path(home_folder)
            self.make_install(home)
            linked_runs = home / "linked-runs"
            linked_runs.symlink_to(Path(outside), target_is_directory=True)
            with patch.object(h2.subprocess, "run", side_effect=self.git_identity()), patch.dict(
                os.environ, {"HARNESS2_RUNS_DIR": str(linked_runs)}
            ), self.assertRaisesRegex(h2.UpstreamRejected, "UPSTREAM_RUNS_OUTSIDE_HOME"):
                h2.read_external_summary("runs/ns/task/summary.json", home=home)

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX")
    def test_symlinked_summary_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            self.make_install(home)
            runs = home / "native-runs"
            target = runs / "ns/task/summary.json"
            target.parent.mkdir(parents=True)
            target.symlink_to(home / "not-a-real-upstream-result.json")
            with patch.object(h2.subprocess, "run", side_effect=self.git_identity()), patch.dict(
                os.environ, {"HARNESS2_RUNS_DIR": str(runs)}
            ), self.assertRaisesRegex(h2.UpstreamRejected, "SYMLINK_NOT_ALLOWED"):
                h2.read_external_summary("runs/ns/task/summary.json", home=home)


if __name__ == "__main__":
    unittest.main()
