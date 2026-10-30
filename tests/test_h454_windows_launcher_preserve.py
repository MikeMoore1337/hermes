"""Pinned launcher preservation: source guards and synthetic PS5.1 lifecycle."""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_windows_launcher_preserve as subject
from scripts.h454_windows_launcher_patch import RUN, RUN_END, PatchRefused

FIXTURE = ("# fixture only\n" + RUN + """    try {
        & docker.exe info | Out-Null
        & docker.exe image inspect $state.imageId | Out-Null
        Stop-OwnedContainer
        & docker.exe run --pull never --detach --init --pids-limit 128 `
            --read-only $state.imageId | Out-Null
        Require ($LASTEXITCODE -eq 0) 'RUN_FAILED'
        Assert-ManagedContainer
        & docker.exe exec $CONTAINER synthetic-stage | Out-Null
        & docker.exe inspect $CONTAINER | Out-Null
    } finally { Stop-OwnedContainer }
""" + RUN_END + "\n} finally {}\n").encode()
PROFILE = "a" * 64
IMAGE = "sha256:" + "a" * 64


class LauncherPreserveTests(unittest.TestCase):
    def prepare(self, source=FIXTURE, profile=PROFILE, image=IMAGE):
        with patch.object(subject, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
            return subject.prepare(source, profile, image)

    def test_existing_run_is_guarded_and_non_run_bytes_are_preserved(self):
        result = self.prepare().decode()
        original = FIXTURE.decode()
        before, tail = original.split(RUN, 1)
        _, after = tail.split(RUN_END, 1)
        self.assertTrue(result.startswith(before + RUN))
        self.assertTrue(result.endswith(RUN_END + after))
        run = result.split(RUN, 1)[1].split(RUN_END, 1)[0]
        self.assertNotIn("Stop-OwnedContainer", run)
        self.assertEqual(run.count("Stop-H454PreservedContainer"), 3)  # definition and two calls
        self.assertIn("Stop-H454PreservedContainer -Claim", run)
        self.assertIn("if (-not (Start-H454PreservedContainer))", run)
        self.assertIn("container create --pull never", run)
        self.assertIn("npipe:////./pipe/dockerDesktopLinuxEngine", run)
        self.assertIn("H454_DOCKER_OVERRIDE", run)
        self.assertIn("--init --pids-limit 128", run)
        self.assertIn("synthetic-stage", run)
        self.assertIn(PROFILE.upper(), run)
        self.assertIn(IMAGE, run)
        self.assertNotIn("container rm", run)

    def test_untrusted_source_or_changed_anchors_fail_closed(self):
        with self.assertRaisesRegex(PatchRefused, "SOURCE_HASH_MISMATCH"):
            subject.prepare(FIXTURE, PROFILE, IMAGE)
        for bad in (FIXTURE.replace(b"Stop-OwnedContainer", b"Other-Stop", 1),
                    FIXTURE.replace(b"docker.exe run", b"docker.exe create", 1),
                    FIXTURE.replace(b"--detach", b"--rm", 1),
                    FIXTURE.replace(b"--pull never", b"--pull always", 1),
                    FIXTURE.replace(b"Assert-ManagedContainer", b"Other-Assert", 1)):
            with self.subTest(bad=hashlib.sha256(bad).hexdigest()[:8]):
                with self.assertRaisesRegex(PatchRefused, "SOURCE_STRUCTURE_MISMATCH"):
                    self.prepare(bad)
        with self.assertRaisesRegex(PatchRefused, "PROFILE_HASH_INVALID"):
            self.prepare(profile="not-a-hash")
        with self.assertRaisesRegex(PatchRefused, "IMAGE_ID_INVALID"):
            self.prepare(image="not-an-image")

    def test_preserves_utf8_bom_and_crlf(self):
        source = b"\xef\xbb\xbf" + FIXTURE.replace(b"\n", b"\r\n")
        result = self.prepare(source)
        self.assertTrue(result.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\n", result.replace(b"\r\n", b""))

    def test_preparer_never_overwrites_source_or_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.ps1"
            output = Path(directory) / "candidate.ps1"
            source.write_bytes(FIXTURE)
            output.write_bytes(b"existing")
            base = ["prepare", "--source", str(source), "--profile-sha256", PROFILE, "--image-id", IMAGE]
            with patch.object(subject, "SOURCE_SHA256", hashlib.sha256(FIXTURE).hexdigest()):
                for target in (source, output):
                    with self.subTest(target=target.name), patch("sys.argv", base + ["--output", str(target)]):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.assertEqual(subject.main(), 2)
                self.assertEqual(source.read_bytes(), FIXTURE)
                self.assertEqual(output.read_bytes(), b"existing")

    @unittest.skipUnless(os.name == "nt", "requires Windows PowerShell 5.1")
    def test_real_ps51_preserves_and_refuses_unsafe_container(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "fixture-launcher.ps1"
            launcher.write_bytes(self.prepare())
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            harness = Path(__file__).with_name("h454_windows_launcher_preserve_fixture.ps1")
            result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File",
                                     str(harness), str(launcher)], capture_output=True,
                                    text=True, encoding="utf-8", timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("H454_LAUNCHER_PRESERVE_FIXTURES=PASS", result.stdout)
            self.assertEqual(result.stderr.strip(), "")


if __name__ == "__main__":
    unittest.main()
