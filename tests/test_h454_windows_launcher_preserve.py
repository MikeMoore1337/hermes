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

FIXTURE = ("""# fixture only
function Stop-TunnelByPid([int]$tunnelProcessId) {
    if ($exe -ne 'ssh.exe' -or -not $cmd.Contains($TUNNEL_TARGET) -or -not $cmd.Contains('38180:fixture')) { return }
}
""" + RUN + """    try {
        $state = Get-Content -LiteralPath $STATE_PATH -Raw | ConvertFrom-Json
        & docker.exe info | Out-Null
        & docker.exe image inspect $state.imageId | Out-Null
        Stop-OwnedContainer
        Stop-TunnelByPid ([int]$state.tunnelPid)
        $sshArgs = @('-o','ExitOnForwardFailure=yes')
        $SSH_PROCESS = Start-Process -FilePath 'ssh.exe' -ArgumentList $sshArgs -PassThru -WindowStyle Hidden
        $ready=$false
        for ($i=0; $i -lt 30; $i++) {
            if ($SSH_PROCESS.HasExited) { throw 'SSH_EXITED' }
            if (Test-LocalHealth) { $ready=$true; break }
            Start-Sleep -Seconds 1
        }
        Require $ready 'SSH_NOT_READY'
        & docker.exe run --pull never --detach --init --pids-limit 128 `
            --read-only $state.imageId | Out-Null
        Require ($LASTEXITCODE -eq 0) 'RUN_FAILED'
        Assert-ManagedContainer
        $encrypted = Get-Content -LiteralPath $CRED_PATH -Raw
        $credentials | & docker.exe exec --interactive $CONTAINER /bin/sh /usr/local/bin/h15-stage.sh | Out-Null
        $state.tunnelPid = $SSH_PROCESS.Id
        [IO.File]::WriteAllText($STATE_PATH,($state | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        while (-not $SSH_PROCESS.HasExited) {
            & docker.exe inspect $CONTAINER | Out-Null
            if (-not (Test-LocalHealth)) { throw 'RELAY_NOT_READY' }
        }
    } finally {
        Stop-OwnedContainer
        if ($SSH_PROCESS -and -not $SSH_PROCESS.HasExited) {
            Stop-TunnelByPid $SSH_PROCESS.Id
        }
    }
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
        self.assertIn("Assert-H454ExistingTunnel\n        Stop-H454PreservedContainer -Claim", run)
        self.assertIn("Stop-H454ExistingTunnel", run)
        self.assertIn("Stop-H454TunnelHandle $SSH_PROCESS", run)
        self.assertIn("$null = $SSH_PROCESS.Handle", run)
        self.assertNotIn("Stop-TunnelByPid", run)
        self.assertIn("Stop-H454PreservedContainer -Claim", run)
        self.assertIn("if (-not (Start-H454PreservedContainer))", run)
        self.assertIn("container create --pull never", run)
        self.assertIn("npipe:////./pipe/dockerDesktopLinuxEngine", run)
        self.assertIn("H454_DOCKER_OVERRIDE", run)
        self.assertIn("--init --pids-limit 128", run)
        self.assertIn("h15-stage.sh", run)
        self.assertIn("Save-H454State", run)
        self.assertIn("H454_STATE_READ_DRIFT", run)
        self.assertIn("tunnelCreatedUtcTicks", run)
        self.assertIn("$SSH_PROCESS.StartTime.ToUniversalTime().Ticks", run)
        self.assertIn("if (Test-LocalHealth) { Assert-H454StartedTunnel $SSH_PROCESS; $ready=$true; break }", run)
        self.assertIn("Assert-H454StartedTunnel $SSH_PROCESS\n        $encrypted = Get-Content", run)
        self.assertIn("Assert-H454StartedTunnel $SSH_PROCESS\n        $credentials | & $script:h454Docker", run)
        self.assertIn("Assert-H454StartedTunnel $SSH_PROCESS\n            if (-not (Test-LocalHealth))", run)
        self.assertNotIn("[IO.File]::WriteAllText($STATE_PATH,($state | ConvertTo-Json)", run)
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
                    FIXTURE.replace(b"38180:fixture", b"other-forward", 1),
                    FIXTURE.replace(b"-FilePath 'ssh.exe'", b"-FilePath 'other.exe'", 1),
                    FIXTURE.replace(b"Get-Content -LiteralPath $STATE_PATH", b"Get-Content -LiteralPath $OTHER_PATH", 1),
                    FIXTURE.replace(b"[IO.File]::WriteAllText($STATE_PATH", b"[IO.File]::AppendAllText($STATE_PATH", 1),
                    FIXTURE.replace(b"$state.tunnelPid = $SSH_PROCESS.Id", b"$state.tunnelPid = 0", 1),
                    FIXTURE.replace(b"ExitOnForwardFailure=yes", b"ExitOnForwardFailure=no", 1),
                    FIXTURE.replace(b"if (Test-LocalHealth) { $ready=$true; break }", b"if (Test-LocalHealth) { break }", 1),
                    FIXTURE.replace(b"$encrypted = Get-Content -LiteralPath $CRED_PATH -Raw", b"$encrypted = 'unreviewed'", 1),
                    FIXTURE.replace(b"/usr/local/bin/h15-stage.sh", b"/usr/local/bin/unreviewed.sh", 1),
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

    if os.name == "nt":
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
