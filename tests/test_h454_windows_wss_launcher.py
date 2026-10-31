"""Compose the identity, interrupted-transition and WSS launcher changes."""
import base64
import hashlib
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import GUARD, patch_launcher
from scripts.h454_windows_launcher_patch import LOCK, RUN, RUN_END
from scripts import h454_windows_launcher_preserve as preserve
from scripts import h454_windows_wss_launcher as wss
from tests.test_h454_windows_launcher_preserve import FIXTURE, IMAGE, PROFILE


def fixture() -> bytes:
    prefix = """#requires -Version 5.1
param([string]$Mode = 'Install')
$ErrorActionPreference = 'Stop'
$PORT = 38180
$RELAY = 'fixture-relay:3000'
$STATE_PATH = 'fixture-state'
function Test-LocalHealth {
    $response = & curl.exe --noproxy '*' --silent
    return ($LASTEXITCODE -eq 0 -and $response -eq '200')
}
"""
    source = FIXTURE.decode().replace("38180:fixture", "127.0.0.1:38180:fixture-relay:3000")
    source = source.replace("$sshArgs = @('-o','ExitOnForwardFailure=yes')",
        """$sshArgs = @('-p',[string]$SSH_PORT,'-i',"`"$KEY`"",'-N','-T',
            '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ExitOnForwardFailure=yes','-L',"127.0.0.1:${PORT}:$RELAY",$TUNNEL_TARGET)""")
    source = source.replace("throw 'RELAY_NOT_READY'", "throw 'TUNNEL_HEALTH_LOST'")
    source = source.replace("'SSH_EXITED'", "'SSH_TUNNEL_EXITED'").replace("'SSH_NOT_READY'", "'SSH_TUNNEL_NOT_READY'")
    source = source.replace("if (-not (Test-LocalHealth)) { throw 'TUNNEL_HEALTH_LOST' }\n",
                            "if (-not (Test-LocalHealth)) { throw 'TUNNEL_HEALTH_LOST' }\n"
                            "            Start-Sleep -Seconds 20\n", 1)
    source = source.replace(RUN, RUN + LOCK, 1).replace(
        RUN_END, "\n    } finally { $runtimeLock.Dispose() }" + RUN_END, 1)
    source = source.replace("        $encrypted = Get-Content -LiteralPath $CRED_PATH -Raw\n",
        "        $encrypted = Get-Content -LiteralPath $CRED_PATH -Raw\n"
        "        $ss = ConvertTo-SecureString -String ($encrypted.Trim())\n"
        "        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)\n"
        "        try { $credentials = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }\n"
        "        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $ss.Dispose() }\n"
        "        $json = $credentials | ConvertFrom-Json\n"
        "        Require ($json.deviceId -ceq $state.deviceId) 'DPAPI_DEVICE_ID_MISMATCH'\n", 1)
    source = source.replace("        $state.tunnelPid = $SSH_PROCESS.Id\n",
        "        $credentials = $null; $json = $null\n        $state.tunnelPid = $SSH_PROCESS.Id\n", 1)
    source = source.replace("$credentials | & docker.exe exec --interactive $CONTAINER /bin/sh /usr/local/bin/h15-stage.sh | Out-Null\n",
        "$credentials | & docker.exe exec --interactive $CONTAINER /bin/sh /usr/local/bin/h15-stage.sh | Out-Null\n"
        "        Require ($LASTEXITCODE -eq 0) 'STAGE_FAILED'\n", 1)
    raw = (prefix + source).encode()
    with patch.object(preserve, "SOURCE_SHA256", hashlib.sha256(raw).hexdigest()):
        preserved = preserve.prepare(raw, PROFILE, IMAGE).decode()
    preserved = preserved.replace("        Stop-H454PreservedContainer\n        if ($null -ne $script:h454OriginalTunnel)",
                                  "        try { Stop-H454PreservedContainer } catch {}\n"
                                  "        if ($null -ne $script:h454OriginalTunnel)", 1)
    return patch_launcher(preserved).encode()


class WssLauncherTests(unittest.TestCase):
    # This synthetic launcher is the e37f6b41 output for public test inputs.
    def test_installed_legacy_launcher_reaches_the_same_guarded_wss_output(self):
        legacy = (Path(__file__).parent / "fixtures/h454_legacy_launcher_e37f.ps1.txt").read_text(encoding="utf-8").encode()
        candidate_image = "sha256:" + "b" * 64
        candidate_profile = "d" * 64
        actual = wss.prepare_from_installed(legacy, source_sha256=hashlib.sha256(legacy).hexdigest(),
                                            ca_sha256="a" * 64, identity_sha256="c" * 64,
                                            candidate_image_id=candidate_image, candidate_profile_sha256=candidate_profile)
        source = fixture().replace(IMAGE.encode(), candidate_image.encode()).replace(PROFILE.upper().encode(), candidate_profile.upper().encode())
        expected = wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(),
                               ca_sha256="a" * 64, identity_sha256="c" * 64)
        self.assertEqual(actual, expected)
        self.assertIn(GUARD.encode(), actual)
        self.assertIn(b"Initialize-H454TunnelJob $PSCommandPath", actual)

    def test_installed_legacy_launcher_refuses_drift_and_preserves_newlines(self):
        legacy = (Path(__file__).parent / "fixtures/h454_legacy_launcher_e37f.ps1.txt").read_text(encoding="utf-8").encode()
        digest = hashlib.sha256(legacy).hexdigest()
        candidate = {"candidate_image_id": "sha256:" + "b" * 64, "candidate_profile_sha256": "d" * 64}
        changed = legacy.replace(b"H454_STATE_ACL", b"H454_STATE_OTHER", 1)
        for altered, pin in ((changed, digest), (changed, hashlib.sha256(changed).hexdigest()),
                             (legacy.replace(b"ExitOnForwardFailure=yes", b"ExitOnForwardFailure=no"), None),
                             (legacy.replace(b"$ready=$true", b"$ready=$false", 1), None)):
            with self.subTest(length=len(altered)), self.assertRaises(AuditError):
                wss.prepare_from_installed(altered, source_sha256=pin or hashlib.sha256(altered).hexdigest(),
                                           ca_sha256="a" * 64, identity_sha256="c" * 64, **candidate)
        for image, profile in ((IMAGE, "d" * 64), ("sha256:bad", "d" * 64), ("sha256:" + "b" * 64, "bad")):
            with self.subTest(image=image, profile=profile), self.assertRaises(AuditError):
                wss.prepare_from_installed(legacy, source_sha256=digest, ca_sha256="a" * 64,
                                           identity_sha256="c" * 64, candidate_image_id=image,
                                           candidate_profile_sha256=profile)
        crlf = b"\xef\xbb\xbf" + legacy.replace(b"\n", b"\r\n")
        result = wss.prepare_from_installed(crlf, source_sha256=hashlib.sha256(crlf).hexdigest(),
                                            ca_sha256="a" * 64, identity_sha256="c" * 64, **candidate)
        self.assertTrue(result.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\n", result.replace(b"\r\n", b""))

    def test_composed_launcher_uses_tls_and_in_memory_credentials(self):
        source = fixture()
        output = wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="a" * 64,
                             identity_sha256="c" * 64).decode()
        self.assertIn("if ($Mode -ne 'Run') { throw 'H454_OWNER_OPERATOR_REQUIRED' }", output)
        self.assertIn("$PORT = 38184", output)
        self.assertIn("$RELAY.Substring(0, $RELAY.Length - 4) + '3001'", output)
        self.assertIn("-LocalPort $PORT -State Listen", output)
        self.assertIn("$script:h454TunnelNeedle = \"127.0.0.1:${PORT}:$RELAY\"", output)
        self.assertIn("A" * 64, output)
        self.assertIn("C" * 64, output)
        self.assertIn("$sshArgs = @('-F','NUL',", output)
        self.assertIn("$KEY = $script:h454WssIdentity", output)
        self.assertLess(output.index("Initialize-H454TunnelJob $PSCommandPath"),
                        output.index("$SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs"))
        self.assertLess(output.index("Assert-H454WssIdentity\n        $h454Preflight"),
                        output.index("Stop-H454ExistingTunnel\n"))
        self.assertIn("$h454Curl -q --proto '=https' --noproxy '*'", output)
        self.assertIn("--ssl-revoke-best-effort", output)
        self.assertLess(output.index("$credentials = Convert-H454SecureCredential"),
                        output.index("$credentials | & $script:h454Docker"))
        self.assertEqual(output.count(GUARD), 1)
        self.assertIn("while ($true) {", output)
        self.assertIn("$SSH_PROCESS = Restart-H454WssTunnel $h454Previous $sshArgs", output)
        self.assertLess(output.index("$h454Preflight = Get-H454PreservedContainer"),
                        output.index("$SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs"))
        self.assertLess(output.index("$SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs"),
                        output.index("if ($script:h454PreflightWasRunning)"))
        self.assertIn("Assert-H454StagedCredential $h454Running.Id $credentials", output)
        self.assertIn("H454_RUNNING_CONTAINER_CLAIM_REFUSED", output)
        self.assertNotIn('"', wss.VERIFY_STAGED_JS)
        self.assertNotIn('$', wss.VERIFY_STAGED_JS)
        self.assertIn("if (-not $h454KeepContainer) { try { Stop-H454PreservedContainer } catch {} }", output)
        self.assertIn("H454_CONTAINER_PREFLIGHT_DRIFT", output)
        self.assertEqual(output.count("$h454StateHash = Save-H454State $h454StateHash $state"), 2)

    def test_changed_input_bad_hash_and_missing_security_anchors_refuse(self):
        source = fixture()
        for altered in (source.replace(b"H454_RECOVERY_REQUIRED", b"REMOVED"),
                        source.replace(b"Assert-H454StartedTunnel", b"MissingTunnelGuard"),
                        source.replace(b"DPAPI_DEVICE_ID_MISMATCH", b"OTHER"),
                        source.replace(b"-LocalPort 38180", b"-LocalPort 1"),
                        source.replace(b"TUNNEL_HEALTH_LOST", b"OTHER"),
                        source.replace(b"SSH_TUNNEL_NOT_READY", b"OTHER"),
                        source.replace(b"'IdentitiesOnly=yes'", b"'IdentitiesOnly=no'"),
                        source.replace(b"'IdentitiesOnly=yes'", b"'IdentitiesOnly=yes','-o','IdentityFile=other'"),
                        source.replace(b"'IdentitiesOnly=yes'", b"'IdentitiesOnly=yes','-o','ProxyCommand=other'"),
                        source.replace(b"'-i'", b"'-j'"),
                        source.replace(b"Stop-H454PreservedContainer -Claim", b"Other-Claim"),
                        source.replace(b"try { Stop-H454PreservedContainer } catch {}", b"Other-Cleanup")):
            with self.subTest(length=len(altered)), self.assertRaises(AuditError):
                wss.prepare(altered, source_sha256=hashlib.sha256(altered).hexdigest(), ca_sha256="a" * 64,
                            identity_sha256="c" * 64)
        with self.assertRaises(AuditError):
            wss.prepare(source, source_sha256="0" * 64, ca_sha256="a" * 64, identity_sha256="c" * 64)
        with self.assertRaises(AuditError):
            wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="invalid", identity_sha256="c" * 64)
        with self.assertRaises(AuditError):
            wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="a" * 64, identity_sha256="invalid")
        with patch.object(wss, "CREDENTIAL_SOURCE_SHA256", "0" * 64), self.assertRaises(AuditError):
            wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="a" * 64, identity_sha256="c" * 64)

    def test_crlf_and_bom_preserved(self):
        source = b"\xef\xbb\xbf" + fixture().replace(b"\n", b"\r\n")
        output = wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="b" * 64,
                             identity_sha256="c" * 64)
        self.assertTrue(output.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\n", output.replace(b"\r\n", b""))

    def _assert_windows_reconnect_monitor_keeps_container_and_tracks_processes(self):
        source = fixture()
        with tempfile.TemporaryDirectory(prefix="h454-wss-monitor-") as tmp:
            launcher = Path(tmp) / "launcher.ps1"
            identity = Path(tmp) / "wss-ssh-identity.pub"
            identity.write_bytes(b"synthetic-public-identity\n")
            output = wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(), ca_sha256="a" * 64,
                                 identity_sha256=hashlib.sha256(identity.read_bytes()).hexdigest())
            launcher.write_bytes(output)
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            harness = Path(__file__).with_name("h454_windows_wss_reconnect_fixture.ps1")
            result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File", str(harness), str(launcher)],
                                    capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("H454_WSS_RECONNECT_FIXTURE=PASS", result.stdout)

    if os.name == "nt":
        test_windows_reconnect_monitor_keeps_container_and_tracks_processes = _assert_windows_reconnect_monitor_keeps_container_and_tracks_processes

    def _assert_windows_launcher_death_kills_only_its_children(self):
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        with tempfile.TemporaryDirectory(prefix="h454-job-") as tmp:
            root = Path(tmp)
            script = root / "parent.ps1"
            pid_file = root / "child.pid"
            script.write_text(
                "param([string]$PidFile)\n$ErrorActionPreference='Stop'\n"
                "function Require([bool]$Ok,[string]$Why){if(-not $Ok){throw $Why}}\n" +
                wss.JOB_GUARD +
                "Initialize-H454TunnelJob $PSCommandPath\n"
                "$exe=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'\n"
                "$child=Start-Process -FilePath $exe -ArgumentList '-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 60\"' -PassThru -WindowStyle Hidden\n"
                "[IO.File]::WriteAllText($PidFile+'.new',[string]$child.Id)\n"
                "[IO.File]::Move($PidFile+'.new',$PidFile)\n"
                "[Console]::WriteLine('READY')\nStart-Sleep -Seconds 60\n", encoding="utf-8")
            sibling = subprocess.Popen([str(powershell), "-NoProfile", "-NonInteractive", "-Command",
                                        "Start-Sleep -Seconds 60"], creationflags=subprocess.CREATE_NO_WINDOW)
            parent = None
            child = None
            owned_child = False
            try:
                parent = subprocess.Popen([str(powershell), "-NoProfile", "-NonInteractive", "-File",
                                           str(script), str(pid_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                deadline = time.monotonic() + 20
                while not pid_file.is_file() and parent.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                if not pid_file.is_file():
                    if parent.poll() is None:
                        parent.terminate()
                    _, error = parent.communicate(timeout=5)
                    self.fail("synthetic launcher did not start its child: " + error.decode(errors="replace"))
                child_pid = int(pid_file.read_text(encoding="ascii"))
                child = kernel.OpenProcess(0x00100001, False, child_pid)  # SYNCHRONIZE | PROCESS_TERMINATE
                self.assertTrue(child, "cannot hold the synthetic child process handle")
                self.assertEqual(kernel.WaitForSingleObject(child, 0), 0x102, "synthetic child already exited")
                observed = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command",
                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={child_pid}').ParentProcessId"],
                    capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(observed.returncode, 0)
                self.assertEqual(observed.stdout.strip(), str(parent.pid), "child is not owned by the fixture launcher")
                owned_child = True
                parent.terminate()
                parent.wait(timeout=5)
                self.assertEqual(kernel.WaitForSingleObject(child, 10000), 0, "child survived launcher death")
                self.assertIsNone(sibling.poll(), "unrelated sibling was terminated")

                source = ("$ErrorActionPreference='Stop'\n"
                          "function Require([bool]$Ok,[string]$Why){if(-not $Ok){throw $Why}}\n" +
                          wss.JOB_GUARD + "Initialize-H454TunnelJob 'C:\\synthetic.ps1'\n")
                encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
                refused = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                         capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(b"H454_DEDICATED_PROCESS_REQUIRED", refused.stderr)
                forged_source = ("$ErrorActionPreference='Stop'\n"
                    "function Require([bool]$Ok,[string]$Why){if(-not $Ok){throw $Why}}\n" + wss.JOB_GUARD +
                    "Assert-H454DedicatedProcess -h454Args @('powershell.exe','-NoProfile','-Command','x','-File','C:\\synthetic.ps1') "
                    "-ScriptPath 'C:\\synthetic.ps1'\n")
                forged_encoded = base64.b64encode(forged_source.encode("utf-16le")).decode("ascii")
                forged = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", forged_encoded],
                                        capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertNotEqual(forged.returncode, 0)
                self.assertIn(b"H454_DEDICATED_PROCESS_REQUIRED", forged.stderr)
            finally:
                if parent is not None and parent.poll() is None:
                    parent.terminate()
                    parent.wait(timeout=5)
                if child:
                    if owned_child and kernel.WaitForSingleObject(child, 0) == 0x102:
                        kernel.TerminateProcess(child, 1)
                        kernel.WaitForSingleObject(child, 5000)
                    kernel.CloseHandle(child)
                if sibling.poll() is None:
                    sibling.terminate()
                sibling.wait(timeout=5)
                if parent is not None:
                    parent.stdout.close()
                    parent.stderr.close()

    if os.name == "nt":
        test_windows_launcher_death_kills_only_its_children = _assert_windows_launcher_death_kills_only_its_children

    def _assert_windows_tls_health_checks_synthetic_certificates(self):
        bash = Path(os.environ["ProgramFiles"]) / "Git" / "bin" / "bash.exe"
        node = shutil.which("node.exe")
        self.assertTrue(bash.is_file() and node, "Git Bash and Node must exist on the Windows runner")
        cert_script = Path(__file__).resolve().parents[1] / "scripts" / "h454_wss_fixture_certificates.sh"
        with tempfile.TemporaryDirectory(prefix="h454-wss-health-") as tmp:
            root = Path(tmp).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            subprocess.run([str(bash), str(cert_script), str(root)], check=True,
                           capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            ca = root / "wss-relay-ca.pem"
            shutil.copyfile(root / "ca.crt", ca)
            source = fixture()
            launcher = wss.prepare(source, source_sha256=hashlib.sha256(source).hexdigest(),
                                   ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(), identity_sha256="c" * 64).decode()
            health = launcher.split("function Test-LocalHealth {\n", 1)[1].split("\n}\n", 1)[0]
            powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            parse = ("$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput("
                     "[Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors);if($errors.Count){exit 1}")
            parse_encoded = base64.b64encode(parse.encode("utf-16le")).decode("ascii")
            parsed = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                     "-EncodedCommand", parse_encoded], input=launcher.encode(), capture_output=True,
                                    timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(parsed.returncode, 0, "composed launcher does not parse in PowerShell 5.1")

            def run_health(port):
                script = ("$STATE_PATH=Join-Path $env:H454_WSS_TEST_DIR 'state.json';"
                          f"$PORT={port}\nfunction Test-LocalHealth {{\n{health}\n}}\n"
                          "if(Test-LocalHealth){exit 0}else{exit 1}")
                encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
                return subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                       "-EncodedCommand", encoded], env=dict(os.environ, H454_WSS_TEST_DIR=str(root)),
                                      capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)

            server = ("const fs=require('node:fs'),https=require('node:https');"
                      "const s=https.createServer({cert:fs.readFileSync(process.argv[1]),"
                      "key:fs.readFileSync(process.argv[2])},(_,r)=>{r.writeHead(404);r.end()});"
                      "s.on('tlsClientError',()=>{});s.on('error',e=>{console.error(e.code);process.exitCode=1});"
                      "s.listen(0,'127.0.0.1',()=>console.log('PORT='+s.address().port))")
            for cert, expected in (("trusted", 0), ("fake", 1), ("wrong", 1)):
                with self.subTest(cert=cert):
                    process = subprocess.Popen([node, "-e", server, str(root / f"{cert}.crt"),
                                                str(root / f"{cert}.key")],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               creationflags=subprocess.CREATE_NO_WINDOW)
                    ready = queue.Queue(maxsize=1)
                    reader = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
                    reader.start()
                    try:
                        try:
                            message = ready.get(timeout=15).decode("ascii", errors="replace").strip()
                        except queue.Empty:
                            self.fail("synthetic server did not report its bound port")
                        if not message and process.poll() is not None:
                            self.fail("synthetic server exited: " + process.stderr.read(1024).decode(errors="replace"))
                        self.assertRegex(message, r"^PORT=[0-9]{1,5}$")
                        port = int(message.removeprefix("PORT="))
                        self.assertTrue(0 < port < 65536 and process.poll() is None)
                        result = run_health(port)
                        self.assertEqual(result.returncode, expected, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
                        if cert == "trusted":
                            ca.write_bytes((root / "fake.crt").read_bytes())
                            self.assertEqual(run_health(port).returncode, 1, "changed CA must fail closed")
                            ca.unlink()
                            self.assertEqual(run_health(port).returncode, 1, "missing CA must fail closed")
                            shutil.copyfile(root / "ca.crt", ca)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        process.wait(timeout=5)
                        reader.join(timeout=5)
                        process.stdout.close()
                        process.stderr.close()

    if sys.platform == "win32" and os.getenv("H454_WINDOWS_WSS_HEALTH") == "1":
        test_windows_tls_health_checks_synthetic_certificates = _assert_windows_tls_health_checks_synthetic_certificates


if __name__ == "__main__":
    unittest.main()
