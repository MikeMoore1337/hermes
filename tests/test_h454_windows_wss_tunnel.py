import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import h454_windows_wss_tunnel as subject
from scripts.h454_windows_launcher_guard import ANCHOR, patch_launcher_bytes
from scripts.h454_windows_wss_config import build as build_config
from scripts.h454_windows_wss_launcher import JOB_GUARD


class WssTunnelTests(unittest.TestCase):
    def test_build_uses_existing_owned_process_guard(self):
        result = subject.build().decode('utf8')
        self.assertEqual(result.count(JOB_GUARD), 1)
        self.assertIn('Initialize-H454TunnelJob $PSCommandPath', result)
        self.assertIn("'-o','ServerAliveInterval=10'", result)
        self.assertIn("'-o','ServerAliveCountMax=2'", result)
        self.assertIn('& $powershell -WindowStyle Hidden -NoProfile -NonInteractive', result)
        self.assertIn('& $ssh @sshArgs 1>$null 2>$null', result)
        self.assertIn('while($true){\ntry {', result)
        self.assertIn("'H454_WSS_TUNNEL=DISCONNECTED'", result)
        self.assertIn('Start-Sleep -Seconds 10\n}', result)
        self.assertNotIn('deviceToken', result)

    def test_preflight_exits_only_after_pins_and_before_starting_a_child(self):
        result = subject.build().decode('utf8')
        preflight = result.index("if($Preflight){'H454_WSS_TUNNEL_PREFLIGHT=PASS';exit 0}")
        self.assertLess(result.index("'H454_TUNNEL_LAUNCHER_DRIFT'"), preflight)
        self.assertLess(result.index('Assert-H454File $ca $settings.caSha256'), preflight)
        self.assertLess(preflight, result.index('Initialize-H454TunnelJob $PSCommandPath'))

    def test_changed_source_guard_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='h454-source-') as temporary:
            source = Path(temporary) / 'supervisor.ps1'
            for content in (b'#requires -Version 5.1\nno guard\n', subject.build().replace(b'\n', b'\r\n')):
                source.write_bytes(content)
                with mock.patch.object(subject, 'SOURCE', source):
                    with self.assertRaisesRegex(ValueError, 'source drift'):
                        subject.build()

    if os.name != 'nt':
        def test_linked_supervisor_source_is_refused(self):
            with tempfile.TemporaryDirectory(prefix='h454-source-') as temporary:
                link = Path(temporary) / 'supervisor.ps1'
                link.symlink_to(subject.SOURCE)
                with mock.patch.object(subject, 'SOURCE', link):
                    with self.assertRaisesRegex(ValueError, 'source drift'):
                        subject.build()

    if os.name == 'nt':
        def test_windows_generated_validation_refuses_drift(self):
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            fixture = Path(__file__).with_name('h454_windows_wss_tunnel_fixture.ps1')
            with tempfile.TemporaryDirectory(prefix='h454-tunnel-test-') as temporary:
                source = Path(temporary) / 'supervisor.ps1'
                source.write_bytes(subject.build())
                legacy = ("$HOST_ADDR = 'relay.example.test'\n$RELAY = '172.29.1.2:3000'\n$SSH_PORT = 2222\n"
                          '$TUNNEL_TARGET = "fixture@$HOST_ADDR"\n' + ANCHOR).encode()
                old_hash = hashlib.sha256(legacy).hexdigest()
                guarded = patch_launcher_bytes(legacy, old_hash)
                config = Path(temporary) / 'generated.json'
                config.write_bytes(build_config(legacy, guarded, original_sha256=old_hash,
                                                guarded_sha256=hashlib.sha256(guarded).hexdigest(),
                                                ca_sha256='A' * 64, identity_sha256='B' * 64,
                                                node_sha256='D' * 64, public_key_sha256='E' * 64))
                result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                         '-File', str(fixture), '-Source', str(source), '-FixtureParent', temporary,
                                         '-GeneratedConfig', str(config)],
                                        capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('H454_WSS_TUNNEL_FIXTURE=PASS', result.stdout)
                child_env = os.environ.copy()
                for name in ('SSH_AUTH_SOCK', 'NODE_OPTIONS', 'NODE_PATH'):
                    child_env.pop(name, None)
                refused = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                          '-File', str(source), '-ConfigSha256', 'A' * 64, '-Preflight'],
                                         capture_output=True, text=True, timeout=10, env=child_env,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                self.assertIn('H454_TUNNEL_REASON=H454_TUNNEL_STATE', refused.stdout)


if __name__ == '__main__':
    unittest.main()
