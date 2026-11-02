import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import h454_windows_wss_tunnel as subject
from scripts.h454_windows_wss_launcher import JOB_GUARD


class WssTunnelTests(unittest.TestCase):
    def test_build_uses_existing_owned_process_guard(self):
        result = subject.build().decode('utf8')
        self.assertEqual(result.count(JOB_GUARD), 1)
        self.assertIn('Initialize-H454TunnelJob $PSCommandPath', result)
        self.assertIn("'-o','ServerAliveInterval=10'", result)
        self.assertIn("'-o','ServerAliveCountMax=2'", result)
        self.assertIn('& $ssh @sshArgs 1>$null 2>$null', result)
        self.assertIn('while($true){\ntry {', result)
        self.assertIn("'H454_WSS_TUNNEL=DISCONNECTED'", result)
        self.assertIn('Start-Sleep -Seconds 10\n}', result)
        self.assertNotIn('deviceToken', result)

    def test_changed_template_anchor_is_refused(self):
        with mock.patch.object(subject, 'TEMPLATE', 'no guard anchor'):
            with self.assertRaisesRegex(ValueError, 'template drift'):
                subject.build()

    if os.name == 'nt':
        def test_windows_generated_validation_refuses_drift(self):
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            fixture = Path(__file__).with_name('h454_windows_wss_tunnel_fixture.ps1')
            with tempfile.TemporaryDirectory(prefix='h454-tunnel-test-') as temporary:
                source = Path(temporary) / 'supervisor.ps1'
                source.write_bytes(subject.build())
                result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                         '-File', str(fixture), '-Source', str(source), '-FixtureParent', temporary],
                                        capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('H454_WSS_TUNNEL_FIXTURE=PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
