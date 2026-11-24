import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'scripts/h454_windows_broker_trial.ps1'
NODE = shutil.which('node')


@unittest.skipUnless(os.name == 'posix' and NODE, 'requires POSIX file modes and Node')
class StageInspectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='h454-stage-')
        self.root = Path(self.tmp.name)
        text = SOURCE.read_text(encoding='utf-8')
        match = re.search(r"\$inspect=@'\s*\n(.*?)\n'@", text, re.S)
        self.assertIsNotNone(match)
        self.script = match.group(1).replace('/run/brc', str(self.root))
        # The real sandbox runs as 65534:65534. Test the same ownership checks
        # as the unprivileged CI user without requiring sudo or Docker.
        self.script = self.script.replace('65534n', f'{os.getuid()}n')
        if os.getuid() != os.getgid():
            self.script = self.script.replace(f's.gid!=={os.getuid()}n', f's.gid!=={os.getgid()}n')
        self.addCleanup(self.tmp.cleanup)

    def inspect(self):
        proc = subprocess.run([NODE, '-e', self.script], capture_output=True, text=True, timeout=10)
        return proc.returncode, proc.stdout

    def write(self, name, value, mode=0o600):
        path = self.root / name
        path.write_text(value, encoding='utf-8')
        path.chmod(mode)

    def complete(self, config, mode=0o600):
        self.write('ready', '')
        self.write('device.json', '{}')
        self.write('config.json', json.dumps(config), mode)

    def test_empty_and_partial_stages(self):
        self.assertEqual((0, 'H454_STAGE_EMPTY'), self.inspect())
        self.write('ready', '')
        self.assertEqual(2, self.inspect()[0])

    def test_initial_and_agent_updated_config(self):
        self.complete({'allowedDirectories': ['/workspace'], 'telemetryEnabled': False})
        self.assertEqual((0, 'H454_STAGE_PRESENT'), self.inspect())
        self.write('config.json', json.dumps({
            'allowedDirectories': ['/workspace'], 'telemetryEnabled': False,
            'pendingWelcomeOnboarding': False, 'welcomeOnboardingEligible': False,
            'usageStats': {'test': 1},
        }), 0o644)
        self.assertEqual((0, 'H454_STAGE_PRESENT'), self.inspect())

    def test_bad_scope_telemetry_extra_keys_and_modes_are_denied(self):
        cases = [
            ({'allowedDirectories': ['/'], 'telemetryEnabled': False}, 0o600),
            ({'allowedDirectories': ['/workspace', '/tmp'], 'telemetryEnabled': False}, 0o600),
            ({'allowedDirectories': ['/workspace'], 'telemetryEnabled': True}, 0o600),
            ({'allowedDirectories': ['/workspace'], 'telemetryEnabled': False, 'unexpected': True}, 0o600),
            ({'allowedDirectories': ['/workspace'], 'telemetryEnabled': False, 'usageStats': []}, 0o600),
            ({'allowedDirectories': ['/workspace'], 'telemetryEnabled': False}, 0o666),
        ]
        for config, mode in cases:
            with self.subTest(config=config, mode=mode):
                self.complete(config, mode)
                self.assertEqual(2, self.inspect()[0])

    def test_symlink_and_hardlink_are_denied(self):
        self.complete({'allowedDirectories': ['/workspace'], 'telemetryEnabled': False})
        config = self.root / 'config.json'
        extra = self.root / 'extra'
        os.link(config, extra)
        self.assertEqual(2, self.inspect()[0])
        extra.unlink()
        config.unlink()
        config.symlink_to(extra)
        self.assertEqual(2, self.inspect()[0])


if __name__ == '__main__':
    unittest.main()
