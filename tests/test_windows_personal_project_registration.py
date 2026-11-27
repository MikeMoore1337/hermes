"""Synthetic registration and rollback; no host task or credential access."""
import tempfile
import unittest
from pathlib import Path

from device_fabric import windows_personal_project_registration as registration


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = self.root / 'device.json'
        self.config.write_bytes(b'old sealed config')
        self.backup = self.root / 'backup'
        self.backup.mkdir()
        self.old, self.new = b'old sealed config', b'new sealed config'

    def test_registers_with_private_recovery_material(self):
        calls = []
        registration.apply(self.config, self.backup, self.old, self.new,
            stop=lambda: calls.append('stop'), start=lambda: calls.append('start'),
            verify=lambda: calls.append('verify') or True)
        self.assertEqual(self.config.read_bytes(), self.new)
        self.assertEqual((self.backup / 'old-device.json').read_bytes(), self.old)
        self.assertEqual((self.backup / 'new-device.json').read_bytes(), self.new)
        self.assertEqual(calls, ['stop', 'start', 'verify'])

    def test_failed_online_verification_restores_and_restarts(self):
        calls = []
        checks = iter((False, True))
        with self.assertRaisesRegex(registration.RegistrationDenied, 'registration_rolled_back'):
            registration.apply(self.config, self.backup, self.old, self.new,
                stop=lambda: calls.append('stop'), start=lambda: calls.append('start'),
                verify=lambda: next(checks))
        self.assertEqual(self.config.read_bytes(), self.old)
        self.assertEqual(calls, ['stop', 'start', 'stop', 'start'])

    def test_failed_first_start_restores_config_and_restarts_old_task(self):
        attempts = []
        def start():
            attempts.append('start')
            if len(attempts) == 1:
                raise OSError('simulated task failure')
        with self.assertRaisesRegex(registration.RegistrationDenied, 'registration_rolled_back'):
            registration.apply(self.config, self.backup, self.old, self.new,
                stop=lambda: None, start=start, verify=lambda: True)
        self.assertEqual(self.config.read_bytes(), self.old)
        self.assertEqual(attempts, ['start', 'start'])

    def test_failed_recovery_is_not_reported_as_success(self):
        with self.assertRaises(registration.RegistrationRollbackFailed):
            registration.apply(self.config, self.backup, self.old, self.new,
                stop=lambda: None, start=lambda: None, verify=lambda: False)
        self.assertEqual(self.config.read_bytes(), self.old)

    def test_drift_never_overwrites_config_or_stops_task(self):
        calls = []
        self.config.write_bytes(b'unrelated')
        with self.assertRaises(registration.RegistrationDenied):
            registration.apply(self.config, self.backup, self.old, self.new,
                stop=lambda: calls.append('stop'), start=lambda: calls.append('start'), verify=lambda: True)
        self.assertEqual(self.config.read_bytes(), b'unrelated')
        self.assertEqual(calls, [])

    def test_existing_backup_never_overwritten(self):
        (self.backup / 'old-device.json').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            registration.apply(self.config, self.backup, self.old, self.new,
                stop=lambda: self.fail('unexpected stop'), start=lambda: None, verify=lambda: True)
        self.assertEqual((self.backup / 'old-device.json').read_bytes(), b'keep')
        self.assertEqual(self.config.read_bytes(), self.old)
