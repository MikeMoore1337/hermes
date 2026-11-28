import json
import os
from pathlib import Path
import tempfile
import unittest

from device_fabric.windows_personal_project_hot_registration import WindowsProjectRegistration, commit_config


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.current = b'old-config'
        self.prepared = b'new-config'
        self.calls = []
        self.busy = False
        def prepare(raw, path):
            self.calls.append(('prepare', raw, path))
            return self.prepared
        def validate(raw):
            self.calls.append(('validate', raw))
        def commit(old, new):
            self.calls.append(('commit', old, new))
            self.current = new
            return 'project-registration-' + 'a' * 32
        self.commit = commit
        self.broker = WindowsProjectRegistration(self.current, prepare=prepare, validate=validate,
            commit=lambda old, new: self.commit(old, new), read_current=lambda: self.current,
            has_sessions=lambda: self.busy)

    def call(self, mode):
        result = self.broker.dispatch({'path': r'D:\Pet-projects\example', 'mode': mode})
        return result, json.loads(result['content'][0]['text'])

    def test_plan_validates_without_committing_or_requesting_reload(self):
        result, body = self.call('plan')
        self.assertFalse(result['isError'])
        self.assertEqual(body['status'], 'plan_pass')
        self.assertEqual(self.current, b'old-config')
        self.assertFalse(self.broker.reload_pending())
        self.assertNotIn('commit', [call[0] for call in self.calls])

    def test_execute_commits_once_and_requires_reload(self):
        result, body = self.call('execute')
        self.assertFalse(result['isError'])
        self.assertEqual(body['status'], 'applied')
        self.assertTrue(body['verification_required'])
        self.assertEqual(self.current, self.prepared)
        self.assertTrue(self.broker.reload_pending())
        self.assertEqual(self.call('execute')[1]['status'], 'refused')
        self.assertEqual(sum(call[0] == 'commit' for call in self.calls), 1)

    def test_active_session_prevents_changing_configuration(self):
        self.busy = True
        self.assertEqual(self.call('execute')[1]['reason'], 'active_sessions')
        self.assertEqual(self.current, b'old-config')
        self.assertFalse(self.broker.reload_pending())

    def test_lost_commit_response_is_unknown_and_still_requests_reload(self):
        def changed_then_failed(old, new):
            self.current = new
            raise OSError()
        self.commit = changed_then_failed
        result, body = self.call('execute')
        self.assertTrue(result['isError'])
        self.assertEqual(body, {'status': 'unknown', 'reason': 'operation_unconfirmed_do_not_retry'})
        self.assertTrue(self.broker.reload_pending())

    def test_configuration_drift_is_refused_before_validation(self):
        self.current = b'external-config'
        self.assertEqual(self.call('execute')[1]['reason'], 'configuration_changed')
        self.assertEqual(self.calls, [])

    def _real_private_backup_and_compare_before_replace(self):
        from scripts.h454_windows_personal_worker import current_sid
        with tempfile.TemporaryDirectory(prefix='h454-hot-registration-') as folder:
            private = Path(folder).resolve()
            path = private / 'device.json'
            path.write_bytes(b'old')
            backup = commit_config(private, current_sid(), b'old', b'new')
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual((private / backup / 'old-device.json').read_bytes(), b'old')
            self.assertEqual((private / backup / 'new-device.json').read_bytes(), b'new')
            self.assertFalse((private / 'project-registration.lock').exists())
            with self.assertRaises(ValueError):
                commit_config(private, current_sid(), b'old', b'another')
            self.assertEqual(path.read_bytes(), b'new')


if os.name == 'nt':
    RegistrationTests.test_real_private_backup_and_compare_before_replace = (
        RegistrationTests._real_private_backup_and_compare_before_replace)

if __name__ == '__main__':
    unittest.main()
