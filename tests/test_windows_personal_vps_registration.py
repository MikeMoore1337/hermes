"""The personal broker forwards only one bounded, owner-approved operation."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from device_fabric import windows_personal_vps_registration as registration


class VpsRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.run = Mock()
        self.broker = registration.VpsProjectRegistration(
            {'hermes-vps': 'host-a', 'yfc-vps': 'host-b'}, b'print("fixed")',
            ssh=r'C:\Windows\System32\OpenSSH\ssh.exe', run=self.run)
        self.args = {'target': 'yfc-vps', 'name': 'demo', 'path': '/opt/example-project', 'mode': 'plan'}

    def result(self, **updates):
        return type('Result', (), {'returncode': updates.get('returncode', 0),
                                   'stdout': updates.get('stdout', b'H454_LINUX_PROJECT=PLAN_PASS\n'),
                                   'stderr': updates.get('stderr', b'')})()

    @staticmethod
    def value(result):
        return json.loads(result['content'][0]['text'])

    def test_plan_sends_arguments_on_stdin_and_never_in_remote_command(self):
        self.run.return_value = self.result()
        result = self.broker.dispatch(self.args)
        self.assertEqual(self.value(result), {'status': 'plan_pass'})
        command = self.run.call_args.args[0]
        self.assertEqual(command[-2], 'host-b')
        self.assertNotIn(self.args['path'], command[-1])
        self.assertNotIn(self.args['name'], command[-1])
        self.assertEqual(json.loads(self.run.call_args.kwargs['input']), self.args)
        self.assertFalse(self.run.call_args.kwargs.get('shell', False))

    def test_execute_reports_backup_but_requires_live_verification(self):
        backup = 'project-registration-' + 'a' * 32
        self.run.return_value = self.result(stdout=('H454_LINUX_PROJECT=TASK_STARTED '
            'REMOTE_ACCESS=NOT_VERIFIED BACKUP=' + backup).encode())
        result = self.value(self.broker.dispatch({**self.args, 'mode': 'execute'}))
        self.assertEqual(result, {'status': 'applied', 'backup': backup, 'verification_required': True})

    def test_invalid_scope_never_launches_ssh(self):
        for changes in ({'target': 'other'}, {'name': '../escape'}, {'path': '/etc'},
                        {'path': '/srv/second-brain/second-brain-vault'},
                        {'path': '/opt/example/../private'}, {'path': '/tmp/example'},
                        {'mode': 'remove'}, {'extra': 'x'}):
            with self.subTest(changes=changes):
                self.assertEqual(self.value(self.broker.dispatch({**self.args, **changes}))['status'], 'refused')
        self.run.assert_not_called()

    def test_interrupted_connection_is_unknown_and_never_retried(self):
        self.run.side_effect = subprocess.TimeoutExpired('ssh', 90)
        result = self.broker.dispatch({**self.args, 'mode': 'execute'})
        self.assertEqual(self.value(result), {'status': 'unknown', 'reason': 'connection_interrupted'})
        self.assertTrue(result['isError'])
        self.run.assert_called_once()

    def test_ssh_exit_255_is_ambiguous_and_not_a_safe_retry(self):
        self.run.return_value = self.result(returncode=255, stdout=b'', stderr=b'connection failed')
        result = self.broker.dispatch({**self.args, 'mode': 'execute'})
        self.assertEqual(self.value(result), {'status': 'unknown', 'reason': 'connection_interrupted'})
        self.run.assert_called_once()

    def test_rollback_failure_is_distinguished_and_output_is_redacted(self):
        self.run.return_value = self.result(returncode=2, stdout=b'',
                                            stderr=b'H454_LINUX_PROJECT=HOLD ROLLBACK=FAILED\nsecret')
        value = self.value(self.broker.dispatch({**self.args, 'mode': 'execute'}))
        self.assertEqual(value, {'status': 'failed', 'reason': 'rollback_failed'})
        self.assertNotIn('secret', repr(value))

    def test_host_alias_and_ssh_executable_are_fixed_at_construction(self):
        for aliases, ssh in (({'hermes-vps': 'host a', 'yfc-vps': 'host-b'}, r'C:\Windows\System32\OpenSSH\ssh.exe'),
                             ({'hermes-vps': 'host-a', 'yfc-vps': 'host-a'}, r'C:\Windows\System32\OpenSSH\ssh.exe'),
                             ({'hermes-vps': 'host-a', 'yfc-vps': 'host-b'}, r'C:\temp\evil.exe')):
            with self.subTest(aliases=aliases, ssh=ssh), self.assertRaises(ValueError):
                registration.VpsProjectRegistration(aliases, b'pass', ssh=ssh, run=self.run)

    def test_owner_local_config_is_optional_and_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, release = root / 'private', root / 'release'
            self.assertIsNone(registration.from_owner_state(private, release, system_root=r'C:\Windows'))
            private.mkdir()
            source = release / 'code' / 'device_fabric' / 'linux_personal_remote_operator.py'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'pass')
            config = private / 'vps-registration.json'
            config.write_text('{"schema":"h454-vps-registration-v1","aliases":{"hermes-vps":"host-a","yfc-vps":"host-b"}}', encoding='ascii')
            with patch('device_fabric.windows_personal_yfc_psec._real_directory'):
                broker = registration.from_owner_state(private, release, system_root=r'C:\Windows')
                self.assertIsInstance(broker, registration.VpsProjectRegistration)
                config.write_text('{"schema":"h454-vps-registration-v1","schema":"other","aliases":{}}', encoding='ascii')
                with self.assertRaises(ValueError):
                    registration.from_owner_state(private, release, system_root=r'C:\Windows')


if __name__ == '__main__':
    unittest.main()
