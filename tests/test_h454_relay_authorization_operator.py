import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from unittest import mock

from scripts import h454_relay_authorization_operator as subject
from scripts import h454_relay_second_authorized_key as key_slot


def key(value):
    blob = b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes([value]) * 32
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode()


if os.name == 'posix' and os.geteuid() == 0:
    class RelayAuthorizationOperatorTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix='h454-auth-operator-')
            self.root = Path(self.temp.name)
            self.parent = self.root / 'varlib'
            self.parent.mkdir(mode=0o700)
            self.home = self.root / 'home'
            self.home.mkdir(mode=0o700)
            self.ssh = self.home / '.ssh'
            self.ssh.mkdir(mode=0o700)
            os.chown(self.home, 65534, 65534)
            os.chown(self.ssh, 65534, 65534)
            self.original = self.ssh / 'authorized_keys'
            self.original.write_text('restrict,port-forwarding ' + key(1) + '\n', encoding='ascii')
            self.original.chmod(0o600)
            os.chown(self.original, 65534, 65534)
            self.original_bytes = self.original.read_bytes()
            self.registry = self.parent / subject.REGISTRY_NAME
            self.user = SimpleNamespace(pw_uid=65534, pw_gid=65534, pw_dir=str(self.home))
            self.relay = {'Name': '/hermes-brc-relay', 'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
                          'State': {'Running': True}, 'NetworkSettings': {'Networks': {
                              'hermes-brc-internal': {'IPAddress': '172.20.0.2', 'NetworkID': 'c' * 64}}}}
            self.settings = ('authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n'
                             'authorizedkeyscommand none\nusedns no\nstrictmodes yes\n'
                             'allowtcpforwarding local\npermitopen any\n').encode()
            self.parent_patch = mock.patch.object(subject, 'REGISTRY_PARENT', self.parent)
            self.user_patch = mock.patch.object(subject.pwd, 'getpwnam', return_value=self.user)
            self.run_patch = mock.patch.object(subject, '_run', side_effect=self.command)
            self.env_patch = mock.patch.dict(os.environ, {'SSH_CONNECTION': '192.0.2.10 1111 192.0.2.11 22'})
            for patch in (self.parent_patch, self.user_patch, self.run_patch, self.env_patch):
                patch.start()

        def tearDown(self):
            for patch in (self.env_patch, self.run_patch, self.user_patch, self.parent_patch):
                patch.stop()
            self.temp.cleanup()

        def command(self, arguments, _limit):
            if arguments[0] == '/usr/bin/docker':
                return json.dumps([self.relay]).encode()
            if arguments[0] == '/usr/sbin/sshd':
                return self.settings
            raise AssertionError('unexpected command')

        def prepare(self):
            return subject.prepare('brc_fixture', key(2) + ' fixture')

        def test_prepare_install_and_revoke_are_bounded_and_idempotent(self):
            pin = self.prepare()
            self.assertEqual(self.prepare(), pin)
            self.assertFalse((self.ssh / 'authorized_keys2').exists())
            self.assertEqual(self.registry.stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.registry / 'request.json').stat().st_mode & 0o777, 0o600)
            subject.install(pin)
            subject.install(pin)
            target = self.ssh / 'authorized_keys2'
            self.assertIn(b'permitopen="172.20.0.2:3001"', target.read_bytes())
            self.assertNotIn(b':3000', target.read_bytes())
            self.assertEqual(self.original.read_bytes(), self.original_bytes)
            subject.revoke(pin)
            subject.revoke(pin)
            self.assertEqual(target.read_bytes(), b'')
            with self.assertRaises(ValueError):
                subject.install(pin)
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_changed_relay_or_sshd_policy_refuses_install(self):
            pin = self.prepare()
            self.relay['Id'] = 'd' * 64
            with self.assertRaises(subject.Hold):
                subject.install(pin)
            self.assertFalse((self.ssh / 'authorized_keys2').exists())
            self.relay['Id'] = 'a' * 64
            self.settings = self.settings.replace(b'authorizedkeyscommand none', b'authorizedkeyscommand /tmp/other')
            with self.assertRaises(subject.Hold):
                subject.install(pin)
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_occupied_second_file_is_never_replaced(self):
            pin = self.prepare()
            target = self.ssh / 'authorized_keys2'
            target.write_bytes(b'foreign')
            with self.assertRaises(key_slot.SecondKeyHold):
                subject.install(pin)
            self.assertEqual(target.read_bytes(), b'foreign')
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_foreign_registry_contents_are_untouched(self):
            self.registry.mkdir(mode=0o700)
            foreign = self.registry / 'foreign'
            foreign.write_bytes(b'foreign')
            with self.assertRaises(subject.Hold):
                self.prepare()
            self.assertEqual(foreign.read_bytes(), b'foreign')
            self.assertFalse((self.registry / 'operator.lock').exists())

        def test_oversized_registry_is_refused_before_writes(self):
            self.registry.mkdir(mode=0o700)
            for index in range(513):
                (self.registry / ('entry-' + str(index))).touch()
            with self.assertRaises(subject.Hold):
                self.prepare()
            self.assertEqual(len(list(self.registry.iterdir())), 513)
            self.assertFalse((self.registry / 'operator.lock').exists())

        def test_receipt_failure_revokes_the_installed_inode(self):
            pin = self.prepare()
            original_write = subject._write_once

            def fail_receipt(registry, name, data):
                if name == 'receipt.json':
                    raise OSError('synthetic receipt failure')
                return original_write(registry, name, data)

            with mock.patch.object(subject, '_write_once', side_effect=fail_receipt):
                with self.assertRaises(subject.Hold):
                    subject.install(pin)
            self.assertEqual((self.ssh / 'authorized_keys2').read_bytes(), b'')
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_drift_after_publication_revokes_the_key(self):
            pin = self.prepare()
            real_snapshot = subject.snapshot
            calls = []

            def changed_snapshot(*args):
                value = real_snapshot(*args)
                calls.append(True)
                if len(calls) == 2:
                    value['relay_id'] = 'd' * 64
                return value

            with mock.patch.object(subject, 'snapshot', side_effect=changed_snapshot):
                with self.assertRaises(subject.Hold):
                    subject.install(pin)
            self.assertEqual((self.ssh / 'authorized_keys2').read_bytes(), b'')
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_unsettled_failure_can_be_revoked_without_receipt(self):
            pin = self.prepare()
            original_write = subject._write_once

            def fail_receipt(registry, name, data):
                if name == 'receipt.json':
                    raise OSError('synthetic receipt failure')
                return original_write(registry, name, data)

            with mock.patch.object(subject, '_write_once', side_effect=fail_receipt), \
                 mock.patch.object(key_slot, 'revoke', side_effect=OSError('synthetic failure')):
                with self.assertRaises(subject.Unsettled):
                    subject.install(pin)
            self.assertIn(key(2).encode(), (self.ssh / 'authorized_keys2').read_bytes())
            self.assertFalse((self.registry / 'receipt.json').exists())
            subject.revoke(pin)
            self.assertEqual((self.ssh / 'authorized_keys2').read_bytes(), b'')
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_interruption_after_link_can_finish_receipt(self):
            pin = self.prepare()
            request = json.loads((self.registry / 'request.json').read_bytes())
            registry_fd = os.open(self.registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            ssh_fd = os.open(self.ssh, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                key_slot.install(registry_fd, ssh_fd, uid=65534, original_sha256=request['original_sha256'],
                                 public_key=request['public_key'], relay_ip=request['relay_ip'])
            finally:
                os.close(ssh_fd)
                os.close(registry_fd)
            self.assertFalse((self.registry / 'receipt.json').exists())
            subject.install(pin)
            self.assertTrue((self.registry / 'receipt.json').exists())
            subject.revoke(pin)

        def test_interrupted_record_link_is_reconciled_but_foreign_link_is_not_removed(self):
            pin = self.prepare()
            request = self.registry / 'request.json'
            pending = self.registry / ('.h454-' + 'a' * 32)
            os.link(request, pending)
            self.assertEqual(self.prepare(), pin)
            self.assertFalse(pending.exists())
            foreign = self.registry / 'foreign'
            os.link(request, foreign)
            with self.assertRaises(subject.Hold):
                self.prepare()
            self.assertTrue(foreign.exists())
            self.assertEqual(hashlib.sha256(request.read_bytes()).hexdigest(), pin)

        def test_wrong_pin_never_installs(self):
            self.prepare()
            with self.assertRaises(subject.Hold):
                subject.install('0' * 64)
            self.assertFalse((self.ssh / 'authorized_keys2').exists())

        def test_changed_receipt_holds_without_revoking_existing_key(self):
            pin = self.prepare()
            subject.install(pin)
            target = self.ssh / 'authorized_keys2'
            before = target.read_bytes()
            (self.registry / 'receipt.json').write_bytes(b'foreign')
            with self.assertRaises(subject.Hold):
                subject.install(pin)
            self.assertEqual(target.read_bytes(), before)

        def test_concurrent_operator_holds_before_publication(self):
            pin = self.prepare()
            fd = os.open(self.registry / 'operator.lock', os.O_RDWR | os.O_NOFOLLOW)
            try:
                subject.fcntl.flock(fd, subject.fcntl.LOCK_EX | subject.fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    subject.install(pin)
            finally:
                os.close(fd)
            self.assertFalse((self.ssh / 'authorized_keys2').exists())

        def test_revoke_before_install_refuses_foreign_target(self):
            pin = self.prepare()
            self.assertEqual(subject.revoke(pin), 'ABSENT')
            target = self.ssh / 'authorized_keys2'
            target.write_bytes(b'foreign')
            with self.assertRaises(subject.Hold):
                subject.revoke(pin)
            self.assertEqual(target.read_bytes(), b'foreign')

        def test_duplicate_cli_input_is_refused_before_creating_registry(self):
            body = b'{"account":"first","account":"second","public_key":"ignored"}'
            stdin = SimpleNamespace(buffer=io.BytesIO(body))
            output = io.StringIO()
            with mock.patch.object(subject.sys, 'argv', ['operator', 'prepare']), \
                 mock.patch.object(subject.sys, 'stdin', stdin), redirect_stdout(output):
                self.assertEqual(subject.main(), 2)
            self.assertEqual(output.getvalue(), 'H454_RELAY_AUTHORIZATION=HOLD\n')
            self.assertFalse(self.registry.exists())

        def test_cli_requires_approval_and_runs_real_install_and_revoke(self):
            def call(arguments, body=b''):
                output = io.StringIO()
                with mock.patch.object(subject.sys, 'argv', ['operator', *arguments]), \
                     mock.patch.object(subject.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(body))), redirect_stdout(output):
                    code = subject.main()
                return code, output.getvalue()

            code, output = call(['prepare'], json.dumps({'account': 'brc_fixture', 'public_key': key(2)}).encode())
            self.assertEqual(code, 0)
            prefix = 'H454_RELAY_REQUEST_SHA256='
            self.assertTrue(output.startswith(prefix))
            pin = output[len(prefix):].strip()
            self.assertRegex(pin, r'^[a-f0-9]{64}$')
            self.assertEqual(call(['install', '--request-sha256', pin])[0], 2)
            self.assertFalse((self.ssh / 'authorized_keys2').exists())
            self.assertEqual(call(['install', '--request-sha256', pin, '--owner-approved'])[0], 0)
            code, output = call(['revoke', '--request-sha256', pin, '--owner-approved'])
            self.assertEqual(code, 0)
            self.assertIn('H454_RELAY_KEY_SLOT=EMPTY', output)
            self.assertIn('H454_EXISTING_SESSIONS=NOT_TERMINATED', output)
            self.assertEqual((self.ssh / 'authorized_keys2').read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
