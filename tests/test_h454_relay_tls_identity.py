import os
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from scripts import h454_relay_tls_identity as subject


if os.name == 'posix' and os.geteuid() == 0 and Path('/usr/bin/openssl').is_file():
    class RelayTlsIdentityTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix='h454-tls-operator-')
            self.parent = Path(self.temp.name)
            self.patch = mock.patch.object(subject, 'PARENT', self.parent)
            self.patch.start()

        def tearDown(self):
            self.patch.stop()
            self.temp.cleanup()

        def test_prepare_generates_verifiable_bounded_private_identity(self):
            result = subject.prepare()
            directory = self.parent / subject.NAME
            self.assertEqual(subject.verify(directory), result)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / 'ca.key').stat().st_mode & 0o777, 0o600)
            self.assertEqual((directory / 'relay.key').stat().st_mode & 0o777, 0o440)
            self.assertEqual((directory / 'relay.key').stat().st_gid, 65534)
            self.assertEqual(set(path.name for path in directory.iterdir()), subject.FILES)
            with self.assertRaises(subject.Hold):
                subject.prepare()
            self.assertEqual(subject.verify(directory), result)

        def test_occupied_target_and_symlink_are_never_replaced(self):
            foreign = self.parent / 'foreign'
            foreign.mkdir()
            sentinel = foreign / 'sentinel'
            sentinel.write_text('keep', encoding='ascii')
            (self.parent / subject.NAME).symlink_to(foreign, target_is_directory=True)
            with self.assertRaises(subject.Hold):
                subject.prepare()
            self.assertEqual(sentinel.read_text(encoding='ascii'), 'keep')

        def test_interrupted_staging_is_preserved_and_blocks_new_identity(self):
            stale = self.parent / ('.h454-tls-' + 'a' * 32)
            stale.mkdir(mode=0o700)
            sentinel = stale / 'ca.key'
            sentinel.write_bytes(b'synthetic unfinished key')
            with self.assertRaisesRegex(subject.Hold, 'TLS_STAGING_PENDING'):
                subject.prepare()
            self.assertEqual(sentinel.read_bytes(), b'synthetic unfinished key')
            self.assertFalse((self.parent / subject.NAME).exists())

        def test_cli_requires_approval_and_sanitizes_unexpected_failure(self):
            output = io.StringIO()
            with mock.patch.object(sys, 'argv', ['operator', 'prepare']), redirect_stdout(output):
                self.assertEqual(subject.main(), 2)
            self.assertIn('H454_REASON=APPROVAL', output.getvalue())
            self.assertEqual(list(self.parent.iterdir()), [])
            output = io.StringIO()
            with mock.patch.object(sys, 'argv', ['operator', 'prepare', '--owner-approved']), \
                 mock.patch.object(subject, 'prepare', side_effect=RuntimeError('private server detail')), redirect_stdout(output):
                self.assertEqual(subject.main(), 2)
            self.assertEqual(output.getvalue(),
                             'H454_RELAY_TLS_IDENTITY=HOLD\nH454_TLS_STATE=INSPECT_BEFORE_RETRY\n')

        def test_generation_failure_removes_only_owned_staging(self):
            sentinel = self.parent / 'unrelated'
            sentinel.write_text('keep', encoding='ascii')
            original = subject._openssl
            calls = []

            def fail_second(*args, **kwargs):
                calls.append(True)
                if len(calls) == 2:
                    raise subprocess.CalledProcessError(1, 'synthetic')
                return original(*args, **kwargs)

            with mock.patch.object(subject, '_openssl', side_effect=fail_second):
                with self.assertRaises(subprocess.CalledProcessError):
                    subject.prepare()
            self.assertEqual(sentinel.read_text(encoding='ascii'), 'keep')
            self.assertEqual(set(path.name for path in self.parent.iterdir()), {'unrelated'})

        def test_unknown_staging_file_is_preserved_on_failure(self):
            def foreign_file(directory, *_args, **_kwargs):
                (directory / 'foreign').write_text('keep', encoding='ascii')
                raise subprocess.CalledProcessError(1, 'synthetic')

            with mock.patch.object(subject, '_openssl', side_effect=foreign_file):
                with self.assertRaisesRegex(subject.Hold, 'TLS_STAGING_DRIFT'):
                    subject.prepare()
            entries = list(self.parent.iterdir())
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0].name.startswith('.h454-tls-'))
            self.assertEqual((entries[0] / 'foreign').read_text(encoding='ascii'), 'keep')

        def test_concurrent_target_is_preserved(self):
            original = subject._rename_no_replace

            def occupied(parent, source, destination):
                os.mkdir(destination, 0o700, dir_fd=parent)
                with (self.parent / destination / 'foreign').open('x', encoding='ascii') as file:
                    file.write('keep')
                return original(parent, source, destination)

            with mock.patch.object(subject, '_rename_no_replace', side_effect=occupied):
                with self.assertRaises(FileExistsError):
                    subject.prepare()
            self.assertEqual((self.parent / subject.NAME / 'foreign').read_text(encoding='ascii'), 'keep')
            self.assertEqual(set(path.name for path in self.parent.iterdir()), {subject.NAME})

        def test_tampered_certificate_and_private_key_symlink_are_rejected(self):
            subject.prepare()
            directory = self.parent / subject.NAME
            cert = directory / 'relay.crt'
            original = cert.read_bytes()
            cert.chmod(0o600)
            cert.write_bytes(original.replace(b'CERTIFICATE', b'CERTIFICATX'))
            cert.chmod(0o444)
            with self.assertRaises((subject.Hold, subprocess.CalledProcessError)):
                subject.verify(directory)
            cert.chmod(0o600)
            cert.write_bytes(original)
            cert.chmod(0o444)
            outside = self.parent / 'outside'
            outside.write_text('keep', encoding='ascii')
            (directory / 'relay.key').unlink()
            (directory / 'relay.key').symlink_to(outside)
            with self.assertRaises((subject.Hold, OSError)):
                subject.verify(directory)
            self.assertEqual(outside.read_text(encoding='ascii'), 'keep')

        def test_different_private_key_is_rejected(self):
            subject.prepare()
            directory = self.parent / subject.NAME
            subject._openssl(self.parent, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
                                           '-out', 'other.key'])
            other = self.parent / 'other.key'
            os.chown(other, 0, 65534)
            other.chmod(0o440)
            os.replace(other, directory / 'relay.key')
            with self.assertRaisesRegex(subject.Hold, 'TLS_KEY_MISMATCH'):
                subject.verify(directory)

        def test_near_expiry_certificate_is_rejected(self):
            subject.prepare()
            directory = self.parent / subject.NAME
            csr = self.parent / 'short.csr'
            ext = self.parent / 'short.ext'
            cert = self.parent / 'short.crt'
            ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                           'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:brc-agent.internal\n', encoding='ascii')
            subject._openssl(directory, ['req', '-new', '-key', 'relay.key', '-out', str(csr),
                                         '-subj', '/CN=brc-agent.internal'])
            subject._openssl(directory, ['x509', '-req', '-in', str(csr), '-CA', 'ca.crt', '-CAkey', 'ca.key',
                                         '-set_serial', '0x123456', '-out', str(cert), '-days', '1',
                                         '-sha256', '-extfile', str(ext)])
            destination = directory / 'relay.crt'
            destination.chmod(0o600)
            destination.write_bytes(cert.read_bytes())
            destination.chmod(0o444)
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                subject.verify(directory)
            self.assertIn('-checkend', failure.exception.cmd)


if __name__ == '__main__':
    unittest.main()
