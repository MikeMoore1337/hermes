"""Build only settings tied to an exact original and guarded launcher."""
import hashlib
import json
import unittest

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import ANCHOR, patch_launcher_bytes
from scripts.h454_windows_wss_config import build


def digest(value):
    return hashlib.sha256(value).hexdigest()


def original(newline='\n'):
    text = ("$HOST_ADDR = 'relay.example.test'\n$RELAY = '172.29.1.2:3000'\n$SSH_PORT = 2222\n"
            '$TUNNEL_TARGET = "fixture@$HOST_ADDR"\n' + ANCHOR + 'end\n')
    return b'\xef\xbb\xbf' + text.replace('\n', newline).encode()


def prepare(source):
    guarded = patch_launcher_bytes(source, digest(source))
    kwargs = dict(original_sha256=digest(source), guarded_sha256=digest(guarded),
                  ca_sha256='a' * 64, identity_sha256='b' * 64, node_sha256='c' * 64, public_key_sha256='d' * 64)
    return guarded, kwargs


class WssConfigTests(unittest.TestCase):
    def test_pinned_source_yields_deterministic_supervisor_settings(self):
        for newline in ('\n', '\r\n'):
            source = original(newline)
            guarded, kwargs = prepare(source)
            result = build(source, guarded, **kwargs)
            settings = json.loads(result)
            self.assertEqual(result, build(source, guarded, **kwargs))
            self.assertEqual((settings['sshHost'], settings['sshUser'], settings['sshPort'], settings['relayAddress']),
                             ('relay.example.test', 'fixture', 2222, '172.29.1.2'))
            self.assertEqual(settings['launcherSha256'], digest(guarded).upper())
            self.assertEqual(settings['caSha256'], 'A' * 64)
            self.assertEqual(set(settings), {'version', 'sshHost', 'sshUser', 'sshPort', 'relayAddress', 'caSha256',
                                             'identitySha256', 'launcherSha256', 'nodeSha256', 'publicKeySha256'})

    def test_drift_and_unsafe_endpoints_fail_closed(self):
        source = original()
        guarded, kwargs = prepare(source)
        for changed, options in ((guarded + b'x', kwargs), (guarded, dict(kwargs, ca_sha256='bad')),
                                 (guarded, dict(kwargs, original_sha256='0' * 64))):
            with self.subTest(options=options), self.assertRaises(AuditError):
                build(source, changed, **options)
        for old, new in ((b'172.29.1.2:3000', b'8.8.8.8:3000'), (b'172.29.1.2:3000', b'127.0.0.1:3000'),
                         (b'SSH_PORT = 2222', b'SSH_PORT = 0'), (b'fixture@$HOST_ADDR', b'fixture@other.example'),
                         (b"$HOST_ADDR = 'relay.example.test'", b"$HOST_ADDR = 'relay.example.test'\n$HOST_ADDR = 'duplicate'")):
            altered = source.replace(old, new)
            self.assertNotEqual(altered, source)
            altered_guarded, altered_kwargs = prepare(altered)
            with self.subTest(old=old), self.assertRaises(AuditError):
                build(altered, altered_guarded, **altered_kwargs)


if __name__ == '__main__':
    unittest.main()
