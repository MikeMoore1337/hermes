"""Prepare only the pinned public inputs and generated supervisor files."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import ANCHOR, patch_launcher_bytes
from scripts.h454_windows_wss_bundle import build, publish


def digest(value):
    return hashlib.sha256(value).hexdigest()


def inputs():
    original = ("$HOST_ADDR = 'relay.example.test'\n$RELAY = '172.29.1.2:3000'\n$SSH_PORT = 2222\n"
                '$TUNNEL_TARGET = "fixture@$HOST_ADDR"\n' + ANCHOR).encode()
    guarded = patch_launcher_bytes(original, digest(original))
    module = b'fixture-module'
    identity = ("$script:h454ModuleHash = '" + digest(module).upper() + "'\n").encode()
    public = b'ssh-ed25519 ' + b'A' * 68 + b' hermes-h454-wss\n'
    ca = b'-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n'
    kwargs = dict(original_sha256=digest(original), guarded_sha256=digest(guarded), identity_sha256=digest(identity),
                  public_key_sha256=digest(public), ca_sha256=digest(ca), node_sha256='D' * 64)
    return [original, guarded, identity, module, public, ca], kwargs


class WssBundleTests(unittest.TestCase):
    def test_bundle_contains_only_expected_files_and_pins(self):
        values, kwargs = inputs()
        bundle = build(*values, **kwargs)
        self.assertEqual(set(bundle), {'h454-wss-identity.ps1', 'h454_windows_wss_identity.mjs',
                                       'wss-relay-ca.pem', 'h454-wss-tunnel.ps1', 'h454-wss-tunnel-config.json'})
        self.assertEqual(bundle['h454-wss-identity.ps1'], values[2])
        self.assertEqual(bundle['h454_windows_wss_identity.mjs'], values[3])
        self.assertEqual(json.loads(bundle['h454-wss-tunnel-config.json'])['launcherSha256'], digest(values[1]).upper())
        self.assertTrue(all(b'brc_dev_' not in value for value in bundle.values()))

    def test_changed_module_public_key_ca_and_launcher_are_refused(self):
        values, kwargs = inputs()
        for index in (1, 2, 3, 4, 5):
            altered = values.copy()
            altered[index] += b'changed'
            with self.subTest(index=index), self.assertRaises(AuditError):
                build(*altered, **kwargs)

    def test_pinned_but_invalid_public_inputs_are_refused(self):
        values, kwargs = inputs()
        for index, key in ((4, 'public_key_sha256'), (5, 'ca_sha256')):
            altered = values.copy()
            altered[index] = b'invalid'
            options = dict(kwargs, **{key: digest(altered[index])})
            with self.subTest(index=index), self.assertRaises(AuditError):
                build(*altered, **options)

    def test_publish_is_idempotent_and_never_overwrites_a_conflict(self):
        values, kwargs = inputs()
        bundle = build(*values, **kwargs)
        with tempfile.TemporaryDirectory(prefix='h454-bundle-') as temporary:
            state = Path(temporary)
            result = publish(bundle, state)
            self.assertEqual(result, publish(bundle, state))
            self.assertEqual(result['h454-wss-tunnel.ps1'], digest(bundle['h454-wss-tunnel.ps1']).upper())
            conflict = state / 'wss-relay-ca.pem'
            conflict.write_bytes(b'existing')
            with self.assertRaisesRegex(AuditError, 'unsafe_wss_bundle_file'):
                publish(bundle, state)
            self.assertEqual(conflict.read_bytes(), b'existing')

    def test_conflict_is_found_before_any_new_file_is_written(self):
        values, kwargs = inputs()
        bundle = build(*values, **kwargs)
        with tempfile.TemporaryDirectory(prefix='h454-bundle-') as temporary:
            state = Path(temporary)
            (state / 'h454-wss-tunnel-config.json').write_bytes(b'occupied')
            with self.assertRaisesRegex(AuditError, 'unsafe_wss_bundle_file'):
                publish(bundle, state)
            self.assertEqual(sorted(path.name for path in state.iterdir()), ['h454-wss-tunnel-config.json'])

    def test_interrupted_flush_is_rechecked_and_committed_on_retry(self):
        values, kwargs = inputs()
        bundle = build(*values, **kwargs)
        with tempfile.TemporaryDirectory(prefix='h454-bundle-') as temporary:
            state = Path(temporary)
            with mock.patch('scripts.h454_windows_wss_bundle.os.fsync', side_effect=OSError('fixture')):
                with self.assertRaisesRegex(AuditError, 'unsafe_wss_bundle_create'):
                    publish(bundle, state)
            self.assertEqual(len(list(state.iterdir())), 1)
            result = publish(bundle, state)
            self.assertEqual(set(result), set(bundle))

    if os.name != 'nt':
        def test_symlinked_state_or_file_is_refused(self):
            values, kwargs = inputs()
            bundle = build(*values, **kwargs)
            with tempfile.TemporaryDirectory(prefix='h454-bundle-') as temporary:
                root = Path(temporary)
                state = root / 'state'
                state.mkdir()
                (root / 'link').symlink_to(state, target_is_directory=True)
                with self.assertRaisesRegex(AuditError, 'unsafe_wss_bundle_directory'):
                    publish(bundle, root / 'link')
                (state / 'h454-wss-identity.ps1').symlink_to(root / 'missing')
                with self.assertRaisesRegex(AuditError, 'unsafe_wss_bundle_file'):
                    publish(bundle, state)


if __name__ == '__main__':
    unittest.main()
