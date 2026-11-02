"""Prepare only the pinned public inputs and generated supervisor files."""
import hashlib
import json
import unittest

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import ANCHOR, patch_launcher_bytes
from scripts.h454_windows_wss_bundle import build


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


if __name__ == '__main__':
    unittest.main()
