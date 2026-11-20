"""Synthetic credential-preserving release rebinding; no host or network."""
import hashlib
import json
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SCHEMA, SERVICE
from scripts.h454_native_paired_rebind import RebindDenied, rebind, rebind_trust
from scripts.h454_native_linux_runtime import SCHEMA as DEVICE_SCHEMA

OLD = "a" * 40
NEW = "b" * 40
ROOTS = [{"project": "hermes", "path": "/srv/synthetic-project"}]
TOKEN = "brc_dev_" + "x" * 64
DEVICE = "h454-linux-hermes-" + "c" * 32


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def snapshots():
    manifest = encode({
        "schema": SCHEMA, "target": "hermes-vps", "release_sha": OLD,
        "artifact_sha256": "d" * 64, "service_name": SERVICE["hermes-vps"][0],
        "service_identity": SERVICE["hermes-vps"][1], "start_state": "DISABLED",
        "access_mode": "READ_ONLY", "roots": ROOTS,
    })
    device = encode({
        "schema": DEVICE_SCHEMA, "target": "hermes-vps", "release_sha": OLD,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "device_id": DEVICE,
        "token": TOKEN, "url": "wss://hermes.mikemoore.top/ws", "roots": ROOTS,
    })
    return manifest, device


class PairedRebindTests(unittest.TestCase):
    def test_private_trust_rebind_preserves_exact_ca_and_relay(self):
        ca = b"-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"
        old = {"schema": "h454-private-relay-v1", "target": "hermes-vps",
               "release_sha": OLD, "relay_ipv4": "172.29.251.2",
               "ca_sha256": hashlib.sha256(ca).hexdigest(),
               "server_name": "brc-agent.internal", "port": 3001}
        with patch("scripts.h454_native_paired_rebind.private_tls._context") as verify:
            result = rebind_trust(encode(old), ca, old_release=OLD, new_release=NEW)
            self.assertEqual(json.loads(result), {**old, "release_sha": NEW})
            verify.assert_called_once_with(ca)
            for changes in ({"relay_ipv4": "8.8.8.8"}, {"port": 443},
                            {"target": "yfc-vps"}, {"ca_sha256": "0" * 64},
                            {"server_name": "foreign.invalid"}):
                with self.subTest(changes=changes), self.assertRaises(RebindDenied):
                    rebind_trust(encode({**old, **changes}), ca,
                                 old_release=OLD, new_release=NEW)
            with self.assertRaises(RebindDenied):
                rebind_trust(encode(old) + b"\n", ca, old_release=OLD, new_release=NEW)

    def test_preserves_bearer_identity_and_scope_across_release(self):
        manifest, device = snapshots()
        result = rebind(manifest, device, old_release=OLD, new_release=NEW,
                        bundle_sha256="e" * 64)
        after_manifest, after_device = json.loads(result.manifest), json.loads(result.device)
        self.assertEqual(after_manifest["release_sha"], NEW)
        self.assertEqual(after_manifest["artifact_sha256"], "e" * 64)
        self.assertEqual(after_device["manifest_sha256"], hashlib.sha256(result.manifest).hexdigest())
        self.assertEqual(after_device["release_sha"], NEW)
        for key in ("device_id", "token", "url", "target", "roots"):
            self.assertEqual(after_device[key], json.loads(device)[key])
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn(DEVICE, repr(result))
        restored = rebind(result.manifest, result.device, old_release=NEW,
                          new_release=OLD, bundle_sha256="d" * 64)
        self.assertEqual(restored.manifest, manifest)
        self.assertEqual(restored.device, device)

    def test_denies_changed_scope_duplicate_json_and_untrusted_releases(self):
        manifest, device = snapshots()
        damaged = json.loads(device)
        for change in ({"roots": [{"project": "hermes", "path": "/etc"}]},
                       {"device_id": "h454-linux-yfc-" + "a" * 32},
                       {"token": "too-short"}, {"manifest_sha256": "0" * 64}):
            with self.subTest(change=list(change)), self.assertRaisesRegex(
                    RebindDenied, "^native_paired_rebind_denied$"):
                rebind(manifest, encode({**damaged, **change}), old_release=OLD,
                       new_release=NEW, bundle_sha256="e" * 64)
        for bad in (device + b"\n", device.replace(b'"token":', b'"token":"x","token":', 1)):
            with self.assertRaises(RebindDenied):
                rebind(manifest, bad, old_release=OLD, new_release=NEW, bundle_sha256="e" * 64)
        for old, new, bundle in ((OLD, OLD, "e" * 64), (OLD, "0" * 40, "e" * 64),
                                 (OLD, NEW, "bad"), (OLD, NEW, "0" * 64)):
            with self.assertRaises(RebindDenied):
                rebind(manifest, device, old_release=old, new_release=new, bundle_sha256=bundle)


if __name__ == "__main__":
    unittest.main()
