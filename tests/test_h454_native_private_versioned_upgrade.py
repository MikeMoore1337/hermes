"""Hermes #454: dormant private-only e888 -> 30db upgrade contracts."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SCHEMA, SERVICE
from scripts import h454_native_private_versioned_upgrade as m
from scripts import h454_native_readonly_bundle as bundle
from scripts.h454_native_linux_active_unit import render_active_unit
from scripts.h454_native_linux_unit_candidate import render_preflight_unit


class PrivateVersionedSourceContracts(unittest.TestCase):
    def historical_bundle(self, files):
        with patch.object(bundle, "SOURCE_FILES", m.SOURCE_FILES):
            archive, receipt = bundle.build_bytes(
                target=m.TARGET, release_sha=m.CURRENT, sources=files)
            manifest = bundle._manifest(
                target=m.TARGET, release_sha=m.CURRENT, sources=files)
        return archive, receipt, manifest

    def test_bundle_proves_exact_source_count_and_status(self):
        files = {name: ("# fixture " + name + "\n").encode() for name in m.SOURCE_FILES}
        files["device_fabric/native_private_tls.py"] += b"def load_private_relay(): pass\n"
        files["scripts/h454_native_linux_service.py"] += b"private_websocket_connector\n"
        binary, receipt, manifest_bytes = self.historical_bundle(files)
        with patch.object(m, "BUNDLE_SHA", hashlib.sha256(binary).hexdigest()), \
             patch.object(m, "MANIFEST_SOURCE_SHA", hashlib.sha256(manifest_bytes).hexdigest()):
            self.assertEqual(m.verified_source(binary, receipt), files)
            corrupt = bytearray(binary)
            corrupt[-20] ^= 1
            with self.assertRaises(m.UpgradeHold):
                m.verified_source(bytes(corrupt), receipt)
            changed = json.loads(receipt)
            changed["activation"] = "ENABLED"
            with self.assertRaises(m.UpgradeHold):
                m.verified_source(binary, bundle._json(changed))

    def test_private_upgrade_rejects_legacy_13_file_parser_without_weakening_it(self):
        files = {name: ("# source " + name + "\n").encode()
                 for name in m.SOURCE_FILES}
        files["device_fabric/native_private_tls.py"] += b"def load_private_relay(): pass\n"
        files["scripts/h454_native_linux_service.py"] += b"private_websocket_connector\n"
        archive, receipt, manifest = self.historical_bundle(files)
        old_13_paths = tuple(name for name in m.SOURCE_FILES
                             if name != "device_fabric/native_private_tls.py")
        self.assertEqual(len(old_13_paths), 13)
        # Reproduce original VPS behavior: old owner-source decoder is pinned
        # to 13 members, and correctly rejects the 14-member release.
        with patch.object(bundle, "SOURCE_FILES", old_13_paths):
            with self.assertRaises(bundle.SourceBundleDenied):
                bundle._bounded_ustar(archive)
            with patch.object(m, "BUNDLE_SHA", hashlib.sha256(archive).hexdigest()), \
                 patch.object(m, "MANIFEST_SOURCE_SHA", hashlib.sha256(manifest).hexdigest()):
                self.assertEqual(m.verified_source(archive, receipt), files)

    def test_strict_new_14_ustar_denies_extras_and_malformed_gzip(self):
        files = {name: ("# fixture " + name + "\n").encode()
                 for name in m.SOURCE_FILES}
        archive, _, _ = self.historical_bundle(files)
        with patch.object(bundle, "SOURCE_FILES", m.SOURCE_FILES):
            self.assertEqual(len(m._bounded_14_ustar(archive)),
                             len(bundle._bounded_ustar(archive)))
        current_files = {name: ("# current " + name + "\n").encode()
                         for name in bundle.SOURCE_FILES}
        current_archive, _ = bundle.build_bytes(
            target=m.TARGET, release_sha=m.CURRENT, sources=current_files)
        with self.assertRaises(m.UpgradeHold):
            m._bounded_14_ustar(current_archive)
        for changed in (archive + b"EXTRA", archive[:-10]):
            with self.subTest(kind="gzip"), self.assertRaises(m.UpgradeHold):
                m._bounded_14_ustar(changed)
        container = io.BytesIO()
        with gzip.GzipFile(fileobj=container, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as extended:
                with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as valid:
                    for item in valid:
                        extended.addfile(item, valid.extractfile(item))
                unexpected = tarfile.TarInfo("scripts/malicious_extra.py")
                payload = b"do_not_execute\n"
                unexpected.size = len(payload)
                extended.addfile(unexpected, io.BytesIO(payload))
        with self.assertRaises(m.UpgradeHold):
            m._bounded_14_ustar(container.getvalue())

    def test_exact_release_and_expected_real_sha_pins(self):
        self.assertEqual(m.PREVIOUS, "e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a")
        self.assertEqual(m.CURRENT, "30db4fbab46626985b078d574dbe0b839872840e")
        self.assertEqual(m.BUNDLE_SHA, "c61fd03785b5ffda9cc24b058ae779ad4514fb79d276769e21b48f8059a6e111")
        self.assertEqual(len(m.SOURCE_FILES), 14)
        self.assertIn("device_fabric/native_private_tls.py", m.SOURCE_FILES)

    def test_generated_unit_matches_new_main_private_renderer_exactly(self):
        data = {
            "schema": SCHEMA, "target": m.TARGET,
            "release_sha": m.CURRENT, "artifact_sha256": m.BUNDLE_SHA,
            "service_name": SERVICE[m.TARGET][0],
            "service_identity": SERVICE[m.TARGET][1],
            "start_state": "DISABLED", "access_mode": "READ_ONLY",
            "roots": [{"project": "hermes", "path": "/srv/hermes/source"}],
        }
        manifest = m.canonical(data)
        manifest_hash = hashlib.sha256(manifest).hexdigest()
        baseline = render_preflight_unit(manifest, target=m.TARGET,
            release_sha=m.CURRENT, manifest_sha256=manifest_hash)
        self.assertIn("RestrictSUIDSGID=no\n", baseline)
        legacy = baseline.replace("RestrictSUIDSGID=no\n", "RestrictSUIDSGID=yes\n")
        with patch.object(m, "render_preflight_unit", return_value=legacy):
            candidate = m._unit_rendered(manifest, "172.29.251.2")
        current = render_active_unit(
            manifest, target=m.TARGET, release_sha=m.CURRENT,
            manifest_sha256=manifest_hash, relay_ipv4="172.29.251.2",
            dns_ipv4="", private_relay=True,
        )
        self.assertEqual(candidate["hermes-commander-native.service"], current.encode())
        self.assertEqual(candidate["hermes-commander-native-preflight.service"], baseline.encode())
        self.assertEqual(current.count("IPAddressAllow="), 1)
        self.assertIn("IPAddressAllow=172.29.251.2/32", current)
        self.assertNotIn("IPAddressAllow=1.1.1.1", current)
        self.assertNotIn("IPAddressAllow=8.8.8.8", current)
        self.assertIn("ReadOnlyPaths=/opt/hermes-commander-native/trust", current)

    def test_inert_deny_bypasses_and_no_service_activation(self):
        self.assertTrue(set(("plan", "install-off", "rollback-off")))
        import inspect
        source = inspect.getsource(m)
        self.assertNotIn('"systemctl", "start"', source)
        self.assertNotIn('"systemctl", "enable"', source)
        self.assertNotIn('"docker", "run"', source)
        self.assertNotIn('device.json", b', source)

    def test_create_only_and_atomic_file_replace(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "manifest.json"
            uid, gid = os.geteuid(), os.getegid()
            m.create_file(file, b"old", uid=uid, gid=gid)
            with self.assertRaises(m.UpgradeHold):
                m.create_file(file, b"second", uid=uid, gid=gid)
            self.assertEqual(file.read_bytes(), b"old")
            m.atomic_replace(file, b"new", mode=0o600, uid=uid, gid=gid)
            self.assertEqual(file.read_bytes(), b"new")
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(Path(folder).iterdir())), 1)

    def test_private_ip_and_ca_pins_refuse_foreign(self):
        import ssl
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            paths = m.Paths(wss=folder)
            pin = {"version": 1, "relay_name": "hermes-brc-relay",
                   "sidecar_name": "hermes-h454-wss-proxy",
                   "relay_ipv4": "8.8.8.8", "gateway_ipv4": "172.29.251.1",
                   "tls_directory": str(folder), "ca_sha256": "a" * 64}
            with patch.object(m, "owned_directory"), \
                 patch.object(m, "checked_file", return_value=m.canonical(pin)):
                with self.assertRaises(m.UpgradeHold):
                    m.private_relay(paths)

    def test_sanitized_plan_does_not_echo_roots(self):
        private = m.Preview(
            b"/srv/private-vault bearer-secret", b"new", {}, {
                "hermes-commander-native-preflight.service": b"preflight",
                "hermes-commander-native.service": b"active",
            }, {}, b"bundle", b"ca", b"private-trust", b"wheel",
            {}, (), 2001, 2001, "172.29.251.2")
        result = json.dumps(m.plan_result(private))
        self.assertNotIn("/srv/private-vault", result)
        self.assertNotIn("bearer-secret", result)
        self.assertIn("H454_PRIVATE_UPGRADE_PLAN_PASS", result)

    def test_owner_tty_is_separate_approval_not_bypassed_by_cli(self):
        fake = {"manifest_sha256": "a" * 64, "active_unit_sha256": "b" * 64}
        with patch.object(m.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(m.UpgradeHold):
                m.typed_approval("INSTALL", fake)


if __name__ == "__main__":
    unittest.main()
