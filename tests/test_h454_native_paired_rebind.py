"""Synthetic credential-preserving release rebinding; no host or network."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SCHEMA, SERVICE
from scripts.h454_native_paired_rebind import (
    RebindDenied, build_transition, rebind, rebind_trust, recover_device,
    replace_frozen_state,
)
from scripts.h454_native_readonly_bundle import SOURCE_FILES, build_bytes
from scripts import h454_native_paired_state as state_tx
from scripts import h454_native_paired_freeze as freeze_tx
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
    def test_transition_requires_exact_bundle_and_preserves_paired_identity(self):
        manifest, device = snapshots()
        ca = b"-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"
        trust = encode({"schema": "h454-private-relay-v1", "target": "hermes-vps",
                        "release_sha": OLD, "relay_ipv4": "172.29.251.2",
                        "ca_sha256": hashlib.sha256(ca).hexdigest(),
                        "server_name": "brc-agent.internal", "port": 3001})
        bundle, receipt = build_bytes(target="hermes-vps", release_sha=NEW,
                                      sources={name: b"synthetic" for name in SOURCE_FILES})
        bundle_sha = hashlib.sha256(bundle).hexdigest()
        with patch("scripts.h454_native_paired_rebind.private_tls._context"):
            transition = build_transition(manifest, device, trust, ca, bundle, receipt,
                                          old_release=OLD, new_release=NEW,
                                          expected_bundle_sha256=bundle_sha)
            self.assertEqual(json.loads(transition.device)["token"], TOKEN)
            self.assertEqual(json.loads(transition.device)["device_id"], DEVICE)
            self.assertEqual(json.loads(transition.trust)["relay_ipv4"], "172.29.251.2")
            self.assertIn(("--release-sha " + NEW).encode(), transition.active_unit)
            self.assertIn(b"IPAddressDeny=any\n", transition.active_unit)
            self.assertNotIn(TOKEN, repr(transition))
            for bad_bundle, bad_receipt, expected in ((bundle, receipt, "0" * 64),
                                                       (bundle + b"x", receipt, bundle_sha),
                                                       (bundle, receipt + b"x", bundle_sha)):
                with self.assertRaises(RebindDenied):
                    build_transition(manifest, device, trust, ca, bad_bundle, bad_receipt,
                                     old_release=OLD, new_release=NEW,
                                     expected_bundle_sha256=expected)

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

    def test_recover_device_from_either_version_without_a_token_backup(self):
        old_manifest, old_device = snapshots()
        new = rebind(old_manifest, old_device, old_release=OLD, new_release=NEW,
                     bundle_sha256="e" * 64)
        for device in (old_device, new.device):
            with self.subTest(version=json.loads(device)["release_sha"]):
                self.assertEqual(recover_device(device, old_manifest, new.manifest,
                                                old_release=OLD, new_release=NEW), old_device)
        corrupt = json.loads(new.device)
        corrupt["roots"] = [{"project": "hermes", "path": "/etc"}]
        with self.assertRaises(RebindDenied):
            recover_device(encode(corrupt), old_manifest, new.manifest,
                           old_release=OLD, new_release=NEW)
        changed_manifest = json.loads(new.manifest)
        changed_manifest["roots"] = [{"project": "hermes", "path": "/etc"}]
        with self.assertRaises(RebindDenied):
            recover_device(new.device, old_manifest, encode(changed_manifest),
                           old_release=OLD, new_release=NEW)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "frozen state requires Linux-style descriptor operations")
class FrozenStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-paired-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.file = self.directory / "device.json"
        self.file.write_bytes(b"old-synthetic")
        self.file.chmod(0o600)

    def replace(self, expected=b"old-synthetic", replacement=b"new-synthetic"):
        replace_frozen_state(self.directory, "device.json", expected=expected,
                             replacement=replacement, trusted_uid=os.geteuid())

    def test_replaces_only_expected_regular_file_and_preserves_private_mode(self):
        before = self.file.stat()
        self.replace()
        after = self.file.stat()
        self.assertEqual(self.file.read_bytes(), b"new-synthetic")
        self.assertEqual(after.st_mode & 0o777, 0o600)
        self.assertEqual((after.st_uid, after.st_gid, after.st_nlink),
                         (before.st_uid, before.st_gid, 1))
        self.assertFalse((self.directory / ".h454-paired-device.json.pending").exists())

    def test_refuses_drift_existing_stage_symlink_and_unfrozen_directory(self):
        with self.assertRaises(RebindDenied):
            self.replace(expected=b"wrong")
        self.assertEqual(self.file.read_bytes(), b"old-synthetic")
        pending = self.directory / ".h454-paired-device.json.pending"
        pending.write_bytes(b"retain")
        with self.assertRaises(RebindDenied):
            self.replace()
        self.assertEqual(pending.read_bytes(), b"retain")
        pending.unlink()
        self.directory.chmod(0o755)
        with self.assertRaises(RebindDenied):
            self.replace()
        self.directory.chmod(0o700)
        self.file.unlink()
        outside = self.directory / "outside"
        outside.write_bytes(b"protected")
        self.file.symlink_to(outside)
        with self.assertRaises(RebindDenied):
            self.replace()
        self.assertEqual(outside.read_bytes(), b"protected")

    def test_mid_switch_drift_keeps_current_and_staged_files(self):
        real_stat = os.stat

        def drift(name, *args, **kwargs):
            if name == "device.json" and kwargs.get("dir_fd") is not None:
                self.file.write_bytes(b"concurrent-change")
            return real_stat(name, *args, **kwargs)

        with patch("scripts.h454_native_paired_rebind.os.stat", side_effect=drift):
            with self.assertRaises(RebindDenied):
                self.replace()
        self.assertEqual(self.file.read_bytes(), b"concurrent-change")
        self.assertEqual((self.directory / ".h454-paired-device.json.pending").read_bytes(),
                         b"new-synthetic")


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "journaled state requires Linux-style descriptor operations")
class JournaledStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-journal-synthetic-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state, self.journal = root / "state", root / "journal"
        self.state.mkdir(mode=0o700)
        self.journal.mkdir(mode=0o700)
        self.manifest, self.device = snapshots()
        for name, data in (("manifest.json", self.manifest), ("device.json", self.device)):
            path = self.state / name
            path.write_bytes(data)
            path.chmod(0o600)
        self.uid = os.geteuid()

    def prepare(self):
        state_tx.prepare(self.state, self.journal, trusted_uid=self.uid,
                         old_release=OLD, new_release=NEW, bundle_sha256="e" * 64)

    def assert_old(self):
        self.assertEqual((self.state / "manifest.json").read_bytes(), self.manifest)
        self.assertEqual((self.state / "device.json").read_bytes(), self.device)

    def test_sealed_journal_contains_no_bearer_and_switch_recovers_once(self):
        self.prepare()
        for path in self.journal.iterdir():
            self.assertNotIn(TOKEN.encode(), path.read_bytes())
        state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assertEqual(json.loads((self.state / "device.json").read_bytes())["release_sha"], NEW)
        state_tx.recover(self.state, self.journal, trusted_uid=self.uid)
        self.assert_old()
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assert_old()

    def test_interrupted_each_switch_step_recovers_without_token_backup(self):
        self.prepare()
        real = state_tx.replace_frozen_state
        calls = []

        def interrupt_second(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("synthetic failure")
            return real(*args, **kwargs)

        with patch.object(state_tx, "replace_frozen_state", side_effect=interrupt_second):
            with self.assertRaises(RebindDenied):
                state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assertNotEqual((self.state / "manifest.json").read_bytes(), self.manifest)
        self.assertEqual((self.state / "device.json").read_bytes(), self.device)
        state_tx.recover(self.state, self.journal, trusted_uid=self.uid)
        self.assert_old()
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)

    def test_interruption_after_both_replacements_still_recovers(self):
        self.prepare()
        real = state_tx.replace_frozen_state
        calls = []

        def interrupt_after_second(*args, **kwargs):
            real(*args, **kwargs)
            calls.append(1)
            if len(calls) == 2:
                raise OSError("synthetic failure")

        with patch.object(state_tx, "replace_frozen_state", side_effect=interrupt_after_second):
            with self.assertRaises(RebindDenied):
                state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assertEqual(json.loads((self.state / "device.json").read_bytes())["release_sha"], NEW)
        self.assertFalse((self.journal / "complete").exists())
        state_tx.recover(self.state, self.journal, trusted_uid=self.uid)
        self.assert_old()

    def test_unsealed_or_changed_device_never_switches(self):
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.prepare()
        changed = json.loads(self.device)
        changed["token"] = "brc_dev_" + "y" * 64
        (self.state / "device.json").write_bytes(encode(changed))
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assertEqual((self.state / "manifest.json").read_bytes(), self.manifest)
        self.assertFalse((self.journal / "started").exists())

    def test_changed_journal_snapshot_and_shared_directory_fail_closed(self):
        with self.assertRaises(RebindDenied):
            state_tx.prepare(self.state, self.state, trusted_uid=self.uid,
                             old_release=OLD, new_release=NEW, bundle_sha256="e" * 64)
        self.assert_old()
        self.prepare()
        (self.journal / "new-manifest.json").write_bytes(b"tampered")
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        self.assert_old()

    def test_foreign_journal_entry_is_preserved_and_refused(self):
        foreign = self.journal / "foreign"
        foreign.write_bytes(b"preserve")
        with self.assertRaises(RebindDenied):
            self.prepare()
        self.assertEqual(foreign.read_bytes(), b"preserve")
        self.assert_old()

    def test_staged_partial_device_forces_hold_and_is_preserved(self):
        self.prepare()
        pending = self.state / ".h454-paired-device.json.pending"
        pending.write_bytes(self.device)
        pending.chmod(0o600)
        with self.assertRaises(RebindDenied):
            state_tx.switch(self.state, self.journal, trusted_uid=self.uid)
        with self.assertRaises(RebindDenied):
            state_tx.recover(self.state, self.journal, trusted_uid=self.uid)
        self.assertEqual(pending.read_bytes(), self.device)
        self.assert_old()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "directory freeze requires Linux-style descriptor operations")
class DirectoryFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-freeze-synthetic-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state, self.journal = root / "state", root / "journal"
        self.state.mkdir(mode=0o700)
        self.journal.mkdir(mode=0o700)

    def test_rejects_current_uid_as_service_identity_without_mutation(self):
        before = self.state.stat()
        with self.assertRaises(RebindDenied):
            freeze_tx.freeze(self.state, self.journal, trusted_uid=os.geteuid(),
                             service_uid=os.geteuid(), service_gid=os.getegid())
        self.assertEqual(self.state.stat().st_uid, before.st_uid)
        self.assertEqual(list(self.journal.iterdir()), [])

    def test_root_roundtrip_or_nonroot_permission_denial(self):
        if os.geteuid() != 0:
            with self.assertRaises(RebindDenied):
                freeze_tx.freeze(self.state, self.journal, trusted_uid=os.geteuid(),
                                 service_uid=12345, service_gid=12345)
            return
        os.chown(self.state, 12345, 12345)
        freeze_tx.freeze(self.state, self.journal, trusted_uid=0,
                         service_uid=12345, service_gid=12345)
        self.assertEqual(self.state.stat().st_uid, 0)
        self.assertEqual((self.journal / "frozen").read_bytes(), b"FROZEN\n")
        freeze_tx.restore_owner(self.state, self.journal, trusted_uid=0,
                                service_uid=12345, service_gid=12345)
        self.assertEqual((self.state.stat().st_uid, self.state.stat().st_gid), (12345, 12345))

    def test_interrupted_freeze_never_loses_recorded_original_owner(self):
        if os.geteuid() != 0:
            with self.assertRaises(RebindDenied):
                freeze_tx.restore_owner(self.state, self.journal, trusted_uid=os.geteuid(),
                                        service_uid=12345, service_gid=12345)
            return
        os.chown(self.state, 12345, 12345)
        create = freeze_tx._create

        def interrupt(fd, name, data):
            if name == "frozen":
                raise OSError("synthetic interruption")
            return create(fd, name, data)

        with patch.object(freeze_tx, "_create", side_effect=interrupt):
            with self.assertRaises(RebindDenied):
                freeze_tx.freeze(self.state, self.journal, trusted_uid=0,
                                 service_uid=12345, service_gid=12345)
        self.assertEqual(self.state.stat().st_uid, 0)
        self.assertFalse((self.journal / "frozen").exists())
        freeze_tx.restore_owner(self.state, self.journal, trusted_uid=0,
                                service_uid=12345, service_gid=12345)
        self.assertEqual((self.state.stat().st_uid, self.state.stat().st_gid), (12345, 12345))


if __name__ == "__main__":
    unittest.main()
