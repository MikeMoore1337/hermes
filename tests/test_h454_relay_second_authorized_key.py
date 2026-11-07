import base64
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import h454_relay_second_authorized_key as subject


def key(seed):
    wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes([seed]) * 32
    return "ssh-ed25519 " + base64.b64encode(wire).decode()


if os.name == "posix" and os.geteuid() == 0:
    class SecondAuthorizedKeyTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-second-key-")
            self.root = Path(self.temp.name)
            self.registry = self.root / "registry"
            self.ssh = self.root / "ssh"
            self.registry.mkdir(mode=0o700)
            self.ssh.mkdir(mode=0o700)
            os.chown(self.ssh, 65534, 65534)
            self.original = self.ssh / "authorized_keys"
            self.original.write_text('restrict,port-forwarding ' + key(1) + '\n', encoding="ascii")
            self.original.chmod(0o600)
            os.chown(self.original, 65534, 65534)
            self.original_bytes = self.original.read_bytes()
            self.digest = hashlib.sha256(self.original_bytes).hexdigest()
            self.registry_fd = os.open(self.registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.ssh_fd = os.open(self.ssh, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

        def tearDown(self):
            os.close(self.ssh_fd)
            os.close(self.registry_fd)
            self.temp.cleanup()

        def install(self, **changes):
            args = {"uid": 65534, "original_sha256": self.digest, "public_key": key(2), "relay_ip": "172.20.0.4"}
            args.update(changes)
            return subject.install(self.registry_fd, self.ssh_fd, **args)

        def revoke(self, receipt):
            return subject.revoke(self.registry_fd, self.ssh_fd, uid=65534, **receipt)

        def test_install_is_idempotent_and_only_allows_new_port(self):
            receipt = self.install()
            self.assertEqual(self.install(), receipt)
            source, target = self.registry / subject.SLOT, self.ssh / subject.TARGET
            self.assertEqual((source.stat().st_dev, source.stat().st_ino),
                             (target.stat().st_dev, target.stat().st_ino))
            self.assertEqual(source.stat().st_uid, 0)
            self.assertEqual(source.stat().st_mode & 0o777, 0o644)
            self.assertIn(b'permitopen="172.20.0.4:3001"', target.read_bytes())
            self.assertNotIn(b':3000', target.read_bytes())
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_existing_file_or_link_is_not_overwritten(self):
            target = self.ssh / subject.TARGET
            for symlink in (False, True):
                other = self.ssh / "other"
                other.write_bytes(b"unrelated")
                if symlink:
                    target.symlink_to(other.name)
                else:
                    target.write_bytes(b"unrelated")
                with self.assertRaises(subject.SecondKeyHold):
                    self.install()
                self.assertEqual(other.read_bytes(), b"unrelated")
                if not symlink:
                    self.assertEqual(target.read_bytes(), b"unrelated")
                target.unlink()
                other.unlink()
            self.assertEqual(list(self.registry.iterdir()), [])
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_existing_original_key_and_unreviewed_original_are_refused(self):
            with self.assertRaises(subject.SecondKeyHold):
                self.install(public_key=key(1))
            with self.assertRaises(subject.SecondKeyHold):
                self.install(original_sha256="0" * 64)
            self.assertEqual(list(self.registry.iterdir()), [])
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_concurrent_target_creation_is_preserved(self):
            original_link = os.link
            target = self.ssh / subject.TARGET

            def racing_link(src, dst, **kwargs):
                if dst == subject.TARGET:
                    target.write_bytes(b"concurrent data")
                return original_link(src, dst, **kwargs)

            with mock.patch.object(subject.os, "link", side_effect=racing_link):
                with self.assertRaises(subject.SecondKeyHold):
                    self.install()
            self.assertEqual(target.read_bytes(), b"concurrent data")
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_concurrent_installers_cannot_replace_each_others_key(self):
            context = multiprocessing.get_context("fork")
            start, results = context.Event(), context.Queue()

            def worker(seed):
                registry_fd = os.open(self.registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                ssh_fd = os.open(self.ssh, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    if not start.wait(5):
                        results.put(("timeout", seed))
                        return
                    try:
                        subject.install(registry_fd, ssh_fd, uid=65534, original_sha256=self.digest,
                                        public_key=key(seed), relay_ip="172.20.0.4")
                        results.put(("installed", seed))
                    except subject.SecondKeyHold:
                        results.put(("held", seed))
                finally:
                    os.close(ssh_fd)
                    os.close(registry_fd)

            processes = [context.Process(target=worker, args=(seed,)) for seed in (2, 3)]
            try:
                for process in processes:
                    process.start()
                start.set()
                for process in processes:
                    process.join(10)
                    self.assertEqual(process.exitcode, 0)
                outcomes = [results.get(timeout=2), results.get(timeout=2)]
                self.assertEqual(sorted(status for status, _ in outcomes), ["held", "installed"])
                winner = next(seed for status, seed in outcomes if status == "installed")
                self.assertIn(key(winner).encode(), (self.ssh / subject.TARGET).read_bytes())
                self.assertEqual(self.original.read_bytes(), self.original_bytes)
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(5)
                results.close()

        def test_original_drift_revokes_only_new_inode(self):
            original_link = os.link

            def racing_link(src, dst, **kwargs):
                result = original_link(src, dst, **kwargs)
                if dst == subject.TARGET:
                    self.original.write_bytes(self.original_bytes + b"# concurrent\n")
                return result

            with mock.patch.object(subject.os, "link", side_effect=racing_link):
                with self.assertRaisesRegex(subject.SecondKeyHold, "KEY_INSTALL_REVOKED"):
                    self.install()
            self.assertEqual((self.ssh / subject.TARGET).read_bytes(), b"")
            self.assertEqual(self.original.read_bytes(), self.original_bytes + b"# concurrent\n")

        def test_existing_registry_slot_is_never_replaced(self):
            slot = self.registry / subject.SLOT
            slot.write_bytes(b"existing data")
            slot.chmod(0o644)
            with self.assertRaises(subject.SecondKeyHold):
                self.install()
            self.assertEqual(slot.read_bytes(), b"existing data")
            self.assertFalse((self.ssh / subject.TARGET).exists())
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_original_disappearance_after_link_revokes_new_key(self):
            original_link = os.link

            def racing_link(src, dst, **kwargs):
                result = original_link(src, dst, **kwargs)
                if dst == subject.TARGET:
                    self.original.unlink()
                return result

            with mock.patch.object(subject.os, "link", side_effect=racing_link):
                with self.assertRaisesRegex(subject.SecondKeyHold, "KEY_INSTALL_REVOKED"):
                    self.install()
            self.assertEqual((self.ssh / subject.TARGET).read_bytes(), b"")
            self.assertFalse(self.original.exists())

        def test_target_replaced_after_link_is_unsettled_and_untouched(self):
            original_link = os.link
            target = self.ssh / subject.TARGET

            def racing_link(src, dst, **kwargs):
                result = original_link(src, dst, **kwargs)
                if dst == subject.TARGET:
                    target.unlink()
                    target.write_bytes(b"concurrent data")
                return result

            with mock.patch.object(subject.os, "link", side_effect=racing_link):
                with self.assertRaisesRegex(subject.SecondKeyHold, "KEY_INSTALL_UNSETTLED"):
                    self.install()
            self.assertEqual(target.read_bytes(), b"concurrent data")
            self.assertEqual((self.registry / subject.SLOT).read_bytes(), b"")
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_revoke_never_truncates_a_replaced_target(self):
            receipt = self.install()
            target = self.ssh / subject.TARGET
            target.unlink()
            target.write_bytes(b"concurrent data")
            self.revoke(receipt)
            self.revoke(receipt)
            self.assertEqual(target.read_bytes(), b"concurrent data")
            self.assertEqual((self.registry / subject.SLOT).read_bytes(), b"")
            self.assertEqual(self.original.read_bytes(), self.original_bytes)
            with self.assertRaises(subject.SecondKeyHold):
                self.install()

        def test_failure_after_link_revokes_or_reports_unsettled(self):
            fsync = os.fsync

            def fail_directory(fd):
                if fd == self.ssh_fd:
                    raise OSError("synthetic directory sync failure")
                return fsync(fd)

            with mock.patch.object(subject.os, "fsync", side_effect=fail_directory):
                with self.assertRaisesRegex(subject.SecondKeyHold, "KEY_INSTALL_REVOKED"):
                    self.install()
            self.assertEqual((self.ssh / subject.TARGET).read_bytes(), b"")
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_failed_emergency_revocation_is_never_reported_as_safe(self):
            fsync = os.fsync

            def fail_directory(fd):
                if fd == self.ssh_fd:
                    raise OSError("synthetic directory sync failure")
                return fsync(fd)

            with mock.patch.object(subject.os, "fsync", side_effect=fail_directory), \
                 mock.patch.object(subject.os, "ftruncate", side_effect=OSError("synthetic revoke failure")):
                with self.assertRaisesRegex(subject.SecondKeyHold, "KEY_INSTALL_UNSETTLED"):
                    self.install()
            self.assertNotEqual((self.ssh / subject.TARGET).read_bytes(), b"")
            self.assertEqual(self.original.read_bytes(), self.original_bytes)

        def test_wrong_receipt_and_invalid_inputs_are_refused(self):
            receipt = self.install()
            bad = dict(receipt, inode=receipt["inode"] + 1)
            with self.assertRaises(subject.SecondKeyHold):
                self.revoke(bad)
            self.assertNotEqual((self.ssh / subject.TARGET).read_bytes(), b"")
            with self.assertRaises(subject.SecondKeyHold):
                self.install(relay_ip="8.8.8.8")
            with self.assertRaises(subject.SecondKeyHold):
                self.install(uid=0)


if __name__ == "__main__":
    unittest.main()
