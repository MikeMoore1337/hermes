"""#454 WSS evidence archive uses only disposable local synthetic files.

No real host, Docker API, systemd, ca.crt, bearer, or production path accessed.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import h454_wss_native_status_evidence_rearm as arch
from scripts import h454_wss_native_status_sidecar_cutover as source


class WssEvidenceArchiveTests(unittest.TestCase):
    def with_fixture(self, fn, *, mismatch=False, occupied=False, fail_at=None):
        with TemporaryDirectory(prefix="h454-restored-wss-archive-test-") as tmp:
            root = Path(tmp)
            backup = root / "native-status-upgrade-evidence"
            backup.mkdir(mode=0o700)
            original = root / "native-status-original-pins.json"
            original_bytes = b'{"synthetic":"pins-before-switch"}\n'
            old_bytes = original_bytes if not mismatch else b'{"foreign":"pins"}\n'
            original.write_bytes(original_bytes)
            archived_pins = backup / "old-pins.json"
            archived_pins.write_bytes(old_bytes)
            os.chmod(original, 0o600)
            os.chmod(archived_pins, 0o600)
            archive = root / "native-status-failed-attempt-20261118-1237"
            if occupied:
                archive.mkdir(mode=0o700)

            def checked_file(path: Path, *, mode: int, limit=100000):
                info = path.lstat()
                self.assertFalse(path.is_symlink())
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), mode)
                self.assertEqual(info.st_nlink, 1)
                self.assertLessEqual(info.st_size, limit)
                return path.read_bytes()

            def protected(path, mode, *, directory):
                self.assertTrue(directory)
                self.assertTrue(path.is_dir())
                self.assertFalse(path.is_symlink())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

            def once(path, data):
                with path.open("xb") as writer:
                    writer.write(data)
                os.chmod(path, 0o600)

            fake = SimpleNamespace(
                ORIGINAL=original,
                BACKUP=backup,
                checked_file=checked_file,
                canonical=source.canonical,
                stage1=SimpleNamespace(protected=protected, write_once=once),
            )
            proof = {
                "original_pins_sha256": hashlib.sha256(original_bytes).hexdigest(),
                "old_proxy_sha256": "a" * 64,
                "candidate_proxy_sha256": "b" * 64,
                "original_relay_id": "c" * 64,
                "original_sidecar_id": "d" * 64,
            }
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(arch, "ROOT", root))
                stack.enter_context(mock.patch.object(arch, "ARCHIVE", archive))
                stack.enter_context(mock.patch.object(arch, "ARCHIVED_BACKUP", archive / "evidence"))
                stack.enter_context(mock.patch.object(
                    arch, "ARCHIVED_ORIGINAL",
                    archive / "evidence" / "native-status-original-pins.json"
                ))
                if fail_at == "link":
                    stack.enter_context(mock.patch.object(arch.os, "link",
                                                         side_effect=OSError("synthetic")))
                elif fail_at == "rename":
                    stack.enter_context(mock.patch.object(arch.os, "rename",
                                                         side_effect=OSError("synthetic")))
                fn(fake, proof, root, backup, original, archive, original_bytes)

    def test_archives_exact_original_inode_bytes_and_keeps_old_source_backup(self):
        def check(tx, proof, root, backup, original, archive, expected):
            extra = backup / "old-proxy.mjs"
            extra.write_bytes(b"synthetic-legacy-source")
            os.chmod(extra, 0o600)
            inode = original.stat().st_ino
            arch.archive_evidence(tx, proof)
            archived = archive / "evidence"
            self.assertFalse(original.exists())
            self.assertFalse(backup.exists())
            self.assertEqual((archived / arch.COPY).read_bytes(), expected)
            self.assertEqual((archived / arch.COPY).stat().st_ino, inode)
            self.assertEqual((archived / arch.COPY).stat().st_nlink, 1)
            self.assertEqual((archived / "old-pins.json").read_bytes(), expected)
            self.assertEqual((archived / "old-proxy.mjs").read_bytes(),
                             b"synthetic-legacy-source")
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o700)
            receipt = (archived / arch.RECEIPT).read_bytes()
            self.assertIn(b'"cutover_authorized":false', receipt)
            self.assertIn(b'"native_service_started":false', receipt)
        self.with_fixture(check)

    def test_occupied_archive_refused_without_touching_originals(self):
        def check(tx, proof, root, backup, original, archive, expected):
            with self.assertRaisesRegex(arch.RearmHold, "ARCHIVE_ALREADY_STARTED"):
                arch.archive_evidence(tx, proof)
            self.assertTrue(original.exists())
            self.assertTrue(backup.exists())
            self.assertEqual(original.read_bytes(), expected)
            self.assertFalse((backup / arch.RECEIPT).exists())
        self.with_fixture(check, occupied=True)

    def test_foreign_old_pin_bytes_refused_before_creating_archive(self):
        def check(tx, proof, root, backup, original, archive, expected):
            with self.assertRaisesRegex(arch.RearmHold, "ORIGINAL_PINS_BACKUP_DRIFT"):
                arch.archive_evidence(tx, proof)
            self.assertTrue(original.exists())
            self.assertTrue(backup.exists())
            self.assertFalse(archive.exists())
        self.with_fixture(check, mismatch=True)

    def test_failed_hardlink_preserves_existing_files_and_stops(self):
        def check(tx, proof, root, backup, original, archive, expected):
            with self.assertRaises(OSError):
                arch.archive_evidence(tx, proof)
            self.assertTrue(original.exists())
            self.assertTrue(backup.exists())
            self.assertEqual(original.read_bytes(), expected)
            self.assertTrue((backup / arch.RECEIPT).exists())
            self.assertTrue(archive.is_dir())
        self.with_fixture(check, fail_at="link")

    def test_failed_atomic_directory_move_does_not_delete_original(self):
        def check(tx, proof, root, backup, original, archive, expected):
            with self.assertRaises(OSError):
                arch.archive_evidence(tx, proof)
            self.assertTrue(original.exists())
            self.assertTrue(backup.exists())
            self.assertEqual(original.read_bytes(), expected)
            self.assertEqual((backup / arch.COPY).read_bytes(), expected)
            self.assertEqual(original.stat().st_ino, (backup / arch.COPY).stat().st_ino)
        self.with_fixture(check, fail_at="rename")

    def test_early_execute_or_missing_execute_rejected_without_plan(self):
        with mock.patch.object(arch, "plan") as plan, mock.patch.object(arch, "rearm") as rearm:
            self.assertEqual(arch.main(["rearm"]), 2)
            self.assertEqual(arch.main(["plan", "--execute"]), 2)
            plan.assert_not_called()
            rearm.assert_not_called()


class RestoredOriginalPlanTests(unittest.TestCase):
    def with_fixture(self, callback, *, mismatch=False, pending=False, stopped=False):
        with TemporaryDirectory(prefix="h454-wss-readonly-plan-") as dirname:
            root = Path(dirname)
            old_raw = b'{"synthetic":"original-pins"}\n'
            candidate = b"status-proxy-source-only"
            old = b"old-proxy-source-only"
            current_pins = {
                "relay_id": "a" * 64,
                "sidecar_id": "b" * 64,
                "relay_image": "sha256:" + "c" * 64,
                "sidecar_image": "sha256:" + "d" * 64,
                "proxy_sha256": hashlib.sha256(old).hexdigest(),
            }
            backup_raw = old_raw if not mismatch else b'{"foreign":"pins"}\n'
            saved = {
                "old-pins.json": backup_raw,
                "old-proxy.mjs": old,
                "candidate-proxy.mjs": candidate,
                "relay-id.txt": ("a" * 64 + "\n").encode("ascii"),
                "sidecar-id.txt": ("b" * 64 + "\n").encode("ascii"),
            }
            if pending:
                (root / "native-status-upgrade.pending").write_bytes(b"pending")
            original = {
                "Id": "b" * 64,
                "Image": "sha256:" + "d" * 64,
                "State": {"Running": not stopped},
            }
            wss = mock.Mock()
            wss._pins.return_value = current_pins
            preflight = mock.Mock()
            preflight.read_fixed.return_value = candidate
            preflight.verify_completed_native3_history.return_value = True

            def current_name(name):
                if name == "hermes-h454-wss-proxy":
                    return original
                return None

            tx = SimpleNamespace(
                CHECKPOINT="synthetic-old-checkpoint",
                CHECKPOINT_NEW="synthetic-new-checkpoint",
                ROOT=root, BACKUP=root / "native-status-upgrade-evidence",
                LIVE_RELAY_ID="a" * 64,
                LIVE_SIDECAR_ID="b" * 64,
                LIVE_RELAY_IMAGE="sha256:" + "c" * 64,
                stage1=SimpleNamespace(
                    LEGACY_IMAGE="sha256:" + "d" * 64,
                    PROXY="hermes-h454-wss-proxy",
                    protected=mock.Mock(),
                    load_existing_wss=mock.Mock(return_value=wss),
                ),
                current_name=mock.Mock(side_effect=current_name),
                read_backup=mock.Mock(return_value=saved),
                checked_file=mock.Mock(return_value=old),
                verify_live=mock.Mock(),
            )
            with mock.patch.object(arch, "ROOT", root), \
                 mock.patch.object(arch, "ARCHIVE", root / "not-yet-archived"):
                callback(tx, preflight, old_raw)

    def test_restored_live_pair_plan_does_not_call_any_docker_mutator(self):
        def verify(tx, preflight, original):
            proof = arch.inspect_locked(tx, preflight, original)
            self.assertEqual(proof["original_pins_sha256"],
                             hashlib.sha256(original).hexdigest())
            self.assertFalse(proof["cutover_authorized"])
            tx.verify_live.assert_called_once()
            preflight.native_release.assert_called_once()
            self.assertEqual(tx.current_name.call_count, 3)
        self.with_fixture(verify)

    def test_changed_backup_refused_without_mutations(self):
        def verify(tx, preflight, original):
            with self.assertRaisesRegex(arch.RearmHold,
                                        "ORIGINAL_PAIR_NOT_RESTORED"):
                arch.inspect_locked(tx, preflight, original)
            tx.verify_live.assert_not_called()
        self.with_fixture(verify, mismatch=True)

    def test_unfinished_transaction_refused_before_reading_backup(self):
        def verify(tx, preflight, original):
            with self.assertRaisesRegex(arch.RearmHold,
                                        "UNFINISHED_WSS_TRANSACTION"):
                arch.inspect_locked(tx, preflight, original)
            tx.read_backup.assert_not_called()
        self.with_fixture(verify, pending=True)

    def test_stopped_original_sidecar_refused(self):
        def verify(tx, preflight, original):
            with self.assertRaisesRegex(arch.RearmHold,
                                        "ORIGINAL_SIDECAR_CHANGED"):
                arch.inspect_locked(tx, preflight, original)
        self.with_fixture(verify, stopped=True)

    def test_root_only_and_tty_required_before_rearm(self):
        with mock.patch.object(arch.os, "geteuid", return_value=65534):
            with self.assertRaisesRegex(arch.RearmHold, "ROOT_REQUIRED"):
                arch.root_operator()
        with mock.patch.object(arch.sys, "stdin") as stdin, \
             mock.patch.object(arch.sys, "stdout") as stdout:
            stdin.isatty.return_value = False
            stdout.isatty.return_value = False
            with self.assertRaisesRegex(arch.RearmHold,
                                        "OWNER_ROOT_TTY_REQUIRED"):
                arch.confirm({
                    "original_pins_sha256": "a" * 64,
                    "original_sidecar_id": "b" * 64,
                })


if __name__ == "__main__":
    unittest.main()
