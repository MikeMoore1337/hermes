"""H-15 SQLite recovery rehearsal: offline, no owner DB, no Docker."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import os
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REHEARSAL = ROOT / "deploy/h15/rehearse-restore.py"
BACKUP = ROOT / "deploy/h15/backup-relay.py"


def load(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class H15RestoreRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load(REHEARSAL, "h15_disposable_rehearsal")
        cls.backup_module = load(BACKUP, "h15_source_snapshot")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "state"
        self.backups = self.root / "backups"
        self.scratch = self.root / "scratch"
        for directory in (self.source, self.backups, self.scratch):
            directory.mkdir(mode=0o700)
        self.database = self.source / "relay.sqlite"

    def make_backup(self):
        with sqlite3.connect(self.database) as conn:
            conn.execute("CREATE TABLE oauth_tokens (token TEXT NOT NULL)")
            conn.execute("INSERT INTO oauth_tokens VALUES ('secret-owner-data-do-not-print')")
        return self.backup_module.backup_sqlite(self.database, self.backups)

    def test_disposable_restore_preserves_integrity_and_original_bytes(self):
        snapshot = self.make_backup()
        before = snapshot.read_bytes()
        report = self.module.rehearse_restore(snapshot, self.scratch)
        self.assertEqual(report["status"], "PASS_DISPOSABLE_ONLY")
        self.assertFalse(report["live_sqlite_modified"])
        self.assertFalse(report["restored_into_production"])
        self.assertFalse(report["oauth_or_mcp_enabled"])
        self.assertEqual(report["tables_checked"], 1)
        self.assertEqual(snapshot.read_bytes(), before)
        with sqlite3.connect(snapshot) as db:
            self.assertEqual(db.execute("SELECT token FROM oauth_tokens").fetchone()[0],
                             "secret-owner-data-do-not-print")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_wal_uncheckpointed_live_write_is_included_in_atomic_backup(self):
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        connection.execute("CREATE TABLE oauth_tokens (token TEXT)")
        connection.execute("INSERT INTO oauth_tokens VALUES ('first')")
        connection.commit()
        connection.execute("INSERT INTO oauth_tokens VALUES ('uncheckpointed')")
        connection.commit()
        self.assertTrue(Path(str(self.database) + "-wal").exists())
        snapshot = self.backup_module.backup_sqlite(self.database, self.backups)
        rehearsal = self.module.rehearse_restore(snapshot, self.scratch)
        self.assertEqual(rehearsal["tables_checked"], 1)
        with sqlite3.connect(snapshot) as check:
            self.assertEqual(check.execute("SELECT count(*) FROM oauth_tokens").fetchone()[0], 2)
        self.assertFalse(Path(str(snapshot) + "-wal").exists())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_corrupt_backup_rejected_without_persistent_temp_files(self):
        snapshot = self.make_backup()
        snapshot.write_bytes(b"secret corrupt backup")
        with self.assertRaises(self.module.RestoreRehearsalDenied):
            self.module.rehearse_restore(snapshot, self.scratch)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_snapshot_sidecar_symlinks_or_insecure_modes_are_refused(self):
        snapshot = self.make_backup()
        Path(str(snapshot) + "-wal").write_bytes(b"unexpected")
        with self.assertRaisesRegex(self.module.RestoreRehearsalDenied,
                                    "unexpected_snapshot_sidecar"):
            self.module.rehearse_restore(snapshot, self.scratch)
        Path(str(snapshot) + "-wal").unlink()

        snapshot.chmod(0o644)
        with self.assertRaisesRegex(self.module.RestoreRehearsalDenied,
                                    "unsafe_snapshot_owner_or_size"):
            self.module.rehearse_restore(snapshot, self.scratch)
        snapshot.chmod(0o600)

        linked = self.backups / "linked.sqlite3"
        linked.symlink_to(snapshot)
        with self.assertRaises(self.module.RestoreRehearsalDenied):
            self.module.rehearse_restore(linked, self.scratch)

        self.scratch.chmod(0o755)
        with self.assertRaises(self.module.RestoreRehearsalDenied):
            self.module.rehearse_restore(snapshot, self.scratch)

    def test_same_directory_and_no_schema_rejected(self):
        snapshot = self.make_backup()
        with self.assertRaisesRegex(self.module.RestoreRehearsalDenied,
                                    "scratch_must_be_separate_from_backup"):
            self.module.rehearse_restore(snapshot, self.backups)
        snapshot.unlink()
        with sqlite3.connect(snapshot) as empty:
            self.assertEqual(empty.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        snapshot.chmod(0o600)
        with self.assertRaises(self.module.RestoreRehearsalDenied):
            self.module.rehearse_restore(snapshot, self.scratch)

    def test_cli_no_sensitive_data_printed_and_no_restore_to_production(self):
        snapshot = self.make_backup()
        proc = subprocess.run(
            ["python3", str(REHEARSAL), "--snapshot", str(snapshot),
             "--scratch-dir", str(self.scratch)],
            text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("H15_SQLITE_RESTORE_REHEARSAL=PASS_DISPOSABLE_ONLY", proc.stdout)
        self.assertIn("H15_SQLITE_PRODUCTION_RESTORE=NO", proc.stdout)
        self.assertNotIn("secret-owner-data", proc.stdout + proc.stderr)
        self.assertNotIn(str(snapshot), proc.stdout + proc.stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])
        snapshot.write_bytes(b"secret-owner-data-do-not-print")
        bad = subprocess.run(
            ["python3", str(REHEARSAL), "--snapshot", str(snapshot),
             "--scratch-dir", str(self.scratch)],
            text=True, capture_output=True,
        )
        self.assertEqual(bad.returncode, 2)
        self.assertNotIn("secret-owner-data", bad.stdout + bad.stderr)

    def test_rehearsal_script_never_targets_live_database_or_mcp(self):
        source = REHEARSAL.read_text()
        self.assertNotIn("/var/lib/hermes-brc-relay/", source)
        self.assertNotIn("docker run", source)
        self.assertNotIn("systemctl", source)
        self.assertNotIn("DELETE FROM", source)
        self.assertIn("immutable=1", source)
        self.assertIn("TemporaryDirectory", source)


if __name__ == "__main__":
    unittest.main()
