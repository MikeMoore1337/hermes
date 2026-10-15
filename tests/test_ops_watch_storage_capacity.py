"""Offline-only read-only capacity checks; no production database."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ops_watch import storage_capacity as audit


class CapacityAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hermes-capacity-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.db = self.root / "incidents.sqlite3"
        self.db.write_bytes(b"metadata-test-only")
        self.db.chmod(0o600)

    def check(self):
        return audit.inspect_capacity(self.root)

    @staticmethod
    def filesystem(total: int, available: int):
        size = 4096
        return SimpleNamespace(f_frsize=size, f_blocks=total // size,
                               f_bavail=available // size)

    def test_small_database_and_healthy_disk_do_not_write(self):
        before = self.db.read_bytes()
        result = self.check()
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["reasons"], [])
        self.assertFalse(result["remediation_performed"])
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual([p.name for p in self.root.iterdir()], ["incidents.sqlite3"])

    def test_large_history_only_warns_and_keeps_evidence(self):
        with self.db.open("r+b") as stream:
            stream.truncate(audit.MAX_DB_BYTES)
        result = self.check()
        self.assertEqual(result["status"], "REVIEW")
        self.assertIn("sqlite_history_large", result["reasons"])
        self.assertEqual(self.db.stat().st_size, audit.MAX_DB_BYTES)

    def test_disk_threshold_checks_10_percent_and_two_gib(self):
        for total, free in [(40 << 30, 4 << 30), (10 << 30, 2 << 30),
                            (10 << 30, 3 << 30)]:
            with self.subTest(total=total, free=free):
                with patch.object(audit.os, "statvfs",
                                  return_value=self.filesystem(total, free)):
                    result = self.check()
                self.assertEqual(result["status"] == "REVIEW",
                                 free <= max(audit.MIN_FREE_BYTES, total // 10))

    def test_weak_permissions_are_rejected(self):
        self.db.chmod(0o644)
        with self.assertRaisesRegex(audit.StorageAuditDenied, "unsafe_database"):
            self.check()
        self.db.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(audit.StorageAuditDenied, "unsafe_directory"):
            self.check()

    def test_symlink_database_and_directory_are_rejected(self):
        self.db.rename(self.root / "real.db")
        self.db.symlink_to(self.root / "real.db")
        with self.assertRaisesRegex(audit.StorageAuditDenied, "unsafe_database"):
            self.check()
        link = self.root.parent / (self.root.name + "-link")
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(audit.StorageAuditDenied, "unsafe_directory"):
            audit.inspect_capacity(link)

    def test_missing_db_and_statvfs_error_are_unknown(self):
        with patch.object(audit.os, "statvfs", side_effect=OSError("PRIVATE_STRING")):
            with self.assertRaisesRegex(audit.StorageAuditDenied,
                                        "storage_metadata_unavailable"):
                self.check()
        self.db.unlink()
        with self.assertRaises(audit.StorageAuditDenied):
            self.check()

    def test_invalid_filesystem_metrics_are_rejected(self):
        cases = [self.filesystem(4096, 8192),
                 SimpleNamespace(f_frsize=0, f_blocks=1, f_bavail=0)]
        for bogus in cases:
            with self.subTest(bogus=bogus):
                with patch.object(audit.os, "statvfs", return_value=bogus):
                    with self.assertRaisesRegex(audit.StorageAuditDenied,
                                                "invalid_filesystem_metrics"):
                        self.check()

    def test_cli_dry_run_is_inert_and_errors_are_redacted(self):
        with patch.object(audit, "inspect_capacity") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")
        with patch.object(audit, "inspect_capacity",
                          side_effect=audit.StorageAuditDenied("PRIVATE_STRING")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
        self.assertNotIn("PRIVATE_STRING", out.getvalue())

    def test_cli_review_has_dedicated_exit_code(self):
        with patch.object(audit, "inspect_capacity",
                          return_value={"status": "REVIEW", "reasons": [],
                                        "remediation_performed": False}):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main(["--execute"]), 1)
        self.assertEqual(json.loads(out.getvalue())["status"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
