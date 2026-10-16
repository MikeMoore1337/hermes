"""H-02 read-only SQLite history capacity and manual-archive planning."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch.core import InputError
from ops_watch.retention_audit import SCHEMA, assess, main
from ops_watch.state_store import DATABASE, persist

NOW = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
INCIDENT = [{"code": "timer_inactive", "fingerprint": "ops:timer_inactive"}]


class RetentionAuditTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        self.root.chmod(0o700)
        persist(self.root, INCIDENT, lambda: [], observed=NOW)
        self.path = self.root / DATABASE

    def test_read_only_low_volume_without_deletion(self):
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = assess(self.root, review_after_acks=1, review_after_bytes=4096 * 50)
        after = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["status"], "MONITOR_ONLY")
        self.assertEqual(result["event_counts"]["total"], 1)
        self.assertEqual(result["event_counts"]["unacknowledged"], 1)
        self.assertTrue(result["outstanding_preservation_required"])
        for name in ("backup_verified", "archive_written", "events_deleted",
                     "sqlite_modified", "telegram_sent", "production_retention_approved"):
            self.assertIs(result[name], False)

    def test_many_acked_events_trigger_manual_review_not_deletion(self):
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TABLE delivery_receipts ("
                "event_id INTEGER PRIMARY KEY, status TEXT NOT NULL, "
                "lease_token TEXT NOT NULL, lease_until TEXT NOT NULL, "
                "attempts INTEGER NOT NULL, telegram_message_id INTEGER, "
                "acknowledged_at TEXT)"
            )
            db.execute(
                "INSERT INTO delivery_receipts(event_id,status,lease_token,lease_until,"
                "attempts,telegram_message_id,acknowledged_at) "
                "VALUES(1,'acknowledged','synthetic',?,1,1,?)",
                (NOW.isoformat(), NOW.isoformat()),
            )
        before = self.path.read_bytes()
        result = assess(self.root, review_after_acks=1, review_after_bytes=4096 * 50)
        self.assertEqual(result["status"], "MANUAL_ARCHIVE_PLAN_REQUIRED")
        self.assertEqual(result["event_counts"]["acknowledged"], 1)
        self.assertFalse(result["outstanding_preservation_required"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(result["events_deleted"])

    def test_file_size_alone_triggers_manual_review(self):
        result = assess(self.root, review_after_acks=1000, review_after_bytes=4096)
        self.assertEqual(result["status"], "MANUAL_ARCHIVE_PLAN_REQUIRED")
        self.assertEqual(result["event_counts"]["acknowledged"], 0)
        self.assertTrue(result["outstanding_preservation_required"])

    def test_invalid_thresholds_do_not_trigger_sqlite(self):
        for a, b in ((True, 4096), (0, 4096), (1, False),
                     (1, 4095), (1_000_001, 4096), (1, 2_000_000_000)):
            with self.subTest(a=a, b=b), self.assertRaisesRegex(
                InputError, "retention_policy_invalid"
            ):
                assess(self.root, review_after_acks=a, review_after_bytes=b)

    def test_symlink_and_insecure_permissions_denied(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
            assess(self.root)
        self.path.chmod(0o600)
        other = self.root / "original"
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaisesRegex(InputError, "delivery_storage_unavailable|unsafe_outbox_db"):
            assess(self.root)
        self.assertTrue(other.is_file())

    def test_no_database_returns_generic_storage_error(self):
        self.path.unlink()
        with self.assertRaises(InputError):
            assess(self.root)

    def test_cli_is_dry_by_default_without_touching_target(self):
        from io import StringIO
        with patch("ops_watch.retention_audit.TARGET", self.root):
            with patch("sys.stdout", new_callable=StringIO) as out:
                self.assertEqual(main([]), 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")
            with patch("sys.stdout", new_callable=StringIO) as out:
                self.assertEqual(main(["--inspect"]), 0)
            packet = json.loads(out.getvalue())
            self.assertEqual(packet["source"], "CANONICAL_LOCAL_SQLITE_READ_ONLY")
            self.assertNotIn("fingerprint", json.dumps(packet))
            self.assertNotIn("timer_inactive", json.dumps(packet))

    def test_no_telegram_or_external_api_imports(self):
        import inspect
        import ops_watch.retention_audit as module
        source = inspect.getsource(module)
        for forbidden in ("import requests", "import urllib", "send_one(", "delete from",
                          "vacuum ", "os.system(", "subprocess."):
            self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
