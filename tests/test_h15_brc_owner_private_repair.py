"""#454 bounded private native re-pair tests. ONLY temporary SQLite databases."""
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from scripts.h15_brc_owner_private_pair import DEVICE, PairDenied, find_pending
from scripts.h15_brc_owner_private_repair import DEVICE_ID, approve_existing, existing_owner_device

SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL, platform TEXT,
    created_at INTEGER NOT NULL, last_seen INTEGER, paused INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE device_codes (
    device_code TEXT PRIMARY KEY, user_code TEXT UNIQUE NOT NULL,
    client_name TEXT NOT NULL, user_id TEXT, approved INTEGER NOT NULL DEFAULT 0,
    denied INTEGER NOT NULL DEFAULT 0, device_id TEXT,
    expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);
"""


class OwnerNativeRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = sqlite3.connect(str(Path(self.temp.name) / "temporary.sqlite"),
                                  isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        now = int(time.time() * 1000)
        self.db.execute("INSERT INTO users VALUES (?,?)", ("admin-id", "admin"))
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)",
                        (DEVICE_ID, "admin-id", DEVICE, "a" * 64, "win32", now, now, 0))
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)",
                        ("safe-sandbox", "admin-id", "Sandbox", "b" * 64,
                         "linux/docker", now, now, 0))
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)", (
            "pending-secret", "ABCD-2345", DEVICE, None, 0, 0, None,
            now + 180_000, now))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def pending(self):
        return find_pending(self.db, "ABCD-2345")

    def test_repair_only_pending_code_not_existing_bearer_or_sandboxes(self):
        before = [tuple(row) for row in self.db.execute(
            "SELECT * FROM devices ORDER BY device_id")]
        approve_existing(self.db, "ABCD-2345", self.pending())
        after = [tuple(row) for row in self.db.execute(
            "SELECT * FROM devices ORDER BY device_id")]
        self.assertEqual(before, after)
        row = self.db.execute("SELECT * FROM device_codes").fetchone()
        self.assertEqual((row["approved"], row["user_id"], row["device_id"]),
                         (1, "admin-id", DEVICE_ID))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", row)

    def test_missing_native_device_denied(self):
        self.db.execute("DELETE FROM devices WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())

    def test_duplicate_native_device_denied(self):
        now = int(time.time() * 1000)
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)",
                        ("unexpected-native", "admin-id", DEVICE, "c" * 64,
                         "win32", now, now, 0))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())

    def test_paused_device_denied(self):
        self.db.execute("UPDATE devices SET paused=1 WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())

    def test_foreign_owner_denied(self):
        self.db.execute("UPDATE devices SET user_id='foreign' WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())

    def test_changed_platform_and_name_denied(self):
        for column, value in (("platform", "linux/docker"), ("name", "Imposter")):
            with self.subTest(column=column):
                old = self.db.execute(
                    f"SELECT {column} FROM devices WHERE device_id=?", (DEVICE_ID,)
                ).fetchone()[0]
                self.db.execute(f"UPDATE devices SET {column}=? WHERE device_id=?",
                                (value, DEVICE_ID))
                with self.assertRaises(PairDenied):
                    approve_existing(self.db, "ABCD-2345", self.pending())
                self.db.execute(f"UPDATE devices SET {column}=? WHERE device_id=?",
                                (old, DEVICE_ID))

    def test_invalid_token_hash_denied(self):
        self.db.execute("UPDATE devices SET token_hash='wrong' WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())

    def test_pending_request_changed_fails_closed(self):
        original = self.pending()
        self.db.execute("UPDATE device_codes SET device_code='different'")
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", original)
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes").fetchone()[0], 0)

    def test_expired_and_denied_code_fail_closed(self):
        for field, value in (("expires_at", 1), ("denied", 1)):
            with self.subTest(field=field):
                original = self.pending()
                self.db.execute(f"UPDATE device_codes SET {field}=?", (value,))
                with self.assertRaises(PairDenied):
                    approve_existing(self.db, "ABCD-2345", original)
                self.db.execute(f"UPDATE device_codes SET {field}=?",
                                (original[field],))

    def test_duplicate_admin_owner_denied(self):
        self.db.execute("DELETE FROM users")
        with self.assertRaises(PairDenied):
            existing_owner_device(self.db)

    def test_pending_approval_with_wrong_name_denied(self):
        self.db.execute("UPDATE device_codes SET client_name='Other'")
        with self.assertRaises(PairDenied):
            approve_existing(self.db, "ABCD-2345", self.pending())


if __name__ == "__main__":
    unittest.main()
