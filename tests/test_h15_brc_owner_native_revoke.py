"""#454 native-only bearer revocation contract; disposable SQLite only."""
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from scripts.h15_brc_owner_native_revoke import revoke_native, DEVICE_ID
from scripts.h15_brc_owner_private_pair import DEVICE, PairDenied

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


class NativeRevokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = sqlite3.connect(str(Path(self.temp.name) / "scratch.sqlite"),
                                  isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        now = int(time.time() * 1000)
        self.db.execute("INSERT INTO users VALUES (?,?)", ("owner-123", "admin"))
        rows = [(DEVICE_ID, "owner-123", DEVICE, "a" * 64, "win32", now, now, 0)]
        rows += [(f"sandbox-{i}", "owner-123", f"Sandbox {i}", hex(11+i)[2:]*64,
                  "linux/docker", now, now, 0) for i in range(3)]
        self.db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)", rows)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def native(self):
        return self.db.execute(
            "SELECT * FROM devices WHERE device_id=?", (DEVICE_ID,)
        ).fetchone()

    def sandbox_rows(self):
        return [tuple(x) for x in self.db.execute(
            "SELECT * FROM devices WHERE device_id<>? ORDER BY device_id",
            (DEVICE_ID,)
        )]

    def test_revoke_preserves_device_and_sandboxes(self):
        native_before = self.native()
        sandboxes_before = self.sandbox_rows()
        revoke_native(self.db)
        native_after = self.native()
        self.assertEqual(native_after["device_id"], native_before["device_id"])
        self.assertEqual(native_after["user_id"], native_before["user_id"])
        self.assertEqual(native_after["name"], native_before["name"])
        self.assertEqual(native_after["paused"], 1)
        self.assertEqual(len(native_after["token_hash"]), 64)
        self.assertNotEqual(native_after["token_hash"], native_before["token_hash"])
        self.assertEqual(self.sandbox_rows(), sandboxes_before)
        self.assertFalse(self.db.in_transaction)

    def test_replay_refused(self):
        revoke_native(self.db)
        old = tuple(self.native())
        with self.assertRaises(PairDenied):
            revoke_native(self.db)
        self.assertEqual(tuple(self.native()), old)

    def test_existing_device_wrong_owner_refused(self):
        self.db.execute("UPDATE devices SET user_id='foreign' WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_wrong_platform_refused(self):
        self.db.execute("UPDATE devices SET platform='linux/docker' WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_missing_native_refused(self):
        self.db.execute("DELETE FROM devices WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_native_duplicate_name_refused(self):
        now = int(time.time() * 1000)
        self.db.execute(
            "UPDATE devices SET name=? WHERE device_id='sandbox-0'", (DEVICE,)
        )
        before = tuple(self.native())
        with self.assertRaises(PairDenied):
            revoke_native(self.db)
        self.assertEqual(tuple(self.native()), before)

    def test_requires_all_three_sandboxes(self):
        self.db.execute("DELETE FROM devices WHERE device_id='sandbox-2'")
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_pending_pairing_refuses_no_mutation(self):
        now = int(time.time() * 1000)
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)",
                        ("pending", "ABCD-2345", DEVICE, None, 0, 0, None,
                         now+180000, now))
        before = tuple(self.native())
        with self.assertRaises(PairDenied):
            revoke_native(self.db)
        self.assertEqual(tuple(self.native()), before)

    def test_owner_username_missing_refused(self):
        self.db.execute("DELETE FROM users")
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_bad_token_hash_refused(self):
        self.db.execute("UPDATE devices SET token_hash=? WHERE device_id=?",
                        ("invalid", DEVICE_ID))
        with self.assertRaises(PairDenied):
            revoke_native(self.db)

    def test_paused_native_refused(self):
        self.db.execute("UPDATE devices SET paused=1 WHERE device_id=?", (DEVICE_ID,))
        with self.assertRaises(PairDenied):
            revoke_native(self.db)


if __name__ == "__main__":
    unittest.main()
