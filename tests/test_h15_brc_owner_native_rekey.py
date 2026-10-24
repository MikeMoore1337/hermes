"""#454 existing-native rekey: synthetic SQLite only, never production."""
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from scripts.h15_brc_owner_private_pair import DEVICE, PairDenied
from scripts.h15_brc_owner_native_rekey import NATIVE_ID, approve_rekey, verify_existing

SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL);
CREATE TABLE devices (device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
 name TEXT NOT NULL, platform TEXT, paused INTEGER NOT NULL DEFAULT 0,
 token_hash TEXT UNIQUE NOT NULL);
CREATE TABLE device_codes (device_code TEXT PRIMARY KEY,
 user_code TEXT UNIQUE NOT NULL, client_name TEXT NOT NULL,
 user_id TEXT, approved INTEGER NOT NULL DEFAULT 0,
 denied INTEGER NOT NULL DEFAULT 0, device_id TEXT,
 expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
"""


class RekeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(str(Path(self.tmp.name) / "fixture.db"),
                                    isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        now = int(time.time() * 1000)
        self.conn.execute("INSERT INTO users VALUES (?,?)", ("owner1", "admin"))
        self.conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)",
                          (NATIVE_ID, "owner1", DEVICE, "win32", 0, "OLD_HASH"))
        self.conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)",
                          ("sandbox1", "owner1", "sandbox", "linux/docker", 0, "SANDBOX_HASH"))
        self.conn.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)",
                          ("private-unpublished", "ABCD-2345", DEVICE, None, 0, 0,
                           None, now + 180000, now))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def row(self):
        return self.conn.execute(
            "SELECT * FROM device_codes WHERE user_code='ABCD-2345'"
        ).fetchone()

    def approve(self):
        approve_rekey(self.conn, "ABCD-2345", self.row())

    def test_one_row_only_and_other_devices_untouched(self):
        original = [tuple(r) for r in
                    self.conn.execute("SELECT * FROM devices ORDER BY device_id")]
        self.approve()
        after = self.row()
        self.assertEqual((after["approved"], after["user_id"], after["device_id"]),
                         (1, "owner1", NATIVE_ID))
        self.assertEqual(original, [tuple(r) for r in
                         self.conn.execute("SELECT * FROM devices ORDER BY device_id")])
        with self.assertRaises(PairDenied):
            self.approve()

    def test_missing_owner_denied(self):
        self.conn.execute("DELETE FROM users")
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.row()["approved"], 0)

    def test_missing_or_duplicate_native_denied(self):
        self.conn.execute("DELETE FROM devices WHERE device_id=?", (NATIVE_ID,))
        with self.assertRaises(PairDenied):
            self.approve()
        self.conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)",
                          (NATIVE_ID, "owner1", DEVICE, "win32", 0, "OLD_HASH"))
        self.conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)",
                          ("fake", "owner1", DEVICE, "win32", 0, "OTHER_HASH"))
        with self.assertRaises(PairDenied):
            self.approve()

    def test_wrong_owner_platform_paused_denied(self):
        for key, bad, restore in [
            ("user_id", "intruder", "owner1"),
            ("platform", "linux/docker", "win32"),
            ("paused", 1, 0),
        ]:
            self.conn.execute(f"UPDATE devices SET {key}=? WHERE device_id=?",
                              (bad, NATIVE_ID))
            with self.assertRaises(PairDenied):
                self.approve()
            self.conn.execute(f"UPDATE devices SET {key}=? WHERE device_id=?",
                              (restore, NATIVE_ID))
        self.assertEqual(self.row()["approved"], 0)

    def test_expired_denied_or_wrong_client_denied(self):
        for query, args in [
            ("UPDATE device_codes SET expires_at=?", (int(time.time() * 1000) - 1000,)),
            ("UPDATE device_codes SET denied=1", ()),
            ("UPDATE device_codes SET client_name='OTHER'", ()),
        ]:
            self.conn.execute(query, args)
            with self.assertRaises(PairDenied):
                self.approve()
            self.conn.execute("DELETE FROM device_codes")
            now = int(time.time() * 1000)
            self.conn.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)",
                              ("private-unpublished", "ABCD-2345", DEVICE, None,
                               0, 0, None, now + 180000, now))

    def test_changed_request_rolls_back(self):
        before = self.row()
        self.conn.execute(
            "UPDATE device_codes SET device_code='other' WHERE user_code='ABCD-2345'")
        with self.assertRaises(PairDenied):
            approve_rekey(self.conn, "ABCD-2345", before)
        self.assertEqual(self.row()["approved"], 0)

    def test_old_hash_not_read_or_changed_by_operator(self):
        self.assertEqual(verify_existing(self.conn), "owner1")
        self.approve()
        rows = self.conn.execute(
            "SELECT device_id,token_hash FROM devices ORDER BY device_id"
        ).fetchall()
        self.assertEqual([(x["device_id"], x["token_hash"]) for x in rows],
                         [(NATIVE_ID, "OLD_HASH"), ("sandbox1", "SANDBOX_HASH")])


if __name__ == "__main__":
    unittest.main()
