"""Offline SQLite regression checks for owner-only BRC pairing (#454).

Uses temporary scratch data; never touches /var/lib/hermes-brc-relay.
"""
import os
import sqlite3
import tempfile
import time
import unittest

if os.name == "posix":
    import pty
from pathlib import Path

from scripts.h15_brc_owner_private_pair import approve, find_pending, PairDenied, DEVICE, prompt_tty

SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL);
CREATE TABLE devices (device_id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE device_codes (device_code TEXT PRIMARY KEY, user_code TEXT UNIQUE NOT NULL,
client_name TEXT NOT NULL, user_id TEXT, approved INTEGER NOT NULL DEFAULT 0,
denied INTEGER NOT NULL DEFAULT 0, device_id TEXT, expires_at INTEGER NOT NULL,
created_at INTEGER NOT NULL);
"""


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = sqlite3.connect(str(Path(self.tmp.name) / "relay.sqlite"),
                                  isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        now = int(time.time() * 1000)
        self.db.execute("INSERT INTO users VALUES (?,?)", ("owner-id", "admin"))
        self.db.execute("INSERT INTO devices VALUES (?,?)", ("old", "Existing device"))
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)", (
            "secret-device-code", "ABCD-2345", DEVICE, None, 0, 0, None,
            now + 180_000, now))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_one_atomic_row_only(self):
        before = [tuple(x) for x in self.db.execute("SELECT * FROM devices").fetchall()]
        row = find_pending(self.db, "ABCD-2345")
        approve(self.db, "ABCD-2345", row)
        after = self.db.execute("SELECT * FROM device_codes").fetchone()
        self.assertEqual(after["approved"], 1)
        self.assertEqual(after["user_id"], "owner-id")
        self.assertIsNone(after["device_id"])
        self.assertEqual(before, [tuple(x) for x in
                                  self.db.execute("SELECT * FROM devices").fetchall()])
        with self.assertRaises(PairDenied):
            approve(self.db, "ABCD-2345", row)

    def test_wrong_name(self):
        self.db.execute("UPDATE device_codes SET client_name=?", ("Unexpected",))
        with self.assertRaises(PairDenied):
            find_pending(self.db, "ABCD-2345")

    def test_expired(self):
        self.db.execute("UPDATE device_codes SET expires_at=?",
                        (int(time.time() * 1000) - 1000,))
        with self.assertRaises(PairDenied):
            find_pending(self.db, "ABCD-2345")

    def test_mismatched_owner(self):
        self.db.execute("DELETE FROM users")
        with self.assertRaises(PairDenied):
            approve(self.db, "ABCD-2345", find_pending(self.db, "ABCD-2345"))
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes").fetchone()[0], 0)

    def test_existing_native(self):
        self.db.execute("INSERT INTO devices VALUES (?,?)", ("already", DEVICE))
        with self.assertRaises(PairDenied):
            approve(self.db, "ABCD-2345", find_pending(self.db, "ABCD-2345"))
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes").fetchone()[0], 0)

    def test_changed_request_atomic_abort(self):
        row = find_pending(self.db, "ABCD-2345")
        self.db.execute("UPDATE device_codes SET device_code=?", ("changed",))
        with self.assertRaises(PairDenied):
            approve(self.db, "ABCD-2345", row)
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes").fetchone()[0], 0)

    @unittest.skipUnless(os.name == "posix", "requires real POSIX PTY")
    def test_nonseekable_tty_prompt(self):
        """Real PTY streams are non-seekable: separate r and w must work."""
        master, slave = pty.openpty()
        try:
            with os.fdopen(os.dup(slave), "r", encoding="ascii") as reader, \
                 os.fdopen(os.dup(slave), "w", encoding="ascii", buffering=1) as writer:
                self.assertFalse(reader.seekable())
                self.assertFalse(writer.seekable())
                os.write(master, b"ABCD-2345" + bytes((10,)))
                self.assertEqual(prompt_tty(reader, writer, "Enter code: ", 64),
                                 "ABCD-2345")
                os.write(master, b"APPROVE H454 ABCD-2345" + bytes((10,)))
                self.assertEqual(prompt_tty(reader, writer, "Confirm: ", 128),
                                 "APPROVE H454 ABCD-2345")
        finally:
            os.close(master)
            os.close(slave)

    def test_denied_request(self):
        self.db.execute("UPDATE device_codes SET denied=1")
        with self.assertRaises(PairDenied):
            find_pending(self.db, "ABCD-2345")


if __name__ == "__main__":
    unittest.main()
