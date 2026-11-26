"""Synthetic SQLite tests for the separate personal Windows owner approval."""
import sqlite3
import unittest
import os

if os.name != "nt":
    from scripts import h454_windows_personal_owner_pair as operator

NOW = 1_700_000_000_000
CODE = "ABCD-2345"
HEX = "a" * 32


@unittest.skipIf(os.name == "nt", "owner operator runs on Linux")
class PersonalOwnerPairTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
          CREATE TABLE users(id TEXT, username TEXT);
          CREATE TABLE devices(device_id TEXT, user_id TEXT, name TEXT, token_hash TEXT);
          CREATE TABLE device_codes(device_code TEXT, user_code TEXT, client_name TEXT,
            user_id TEXT, approved INTEGER, denied INTEGER, device_id TEXT,
            expires_at INTEGER, created_at INTEGER);
        """)
        self.db.execute("INSERT INTO users VALUES (?,?)", ("owner", "admin"))
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?)", (
            "h454-win-native-" + "b" * 32, "owner", "H454 Windows native read-only", "synthetic-hash"))
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)", (
            "synthetic-device-code", CODE, operator.NAME, None, 0, 0, None, NOW + 180_000, NOW))

    def test_only_pending_row_is_bound_and_old_read_only_device_is_unchanged(self):
        before = [tuple(row) for row in self.db.execute("SELECT * FROM devices")]
        row = operator.pending(self.db, CODE, NOW + 1)
        device = operator.approve(self.db, user_code=CODE, original=row, new_hex=HEX, now_ms=NOW + 1)
        self.assertEqual(device, operator.PREFIX + HEX)
        self.assertEqual(tuple(self.db.execute(
            "SELECT approved,user_id,device_id FROM device_codes").fetchone()), (1, "owner", device))
        self.assertEqual([tuple(row) for row in self.db.execute("SELECT * FROM devices")], before)
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db, user_code=CODE, original=row, new_hex=HEX, now_ms=NOW + 1)

    def test_expiry_other_profile_and_existing_personal_device_are_denied(self):
        row = operator.pending(self.db, CODE, NOW + 1)
        for bad in ("x" * 32, "A" * 32, "a" * 31, None):
            with self.subTest(bad=bad), self.assertRaises(operator.PairDenied):
                operator.approve(self.db, user_code=CODE, original=row, new_hex=bad, now_ms=NOW + 1)
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?)", (
            operator.PREFIX + HEX, "owner", operator.NAME, "synthetic-hash"))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db, user_code=CODE, original=row, new_hex=HEX, now_ms=NOW + 1)
        self.db.execute("DELETE FROM devices WHERE name=?", (operator.NAME,))
        self.db.execute("UPDATE device_codes SET client_name=?", ("H454 Windows native read-only",))
        with self.assertRaises(operator.PairDenied):
            operator.pending(self.db, CODE, NOW + 1)
        self.db.execute("UPDATE device_codes SET client_name=?, expires_at=?", (operator.NAME, NOW + 1000))
        with self.assertRaises(operator.PairDenied):
            operator.pending(self.db, CODE, NOW + 1)


if __name__ == "__main__":
    unittest.main()
