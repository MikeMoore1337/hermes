"""H454 owner-bounded three-host native pairing, disposable SQLite only."""
from __future__ import annotations

import sqlite3
from pathlib import Path
import tempfile
import time
import unittest

from scripts import h454_native_owner_pair as operator
from device_fabric.native_brc_enrollment import NAME

SQL = """
CREATE TABLE users (id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL);
CREATE TABLE devices (device_id TEXT PRIMARY KEY,user_id TEXT NOT NULL,
 name TEXT NOT NULL,platform TEXT,paused INTEGER,token_hash TEXT);
CREATE TABLE device_codes (device_code TEXT PRIMARY KEY,
 user_code TEXT UNIQUE NOT NULL,client_name TEXT NOT NULL,user_id TEXT,
 approved INTEGER NOT NULL DEFAULT 0,denied INTEGER NOT NULL DEFAULT 0,
 device_id TEXT,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
"""
NOW = int(time.time()*1000)
CODE = "ABCD-2345"
NEW_HEX = "b"*32


class NewOwnerNativePairing(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = sqlite3.connect(str(Path(temp.name) / "pairs.sqlite"),
                                  isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SQL)
        self.db.execute("INSERT INTO users VALUES (?,?)", ("owner", "admin"))
        # Old Win32 native remains revoked and paused, and sandbox baseline
        # must be byte-for-byte untouched after any approval or refusal.
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)", (
            "h454-win-01335a1f6e6705b4", "owner",
            "H15 Windows native read-only", "win32", 1, "0"*64))
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)", (
            "h15-hermes-ab005bc0e0ea", "owner", "Hermes sandbox",
            "linux/docker", 0, "1"*64))
        self.target = "windows"
        self._create(self.target)

    def _create(self, target):
        self.db.execute("DELETE FROM device_codes")
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)", (
            "synthetic-code-secret", CODE, NAME[target], None, 0, 0,
            None, NOW + 180_000, NOW))

    def _snapshot(self):
        return {
            "devices": [tuple(x) for x in self.db.execute(
                "SELECT * FROM devices ORDER BY device_id")],
            "users": [tuple(x) for x in self.db.execute(
                "SELECT * FROM users ORDER BY id")],
        }

    def test_new_win_and_both_linux_are_approved_without_any_existing_device_change(self):
        for target in ("windows", "hermes-vps", "yfc-vps"):
            with self.subTest(target=target):
                self._create(target)
                before = self._snapshot()
                row = operator.pending(self.db,target,CODE,NOW+1)
                did = operator.approve(
                    self.db,target=target,user_code=CODE,original=row,
                    new_hex=NEW_HEX,now_ms=NOW+1)
                self.assertEqual(did,operator.PREFIX[target]+NEW_HEX)
                pending_row = self.db.execute(
                    "SELECT * FROM device_codes WHERE user_code=?",(CODE,)
                ).fetchone()
                self.assertEqual(pending_row["approved"],1)
                self.assertEqual(pending_row["user_id"],"owner")
                self.assertEqual(pending_row["device_id"],did)
                self.assertEqual(self._snapshot(),before)
                with self.assertRaises(operator.PairDenied):
                    operator.approve(
                        self.db,target=target,user_code=CODE,
                        original=row,new_hex=NEW_HEX,now_ms=NOW+1)

    def test_old_native_or_occupied_new_identity_cannot_be_reused(self):
        row=operator.pending(self.db,self.target,CODE,NOW+1)
        for bad in ("0"*31,"0"*33,"A"*32,"x"*32,"1"*31 + "-",None):
            with self.subTest(bad=bad),self.assertRaises(operator.PairDenied):
                operator.approve(self.db,target="windows",user_code=CODE,
                                 original=row,new_hex=bad,now_ms=NOW+1)
        self.db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)", (
            operator.PREFIX["windows"]+NEW_HEX,"owner",NAME["windows"],
            "win32",0,"e"*64))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db,target="windows",user_code=CODE,
                             original=row,new_hex=NEW_HEX,now_ms=NOW+1)
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes").fetchone()[0],0)

    def test_atomic_wrong_owner_conflicting_pending_and_mismatched_target(self):
        original=operator.pending(self.db,self.target,CODE,NOW+1)
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)", (
            "other-code","EFGH-2345",NAME[self.target],None,0,0,None,
            NOW+180_000,NOW))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db,target=self.target,user_code=CODE,
                original=original,new_hex=NEW_HEX,now_ms=NOW+1)
        self.assertEqual(self.db.execute(
            "SELECT approved FROM device_codes WHERE user_code=?",(CODE,)
            ).fetchone()[0],0)
        self.db.execute("DELETE FROM device_codes WHERE user_code='EFGH-2345'")
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db,target="hermes-vps",user_code=CODE,
                             original=original,new_hex=NEW_HEX,now_ms=NOW+1)
        self.db.execute("DELETE FROM users")
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db,target=self.target,user_code=CODE,
                             original=original,new_hex=NEW_HEX,now_ms=NOW+1)

    def test_preexisting_approval_expiry_and_races_fail_closed(self):
        row=operator.pending(self.db,self.target,CODE,NOW+1)
        for update in (
            "UPDATE device_codes SET approved=1",
            "UPDATE device_codes SET denied=1",
            "UPDATE device_codes SET expires_at=0",
            "UPDATE device_codes SET client_name='other'",
        ):
            with self.subTest(update=update):
                self.db.execute(update)
                with self.assertRaises(operator.PairDenied):
                    operator.approve(self.db,target=self.target,user_code=CODE,
                                     original=row,new_hex=NEW_HEX,now_ms=NOW+1)
                self._create(self.target)
        self.db.execute("UPDATE device_codes SET created_at=?",(NOW+2,))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db,target=self.target,user_code=CODE,
                             original=row,new_hex=NEW_HEX,now_ms=NOW+3)


if __name__=="__main__":
    unittest.main()
