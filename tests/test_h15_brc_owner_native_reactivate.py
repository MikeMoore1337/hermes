"""Owner-only native device reactivation must not affect other devices.

All tests use an ephemeral SQLite database; no production credentials or calls.
"""
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from scripts.h15_brc_owner_private_pair import DEVICE, PairDenied, find_pending
from scripts.h15_brc_owner_private_repair import DEVICE_ID, existing_owner_device
from scripts.h15_brc_owner_native_reactivate import approve_revoked

SCHEMA = """
CREATE TABLE users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL);
CREATE TABLE devices(device_id TEXT PRIMARY KEY,user_id TEXT,name TEXT,
token_hash TEXT UNIQUE,platform TEXT,created_at INTEGER,last_seen INTEGER,
paused INTEGER NOT NULL DEFAULT 0);
CREATE TABLE device_codes(device_code TEXT PRIMARY KEY,user_code TEXT UNIQUE,
client_name TEXT,user_id TEXT,approved INTEGER DEFAULT 0,
denied INTEGER DEFAULT 0,device_id TEXT,expires_at INTEGER,created_at INTEGER);
"""

class RevokedNativeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.db = sqlite3.connect(str(Path(self.folder.name)/"db.sqlite"), isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        now=int(time.time()*1000)
        self.db.execute("INSERT INTO users VALUES (?,?)",("owner","admin"))
        values=[(DEVICE_ID,"owner",DEVICE,"a"*64,"win32",now,now,1)]
        values += [(f"sandbox-{n}","owner",f"Sandbox {n}",str(n+2)*64,
                    "linux/docker",now,now,0) for n in range(3)]
        self.db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)",values)
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)",
                        ("code-1","ABCD-2345",DEVICE,None,0,0,None,now+180000,now))

    def state(self):
        return (tuple(tuple(r) for r in self.db.execute(
            "SELECT * FROM devices ORDER BY device_id")),
                tuple(tuple(r) for r in self.db.execute(
            "SELECT * FROM device_codes ORDER BY device_code")))

    def approve(self):
        approve_revoked(self.db,"ABCD-2345",find_pending(self.db,"ABCD-2345"))

    def test_single_activation_and_no_replay(self):
        before=self.state()
        with self.assertRaises(PairDenied):
            existing_owner_device(self.db)
        self.approve()
        after=self.state()
        self.assertEqual(after[0][1:],before[0][1:])
        native=self.db.execute(
            "SELECT paused,token_hash FROM devices WHERE device_id=?",(DEVICE_ID,)
        ).fetchone()
        self.assertEqual(native["paused"],0)
        self.assertNotEqual(native["token_hash"],"a"*64)
        self.assertEqual(len(native["token_hash"]),64)
        code=self.db.execute("SELECT approved,device_id FROM device_codes").fetchone()
        self.assertEqual(tuple(code),(1,DEVICE_ID))
        with self.assertRaises(PairDenied):
            self.approve()

    def test_paused_required(self):
        self.db.execute("UPDATE devices SET paused=0 WHERE device_id=?",(DEVICE_ID,))
        before=self.state()
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.state(),before)

    def test_duplicate_name_and_wrong_owner_denied(self):
        self.db.execute("UPDATE devices SET name=? WHERE device_id='sandbox-0'",(DEVICE,))
        before=self.state()
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.state(),before)

    def test_other_pending_code_denied(self):
        now=int(time.time()*1000)
        self.db.execute("INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)",
            ("code-2","EFGH-3456",DEVICE,None,0,0,None,now+180000,now))
        before=self.state()
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.state(),before)

    def test_missing_sandbox_denied(self):
        self.db.execute("DELETE FROM devices WHERE device_id='sandbox-1'")
        before=self.state()
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.state(),before)

    def test_expired_code_denied(self):
        self.db.execute("UPDATE device_codes SET expires_at=1")
        before=self.state()
        original=self.db.execute("SELECT * FROM device_codes").fetchone()
        with self.assertRaises(PairDenied):
            approve_revoked(self.db,"ABCD-2345",original)
        self.assertEqual(self.state(),before)

    def test_wrong_platform_denied(self):
        self.db.execute("UPDATE devices SET platform='linux/docker' WHERE device_id=?",(DEVICE_ID,))
        before=self.state()
        with self.assertRaises(PairDenied):
            self.approve()
        self.assertEqual(self.state(),before)

if __name__=="__main__":
    unittest.main()
