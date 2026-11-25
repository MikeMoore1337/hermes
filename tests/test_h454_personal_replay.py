"""Durable personal READ replay claims on disposable local files."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric import personal_replay as replay
from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h15_native_windows_outbound as outbound


class PersonalReplayTests(unittest.TestCase):
    def test_transport_never_dispatches_a_claimed_or_failed_request(self):
        message = {"type": "call", "id": "request-one", "tool": "native_file_stat",
                   "args": {"project": "hermes", "relative": "README.md"}}
        result = {"status": "ok", "project": "hermes", "relative": "README.md",
                  "action": "stat", "kind": "file", "size_bytes": 3}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = replay.PersonalReplay(root, create=True)
            session = mcp.McpSession()
            session.initialized = True
            with patch.object(mcp.native, "handle_native_request", return_value=result) as read:
                self.assertIsNotNone(outbound.safe_call(session, message, set(), ledger.claim))
                self.assertIsNone(outbound.safe_call(session, message, set(), replay.PersonalReplay(root).claim))
                with self.assertRaises(outbound.NativeTransportDenied):
                    outbound.safe_call(session, {**message, "id": "other"}, set(),
                                       lambda _: (_ for _ in ()).throw(replay.ReplayDenied()))
            read.assert_called_once()

    def test_duplicate_remains_denied_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = replay.PersonalReplay(root, create=True)
            self.assertTrue(ledger.claim("request-one"))
            self.assertFalse(replay.PersonalReplay(root).claim("request-one"))
            self.assertTrue(replay.PersonalReplay(root).claim("request-two"))
            self.assertNotIn(b"request-one", (root / "read-replay.sqlite3").read_bytes())

    def test_concurrent_duplicate_is_reserved_only_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            replay.PersonalReplay(root, create=True)
            with ThreadPoolExecutor(max_workers=4) as workers:
                results = list(workers.map(lambda _: replay.PersonalReplay(root).claim("same-id"), range(4)))
            self.assertEqual(results.count(True), 1)
            self.assertEqual(results.count(False), 3)

    def test_existing_fifty_thousand_claims_do_not_block_new_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = replay.PersonalReplay(root, create=True)
            with closing(sqlite3.connect(ledger.path)) as db:
                db.executemany("INSERT INTO claimed(id) VALUES(?)",
                               ((i.to_bytes(32, "big"),) for i in range(50_000)))
                db.commit()
            self.assertTrue(ledger.claim("after-existing-claims"))
            self.assertFalse(replay.PersonalReplay(root).claim("after-existing-claims"))
            code = ("from pathlib import Path; import sys; "
                    "from device_fabric.personal_replay import PersonalReplay; "
                    "print(PersonalReplay(Path(sys.argv[1])).claim('after-existing-claims'))")
            result = subprocess.run([sys.executable, "-B", "-c", code, str(root)],
                                    check=True, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self.assertEqual(result.stdout.strip(), "False")

    def test_missing_truncated_and_capacity_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(replay.ReplayDenied):
                replay.PersonalReplay(root)
            ledger = replay.PersonalReplay(root, create=True)
            self.assertTrue(ledger.claim("one"))
            size_limit = ledger.path.stat().st_size
            with patch.object(replay, "MAX_BYTES", size_limit):
                for index in range(1000):
                    try:
                        ledger.claim(f"fill-{index}")
                    except replay.ReplayDenied:
                        break
                else:
                    self.fail("the database exceeded its page budget")
                self.assertLessEqual(ledger.path.stat().st_size, size_limit)
                self.assertFalse(ledger.claim("one"))
            (root / "read-replay.sqlite3").write_bytes(b"")
            with self.assertRaises(replay.ReplayDenied):
                replay.PersonalReplay(root)
