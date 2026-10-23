"""Hermes #474/#475: deterministic no-model crash/replay proofs for SQLite.

No real LLM, worker, network call, owner grant or production DB is touched.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from scripts.orchestration_pre_call_reservation_probe import (
    EXPIRED, FIRST_ONLY, InvalidFixture, NO_APPROVAL, REPLAY_BLOCKED,
    initialize_temporary_fixture, read_record, reserve_once,
)

REV = "a" * 40
REV2 = "b" * 40


class OneShotReservationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="hermes-474-475-once-")
        self.addCleanup(self.scratch.cleanup)
        self.db = Path(self.scratch.name) / "reservation.sqlite"
        initialize_temporary_fixture(self.db)

    def reserve(self, **overrides):
        args = dict(db_path=self.db, operation_key="stable-operation-123",
                    revision=REV, approval_id="verified-by-external-test",
                    grant_verified=True, grant_expires_at=2000, now=1000)
        args.update(overrides)
        return reserve_once(**args)

    def test_first_and_repeated_attempt(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.reserve(), REPLAY_BLOCKED)
        self.assertEqual(read_record(self.db, "stable-operation-123"),
                         ("stable-operation-123", REV,
                          "verified-by-external-test", 1000))

    def test_revision_change_does_not_reset_attempt(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.reserve(revision=REV2), REPLAY_BLOCKED)

    def test_approval_change_does_not_reset_attempt(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.reserve(approval_id="different-grant"),
                         REPLAY_BLOCKED)

    def test_expiry_before_reservation_does_not_write(self):
        self.assertEqual(self.reserve(grant_expires_at=1000), EXPIRED)
        self.assertIsNone(read_record(self.db, "stable-operation-123"))

    def test_no_verified_grant_does_not_write(self):
        self.assertEqual(self.reserve(grant_verified=False), NO_APPROVAL)
        self.assertIsNone(read_record(self.db, "stable-operation-123"))

    def test_boolean_epoch_and_grant_are_not_accepted_as_integers(self):
        for kw in (dict(now=True), dict(grant_expires_at=True),
                   dict(grant_verified=1)):
            with self.subTest(kw=kw), self.assertRaises(InvalidFixture):
                self.reserve(**kw)

    def test_empty_or_malformed_provenance_is_not_reservable(self):
        for kw in (dict(operation_key=""), dict(operation_key="bad whitespace"),
                   dict(approval_id=None), dict(approval_id=""),
                   dict(revision="short"), dict(revision=REV.upper()),
                   dict(operation_key="' DROP TABLE x; --")):
            with self.subTest(kw=kw), self.assertRaises(InvalidFixture):
                self.reserve(**kw)

    def test_missing_table_fails_closed(self):
        missing = Path(self.scratch.name) / "missing.sqlite"
        with self.assertRaises(sqlite3.OperationalError):
            self.reserve(db_path=missing)

    def test_missing_database_readback_does_not_create_one(self):
        missing = Path(self.scratch.name) / "unknown.sqlite"
        with self.assertRaises(sqlite3.OperationalError):
            read_record(missing, "stable-operation-123")
        self.assertFalse(missing.exists())

    def test_only_one_concurrent_sqlite_reservation(self):
        start = threading.Barrier(8)
        def worker(_):
            start.wait(timeout=8)
            return self.reserve()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(results.count(FIRST_ONLY), 1)
        self.assertEqual(results.count(REPLAY_BLOCKED), 7)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM synthetic_pre_call_reservations"
            ).fetchone()[0], 1)

    def test_crash_after_commit_remains_blocked_after_restart(self):
        # A separate Python interpreter writes the reservation then force-exits
        # without finally blocks, LLM calls or provider credentials.
        program = (
            "import os,sys\n"
            "from pathlib import Path\n"
            "from scripts.orchestration_pre_call_reservation_probe "
            "import reserve_once,FIRST_ONLY\n"
            "result=reserve_once(Path(sys.argv[1]),operation_key='stable-operation-123',"
            "revision='a'*40,approval_id='verified-by-external-test',"
            "grant_verified=True,grant_expires_at=2000,now=1000)\n"
            "assert result==FIRST_ONLY,result\n"
            "os._exit(29)\n"
        )
        child = subprocess.run([sys.executable, "-B", "-c", program, str(self.db)],
                               cwd=str(Path(__file__).resolve().parents[1]),
                               capture_output=True, timeout=12, check=False)
        self.assertEqual(child.returncode, 29, child.stderr.decode(errors="replace"))
        self.assertIsNotNone(read_record(self.db, "stable-operation-123"))
        self.assertEqual(self.reserve(), REPLAY_BLOCKED)

    def test_approved_retry_cannot_reserve_after_crash(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        # A later synthetic owner confirmation is not an authority to
        # silently repeat the same logical external operation.
        self.assertEqual(
            self.reserve(approval_id="fresh-explicit-approval",
                         revision=REV2, now=1900, grant_expires_at=3000),
            REPLAY_BLOCKED)


if __name__ == "__main__":
    unittest.main()
