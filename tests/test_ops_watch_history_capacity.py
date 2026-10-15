"""H-02: acknowledged history must not fill the pending incident queue."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ops_watch.core import InputError
from ops_watch import state_store
from ops_watch.delivery_contract import claim_one, confirm_one, stats
from ops_watch.incident_preview import ACTIONS, CRITICAL, TITLES

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
CODE = "timer_inactive"


def raised():
    return [{"code": CODE, "fingerprint": "ops:" + CODE}]


class RetainedHistoryDoesNotBlockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hermes-pending-cap-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        state_store.persist(self.directory, [], lambda: [], observed=NOW)

    def test_capacity_excludes_acked_but_preserves_all_history(self):
        with patch.object(state_store, "MAX_EVENTS", 1):
            state_store.persist(self.directory, raised(), lambda: [], observed=NOW)
            first = claim_one(self.directory, now=NOW)
            confirm_one(self.directory, event_id=first["event_id"],
                        lease_token=first["lease_token"], telegram_message_id=101,
                        now=NOW + timedelta(seconds=1))
            changes, _, total = state_store.persist(
                self.directory, [], lambda: [], observed=NOW + timedelta(seconds=2))
        self.assertEqual(changes["resolved"], ["ops:" + CODE])
        self.assertEqual(total, 2)
        second = claim_one(self.directory, now=NOW + timedelta(seconds=3))
        self.assertEqual(second["event_id"], 2)
        self.assertEqual(second["phase"], "resolved")
        self.assertEqual(stats(self.directory)["total"], 2)
        self.assertEqual(stats(self.directory)["acknowledged"], 1)

    def test_pending_limit_still_blocks_overflow_and_does_not_mutate_state(self):
        with patch.object(state_store, "MAX_EVENTS", 1):
            state_store.persist(self.directory, raised(), lambda: [], observed=NOW)
            with self.assertRaisesRegex(InputError, "outbox_full"):
                state_store.persist(self.directory, [], lambda: [],
                                    observed=NOW + timedelta(seconds=1))
        self.assertEqual(stats(self.directory)["total"], 1)
        self.assertEqual(state_store.read_current(self.directory), raised())

    def test_more_than_one_thousand_acked_events_do_not_block_new_alert(self):
        # Bounded synthetic fixture; uses only temporary SQLite.
        claim_one(self.directory, now=NOW)  # Creates delivery_receipts.
        with sqlite3.connect(self.directory / state_store.DATABASE) as db:
            for number in range(1100):
                db.execute(
                    "INSERT INTO events(fingerprint,phase,severity,title,action,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    ("ops:" + CODE, "new",
                     "critical" if CODE in CRITICAL else "warning",
                     TITLES[CODE], ACTIONS[CODE], NOW.isoformat()))
                event_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO delivery_receipts("
                    "event_id,status,lease_token,lease_until,attempts,"
                    "telegram_message_id,acknowledged_at) VALUES (?,?,?,?,?,?,?)",
                    (event_id, "acknowledged", "a" * 32, NOW.isoformat(),
                     1, event_id + 100, NOW.isoformat()))
        changes, previews, total = state_store.persist(
            self.directory, raised(), lambda: [], observed=NOW)
        self.assertEqual(total, 1101)
        self.assertEqual(changes["raised"], ["ops:" + CODE])
        next_event = claim_one(self.directory, now=NOW)
        self.assertEqual(next_event["event_id"], 1101)
        self.assertEqual(next_event["attempt"], 1)
        self.assertEqual(stats(self.directory)["acknowledged"], 1100)

    def test_exhausted_unacked_event_is_not_mistaken_for_acked_capacity(self):
        state_store.persist(self.directory, raised(), lambda: [], observed=NOW)
        for attempt in range(5):
            claimed = claim_one(self.directory, now=NOW + timedelta(seconds=91 * attempt))
            self.assertEqual(claimed["event_id"], 1)
        with patch.object(state_store, "MAX_EVENTS", 1):
            with self.assertRaisesRegex(InputError, "outbox_full"):
                state_store.persist(self.directory, [], lambda: [],
                    observed=NOW + timedelta(seconds=91 * 6))
        self.assertEqual(stats(self.directory)["exhausted"], 1)


if __name__ == "__main__":
    unittest.main()
