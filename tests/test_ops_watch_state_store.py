"""Durable Ops Watch incident transitions without any outbound API calls."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch.core import InputError
from ops_watch.state_store import DATABASE, inspect, persist

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def active(code: str) -> list[dict]:
    return [{"code": code, "severity": "critical", "fingerprint": "ops:" + code}]


class TransactionalOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.path.chmod(0o700)

    def save(self, current, legacy=lambda: []):
        return persist(self.path, current, legacy, observed=NOW)

    def test_new_incident_persists_once_across_repeated_runs(self):
        delta, previews, count = self.save(active("timer_inactive"))
        self.assertEqual(delta["raised"], ["ops:timer_inactive"])
        self.assertEqual(previews[0]["phase"], "new")
        self.assertEqual(count, 1)
        self.assertEqual(self.save(active("timer_inactive"))[2], 1)
        self.assertEqual(len(inspect(self.path)), 1)

    def test_recovery_is_an_additional_durable_event(self):
        self.save(active("timer_inactive"))
        delta, previews, count = self.save([])
        self.assertEqual(delta["resolved"], ["ops:timer_inactive"])
        self.assertEqual(previews[0]["phase"], "resolved")
        self.assertEqual(count, 2)
        self.assertEqual(self.save([])[2], 2)

    def test_multiple_incidents_stored_in_single_transaction(self):
        current = active("timer_disabled") + active("timer_inactive")
        self.assertEqual(self.save(current)[2], 2)
        self.assertEqual({x["fingerprint"] for x in inspect(self.path)},
                         {"ops:timer_disabled", "ops:timer_inactive"})

    def test_initial_migration_preserves_prior_alert_without_duplicate(self):
        prior = active("timer_inactive")
        self.assertEqual(self.save(prior, lambda: prior)[2], 0)
        self.assertEqual(self.save(prior, lambda: (_ for _ in ()).throw(
            AssertionError("legacy only read once")))[2], 0)
        self.assertEqual(inspect(self.path), [])

    def test_failed_projection_does_not_repeat_committed_event(self):
        self.save(active("timer_inactive"))
        # Simulate the JSON file write failing *after* the DB commit.
        # Next collector starts from SQLite, not the old JSON snapshot.
        def wrong_legacy():
            raise AssertionError("stale JSON must be ignored after commit")
        delta, preview, count = self.save(active("timer_inactive"), wrong_legacy)
        self.assertEqual(delta["raised"], [])
        self.assertEqual(count, 1)

    def test_failure_before_commit_rolls_back_transition(self):
        self.save([])
        with patch("ops_watch.state_store.render", side_effect=InputError("render_denied")):
            with self.assertRaises(InputError):
                self.save(active("timer_inactive"))
        self.assertEqual(inspect(self.path), [])
        self.assertEqual(self.save(active("timer_inactive"))[2], 1)

    def test_symlink_database_is_rejected(self):
        target = self.path / "ordinary"
        target.write_text("do not touch", encoding="utf-8")
        (self.path / DATABASE).symlink_to(target)
        with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
            self.save(active("timer_inactive"))
        self.assertEqual(target.read_text(encoding="utf-8"), "do not touch")

    def test_weak_database_permissions_are_rejected(self):
        self.save([])
        (self.path / DATABASE).chmod(0o644)
        with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
            self.save(active("timer_inactive"))

    def test_corrupt_sqlite_fails_closed(self):
        (self.path / DATABASE).write_bytes(b"not a sqlite database")
        (self.path / DATABASE).chmod(0o600)
        with self.assertRaises(InputError):
            self.save(active("timer_inactive"))

    def test_untrusted_event_text_is_not_copied(self):
        data = active("outbox_backlog")
        data[0]["private"] = "Bearer should-stay-private"
        _, _, count = self.save(data)
        self.assertEqual(count, 1)
        self.assertNotIn("should-stay-private", str(inspect(self.path)))
        with sqlite3.connect(self.path / DATABASE) as db:
            state = db.execute("SELECT findings_json FROM state WHERE id=1").fetchone()[0]
        self.assertNotIn("should-stay-private", state)

    def test_duplicate_current_incident_cannot_be_saved(self):
        with self.assertRaisesRegex(InputError, "invalid_current_incidents"):
            self.save(active("timer_inactive") + active("timer_inactive"))

    def test_input_cannot_persist_unrecognized_keys(self):
        data = active("timer_inactive")
        data[0]["raw_model_output"] = "SECRET PRIVATE DATA"
        self.save(data)
        with sqlite3.connect(self.path / DATABASE) as db:
            row = db.execute("SELECT findings_json FROM state").fetchone()[0]
        self.assertNotIn("PRIVATE DATA", row)

    def test_readonly_inspection_has_strict_limit(self):
        self.save(active("timer_disabled"))
        for bad in (0, 51, True, -1):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                inspect(self.path, max_items=bad)
        self.assertEqual(len(inspect(self.path, max_items=1)), 1)

    def test_full_queue_refuses_to_drop_events(self):
        self.save([])
        db_path = self.path / DATABASE
        with sqlite3.connect(db_path) as db:
            db.executemany(
                "INSERT INTO events(fingerprint,phase,severity,title,action,created_at) "
                "VALUES('ops:x','new','warning','x','x',?)",
                [(NOW.isoformat(),)] * 1000,
            )
        with self.assertRaisesRegex(InputError, "outbox_full"):
            self.save(active("timer_inactive"))
        self.assertEqual(len(inspect(self.path)), 50)

    def test_queue_has_no_ack_or_delivery_api(self):
        self.save(active("timer_inactive"))
        with sqlite3.connect(self.path / DATABASE) as db:
            names = [r[1] for r in db.execute("PRAGMA table_info(events)").fetchall()]
        self.assertEqual(names, [
            "id", "fingerprint", "phase", "severity", "title", "action", "created_at"
        ])

if __name__ == "__main__":
    unittest.main()
