"""H-04 production-safe isolated state transitions and source anti-corruption tests."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from qa_advisor.signal_store import (
    FILE, SignalError, from_ci, observed_status, read, store,
)
from ops_watch import collector
from ops_watch.state_store import inspect, read_current

NOW = datetime(2026, 10, 15, 4, tzinfo=UTC)
SHA = "a" * 40


def outcome(state="FAILURE", rid=101):
    return {
        "status": state, "head_sha": SHA, "run_id": rid,
    }


class PrivateSignalTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.path = Path(self.context.name)
        self.path.chmod(0o700)

    def record(self, state="FAILURE", rid=101):
        return from_ci(outcome(state, rid), now=NOW)

    def test_atomic_private_file_created_once_with_no_raw_secrets(self):
        self.assertEqual(store(self.record(), directory=self.path), "STORED_SAFE_CI_SIGNAL")
        self.assertEqual(read(self.path)["status"], "FAILURE")
        self.assertEqual((self.path / FILE).stat().st_mode & 0o777, 0o600)
        raw=(self.path / FILE).read_text()
        self.assertNotIn("Bearer", raw)
        self.assertNotIn("job_logs", raw)
        self.assertEqual(observed_status(self.path, now=NOW), "FAILURE")
        self.assertIsNone(observed_status(self.path, now=NOW+timedelta(minutes=33)))

    def test_unknown_api_must_not_erase_last_failure_or_reset_monotonic_id(self):
        store(self.record(), directory=self.path)
        unknown=from_ci({"status":"UNKNOWN"},now=NOW+timedelta(minutes=1))
        self.assertEqual(store(unknown,directory=self.path),"PRESERVED_PREVIOUS_SIGNAL_ON_UNKNOWN")
        self.assertEqual(read(self.path)["run_id"],101)
        with self.assertRaisesRegex(SignalError,"run_id_moved_backward"):
            store(from_ci(outcome("SUCCESS",99),now=NOW+timedelta(minutes=2)),directory=self.path)
        with self.assertRaisesRegex(SignalError,"same_run_cannot_prove_recovery"):
            store(from_ci(outcome("SUCCESS",101),now=NOW+timedelta(minutes=2)),directory=self.path)

    def test_new_success_resolves_only_after_newer_run(self):
        store(self.record(),directory=self.path)
        store(from_ci(outcome("RUNNING",102),now=NOW+timedelta(minutes=1)),directory=self.path)
        self.assertIsNone(observed_status(self.path,now=NOW+timedelta(minutes=1)))
        store(from_ci(outcome("SUCCESS",102),now=NOW+timedelta(minutes=2)),directory=self.path)
        self.assertEqual(observed_status(self.path,now=NOW+timedelta(minutes=2)),"SUCCESS")

    def test_corrupted_symlink_and_permissive_file_refused(self):
        store(self.record(),directory=self.path)
        f=self.path/FILE
        f.chmod(0o644)
        with self.assertRaisesRegex(SignalError,"signal_file_unsafe"):
            read(self.path)
        f.chmod(0o600)
        f.unlink()
        f.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(SignalError,"signal_file_unsafe"):
            read(self.path)

    def test_untrusted_status_fields_and_invalid_clock_are_denied(self):
        for item in (
            {"status":["failure"]},
            {"status":"SUCCESS","run_id":True,"head_sha":SHA},
            {"status":"SUCCESS","run_id":1,"head_sha":"fake"},
        ):
            with self.subTest(value=str(item)):
                with self.assertRaises(SignalError):
                    from_ci(item,now=NOW)
        with self.assertRaises(SignalError):
            from_ci(outcome(),now=datetime(2026,10,15,4))
        record=self.record()
        record["observed_at"]=(NOW+timedelta(days=10)).isoformat()
        store(record,directory=self.path)
        self.assertIsNone(observed_status(self.path,now=NOW))
    
    def test_invalid_store_directory_does_not_create_data(self):
        self.path.chmod(0o755)
        with self.assertRaisesRegex(SignalError,"signal_directory_unsafe"):
            store(self.record(),directory=self.path)


class CollectorSignalReconciliation(unittest.TestCase):
    def test_fail_unknown_and_success_are_distinct_transitions(self):
        with tempfile.TemporaryDirectory() as root:
            directory=Path(root)
            directory.chmod(0o700)
            source=directory/"state.json"
            source.write_text(json.dumps({"health":{
                "last_successful_discovery_at": NOW.isoformat(),
                "consecutive_discovery_failures":0,
                "consecutive_drain_failures":0,
                "pending_jobs":0,
                "oldest_pending_age_seconds":0,
            }}))
            guard={"loaded":True,"enabled":True,"active":True}
            with patch.object(collector,"_state",return_value=True):
                with patch.object(collector,"observed_status",return_value="FAILURE"):
                    first=collector.once(source=source,target=directory,
                                         observed=NOW,agent_guard=guard)
                with patch.object(collector,"observed_status",return_value=None):
                    preserved=collector.once(source=source,target=directory,
                                             observed=NOW,agent_guard=guard)
                with patch.object(collector,"observed_status",return_value="SUCCESS"):
                    recovered=collector.once(source=source,target=directory,
                                             observed=NOW,agent_guard=guard)
                with patch.object(collector,"observed_status",return_value="SUCCESS"):
                    deduped=collector.once(source=source,target=directory,
                                           observed=NOW,agent_guard=guard)
            self.assertEqual(first["changes"]["raised"],["ops:ci_failed"])
            self.assertEqual(preserved["changes"],{"raised":[],"resolved":[]})
            self.assertEqual(recovered["changes"]["resolved"],["ops:ci_failed"])
            self.assertEqual(deduped["changes"],{"raised":[],"resolved":[]})
            self.assertEqual(read_current(directory),[])
            events=inspect(directory)
            self.assertEqual([(row["phase"],row["fingerprint"]) for row in events],
                             [("resolved","ops:ci_failed"),("new","ops:ci_failed")])
            self.assertEqual((directory/"incidents.sqlite3").stat().st_mode & 0o777,0o600)

if __name__ == "__main__":
    unittest.main()
