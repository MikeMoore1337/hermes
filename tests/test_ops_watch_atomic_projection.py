"""H-02: process crash during JSON projection must not wedge real monitor."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch import collector
from ops_watch.core import InputError


class CrashRecoveryProjectionTests(unittest.TestCase):
    def test_stale_legacy_temp_files_cannot_disable_alert_collection(self):
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as root:
            target = Path(root)
            target.chmod(0o700)
            source = target / "state.json"
            health = {
                "last_successful_discovery_at": now.isoformat(),
                "consecutive_discovery_failures": 3,
                "consecutive_drain_failures": 0,
                "pending_jobs": 0,
                "oldest_pending_age_seconds": 0,
            }
            source.write_text(json.dumps({"health": health}), encoding="utf-8")
            # These fixed names are left by a simulated SIGKILL during
            # the prior (O_EXCL based) version's JSON projection.
            old_finding = target / "findings.json.tmp"
            old_preview = target / "incident-preview.json.tmp"
            old_finding.write_text("CRASH_LEFTOVER", encoding="utf-8")
            old_preview.write_text("CRASH_LEFTOVER", encoding="utf-8")
            good = {"loaded": True, "enabled": True, "active": True}
            with patch.object(collector, "_state", return_value=True):
                incident = collector.once(source, target, now, agent_guard=good)
            self.assertEqual(incident["queued_incident_events"], 1)
            self.assertEqual(incident["changes"]["raised"], ["ops:discovery_failures"])
            self.assertEqual(old_finding.read_text(), "CRASH_LEFTOVER")
            self.assertEqual(old_preview.read_text(), "CRASH_LEFTOVER")
            self.assertEqual((target / "findings.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((target / "incident-preview.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(target.glob(".findings.json.*.tmp")), [])
            self.assertEqual(list(target.glob(".incident-preview.json.*.tmp")), [])

            # The synthetic problem is now resolved and the same real
            # collector state machine persists its recovery exactly once.
            health["consecutive_discovery_failures"] = 0
            source.write_text(json.dumps({"health": health}), encoding="utf-8")
            with patch.object(collector, "_state", return_value=True):
                resolved = collector.once(source, target, now, agent_guard=good)
            self.assertEqual(resolved["queued_incident_events"], 2)
            self.assertEqual(resolved["changes"]["resolved"], ["ops:discovery_failures"])
            with sqlite3.connect((target / "incidents.sqlite3").as_uri()+"?mode=ro", uri=True) as db:
                result = db.execute(
                    "SELECT phase FROM events ORDER BY id"
                ).fetchall()
            self.assertEqual(result, [("new",), ("resolved",)])

    def test_symlinked_legacy_temporary_file_never_writes_target(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            directory.chmod(0o700)
            sentinel = directory / "must_not_touch"
            sentinel.write_text("ORIGINAL", encoding="utf-8")
            (directory / "findings.json.tmp").symlink_to(sentinel)
            collector._atomic_json(directory, "findings.json", [])
            self.assertEqual(sentinel.read_text(), "ORIGINAL")
            self.assertEqual(json.loads((directory / "findings.json").read_text()), [])
            self.assertTrue((directory / "findings.json.tmp").is_symlink())

    def test_atomic_replace_failure_cleans_staging_and_preserves_old_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            directory.chmod(0o700)
            collector._atomic_json(directory, "findings.json", [{"code":"first"}])
            initial = (directory / "findings.json").read_bytes()
            with patch.object(collector.os, "replace", side_effect=OSError("NO_SECRET_DATA")):
                with self.assertRaises(OSError):
                    collector._atomic_json(directory, "findings.json", [{"code":"second"}])
            self.assertEqual((directory / "findings.json").read_bytes(), initial)
            self.assertEqual(list(directory.glob(".findings.json.*.tmp")), [])

    def test_unapproved_projection_name_is_rejected_before_file_created(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            directory.chmod(0o700)
            with self.assertRaisesRegex(InputError, "invalid_projection_name"):
                collector._atomic_json(directory, "../agent_credentials", [])
            self.assertEqual(list(directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
