"""H-02: failures of delivery SERVICE should not be masked by an active timer."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch import collector
from ops_watch.core import InputError, analyze
from ops_watch.incident_preview import render

NOW = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)
GOOD = {"loaded": True, "enabled": True, "active": True}
NEWS = {
    "last_successful_discovery_at": NOW.isoformat(),
    "consecutive_discovery_failures": 0,
    "consecutive_drain_failures": 0,
    "pending_jobs": 0,
    "oldest_pending_age_seconds": 0,
}


class SenderServiceMonitorTests(unittest.TestCase):
    def _findings(self, sender):
        snapshot = collector.normalized(
            NEWS, NOW, timer_enabled=True, timer_active=True,
            agent_guard=GOOD, alerts_timer=GOOD,
            alerts_service=sender,
        )
        return analyze(snapshot, now=NOW)

    def test_completed_oneshot_is_inactive_but_not_failed(self):
        self.assertEqual(self._findings({"failed": False}), [])

    def test_failed_sender_with_healthy_timer_is_critical_incident(self):
        found = self._findings({"failed": True})
        self.assertEqual(
            {row["code"] for row in found}, {"alert_sender_failed"}
        )
        self.assertEqual(found[0]["severity"], "critical")
        rendered = render({"raised": ["ops:alert_sender_failed"], "resolved": []}, found)
        self.assertEqual(rendered[0]["phase"], "new")
        self.assertIn("уведомлений", rendered[0]["title"])
        self.assertNotIn("TOKEN", str(rendered))

    def test_invalid_result_type_does_not_claim_success(self):
        for value in ("false", 0, None, {}, []):
            with self.subTest(value=repr(value)):
                with self.assertRaises(InputError):
                    self._findings({"failed": value})

    def test_exact_read_only_systemctl_response_is_checked(self):
        for result, failed in (
            ("success", False), ("start-limit-hit", True),
            ("exit-code", True), ("timeout", True),
            ("oom-kill", True), ("signal", True),
        ):
            output = f"LoadState=loaded\nResult={result}\n"
            with patch.object(
                collector.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, output, ""),
            ) as run:
                self.assertEqual(
                    collector._ops_alert_service_status(), {"failed": failed}
                )
                self.assertEqual(run.call_args.args[0], [
                    "systemctl", "show", "hermes-ops-alerts.service",
                    "-p", "LoadState", "-p", "Result", "--no-pager",
                ])
                self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_missing_or_unknown_unit_is_not_misreported_healthy(self):
        for output, expected in (
            ("LoadState=not-found\nResult=success\n", {"failed": True}),
            ("LoadState=loaded\nResult=future-unknown\n", None),
            ("LoadState=loaded\nResult=success\nSECRET=XXX\n", None),
            ("LoadState=loaded\nResult=success\nResult=success\n", None),
            ("LoadState=loaded\n", None),
        ):
            with self.subTest(output=output):
                with patch.object(
                    collector.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 0, output, ""),
                ):
                    if expected is None:
                        with self.assertRaisesRegex(InputError,
                                    "alert_delivery_status_unavailable"):
                            collector._ops_alert_service_status()
                    else:
                        self.assertEqual(collector._ops_alert_service_status(), expected)

    def test_persist_failure_recovery_once_on_synthetic_sqlite(self):
        with tempfile.TemporaryDirectory(prefix="hermes-sender-result-") as root:
            directory = Path(root)
            directory.chmod(0o700)
            source = directory / "sanitized.json"
            source.write_text(json.dumps({"health": NEWS}), encoding="utf-8")
            with patch.object(collector, "_state", return_value=True):
                bad = collector.once(
                    source, directory, NOW, agent_guard=GOOD,
                    alerts_timer=GOOD, alerts_service={"failed": True},
                )
                again = collector.once(
                    source, directory, NOW, agent_guard=GOOD,
                    alerts_timer=GOOD, alerts_service={"failed": True},
                )
                resolved = collector.once(
                    source, directory, NOW, agent_guard=GOOD,
                    alerts_timer=GOOD, alerts_service={"failed": False},
                )
                stable = collector.once(
                    source, directory, NOW, agent_guard=GOOD,
                    alerts_timer=GOOD, alerts_service={"failed": False},
                )
            self.assertEqual(bad["changes"]["raised"], ["ops:alert_sender_failed"])
            self.assertEqual(bad["queued_incident_events"], 1)
            self.assertEqual(again["queued_incident_events"], 1)
            self.assertEqual(resolved["changes"]["resolved"], ["ops:alert_sender_failed"])
            self.assertEqual(resolved["queued_incident_events"], 2)
            self.assertEqual(stable["queued_incident_events"], 2)
            database = directory / "incidents.sqlite3"
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as conn:
                rows = conn.execute("SELECT phase FROM events ORDER BY id").fetchall()
            self.assertEqual(rows, [("new",), ("resolved",)])


if __name__ == "__main__":
    unittest.main()
