"""Issue #295 - offline end-to-end Ops Watch quota alert lifecycle.

Exercise collector SQLite persistence and event dedup, not Telegram delivery.
No provider credentials, model inference, network or real VPS involvement.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from ops_watch.collector import once

NOW = datetime(2026, 10, 14, 7, 30, tzinfo=UTC)
HEALTH = {
    "last_successful_discovery_at": "2026-10-14T07:25:00+00:00",
    "consecutive_discovery_failures": 0,
    "consecutive_drain_failures": 0,
    "pending_jobs": 0,
    "oldest_pending_age_seconds": 0,
    "provider_rate_limit_count": 0,
}
GOOD_GUARD = {"loaded": True, "enabled": True, "active": True}


class QuotaAlertLifecycleTests(TestCase):
    def collect_sequence(self, signals: list[dict[str, str]]) -> list[dict]:
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            target.chmod(0o700)
            with (
                patch("ops_watch.collector._read_state", return_value=HEALTH),
                patch("ops_watch.collector._state", return_value=True),
                patch("ops_watch.collector._codex_telemetry", return_value=None),
                patch("ops_watch.collector.observed_status", return_value=None),
                patch("ops_watch.collector.quota_observe", side_effect=signals),
            ):
                result = []
                for idx in range(len(signals)):
                    result.append(once(
                        source=target / "source-not-read",
                        target=target,
                        observed=NOW + timedelta(seconds=idx * 15),
                        agent_guard=GOOD_GUARD,
                        quota_paths={"codex": target / "no-provider"},
                    ))
            return result

    def test_auth_and_stale_cannot_be_cleared_by_missing_quota_source(self):
        records = self.collect_sequence([
            {"desktop_commander": "auth_required", "github_api": "stale"},
            {"desktop_commander": "unknown", "github_api": "not_connected"},
            {"desktop_commander": "healthy", "github_api": "healthy"},
        ])
        expected = ["ops:quota_desktop_auth", "ops:quota_github_stale"]
        self.assertEqual(records[0]["changes"]["raised"], expected)
        self.assertEqual(records[1]["changes"]["raised"], [])
        self.assertEqual(records[1]["changes"]["resolved"], [])
        self.assertEqual(sorted(records[1]["active_codes"]),
                         ["quota_desktop_auth", "quota_github_stale"])
        self.assertEqual(records[2]["changes"]["resolved"], expected)
        self.assertEqual(records[2]["changes"]["raised"], [])

    def test_previous_quota_threshold_survives_unknown_then_resolves_on_fresh(self):
        records = self.collect_sequence([
            {"desktop_commander": "warn95", "github_api": "exhausted"},
            {"desktop_commander": "not_connected", "github_api": "auth_required"},
            {"desktop_commander": "healthy", "github_api": "healthy"},
        ])
        self.assertEqual(records[0]["changes"]["raised"],
                         ["ops:quota_desktop_95", "ops:quota_github_exhausted"])
        self.assertEqual(records[1]["changes"]["raised"], ["ops:quota_github_auth"])
        self.assertEqual(records[1]["changes"]["resolved"], [])
        self.assertIn("quota_github_exhausted", records[1]["active_codes"])
        self.assertEqual(records[2]["changes"]["resolved"], [
            "ops:quota_desktop_95", "ops:quota_github_auth",
            "ops:quota_github_exhausted",
        ])

    def test_verified_new_status_replaces_old_source_status(self):
        records = self.collect_sequence([
            {"desktop_commander": "auth_required", "github_api": "stale"},
            {"desktop_commander": "stale", "github_api": "auth_required"},
        ])
        self.assertEqual(records[1]["changes"]["resolved"],
                         ["ops:quota_desktop_auth", "ops:quota_github_stale"])
        self.assertEqual(records[1]["changes"]["raised"],
                         ["ops:quota_desktop_stale", "ops:quota_github_auth"])
