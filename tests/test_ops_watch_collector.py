"""Local collector regression and redaction checks, no real systemd/files."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch.collector import InputError, _read_state, normalized, once


class HostCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 10, 14, 7, 30, tzinfo=UTC)
        self.health = {
            "last_successful_discovery_at": "2026-10-14T07:00:00+00:00",
            "consecutive_discovery_failures": 0,
            "consecutive_drain_failures": 0,
            "pending_jobs": 0,
            "oldest_pending_age_seconds": 0,
            "provider_rate_limit_count": 20000,
            "secret_content": "Bearer secret should never be repeated",
        }

    def test_normalized_snapshot_omits_tokens_and_cumulative_429(self) -> None:
        snapshot = normalized(self.health, self.now, timer_enabled=True, timer_active=True)
        self.assertNotIn("secret", str(snapshot))
        self.assertNotIn("provider_rate_limit_count", str(snapshot))
        self.assertEqual(snapshot["news"]["recent_provider_rate_limits"], 0)

    def test_missing_required_counter_does_not_claim_success(self) -> None:
        self.health.pop("pending_jobs")
        with self.assertRaises(InputError):
            normalized(self.health, self.now, timer_enabled=True, timer_active=True)

    def test_wrong_counter_type_is_rejected(self) -> None:
        self.health["consecutive_drain_failures"] = True
        with self.assertRaises(InputError):
            normalized(self.health, self.now, timer_enabled=True, timer_active=True)

    def test_invalid_health_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"health": {"secret":', encoding="utf-8")
            with self.assertRaises(InputError):
                _read_state(path)

    @patch("ops_watch.collector._state", return_value=True)
    @patch("ops_watch.collector._read_state")
    def test_collecting_twice_deduplicates_alerts(self, mock_read, mock_state) -> None:
        mock_read.return_value = self.health
        self.health["consecutive_discovery_failures"] = 3
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            target.chmod(0o700)
            first = once(Path(tmp) / "dummy", target, self.now)
            second = once(Path(tmp) / "dummy", target, self.now)
            self.assertEqual(first["changes"]["raised"], ["ops:discovery_failures"])
            self.assertEqual(second["changes"]["raised"], [])

    @patch("ops_watch.collector._state", return_value=True)
    @patch("ops_watch.collector._read_state")
    def test_recovery_announced_once(self, mock_read, mock_state) -> None:
        mock_read.return_value = self.health
        self.health["consecutive_drain_failures"] = 4
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            target.chmod(0o700)
            first = once(Path(tmp) / "dummy", target, self.now)
            self.assertEqual(first["changes"]["raised"], ["ops:drain_failures"])
            self.health["consecutive_drain_failures"] = 0
            second = once(Path(tmp) / "dummy", target, self.now)
            self.assertEqual(second["changes"]["resolved"], ["ops:drain_failures"])
