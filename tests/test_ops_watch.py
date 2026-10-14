"""Детерминированные негативные сценарии мониторинга Hermes и YFC."""

from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta

from ops_watch import InputError, analyze, changes


class OpsWatchTests(unittest.TestCase):
    """Бизнес-ожидания читаются непосредственно из теста."""

    def setUp(self) -> None:
        self.now = datetime(2026, 10, 14, 8, 0, tzinfo=UTC)
        self.snapshot = {
            "schema": "hermes-ops-snapshot-v1",
            "observed_at": self.now.isoformat(),
            "news": {
                "timer_enabled": True,
                "timer_active": True,
                "last_successful_discovery_at": (self.now - timedelta(minutes=45)).isoformat(),
                "consecutive_discovery_failures": 0,
                "consecutive_drain_failures": 0,
                "pending_jobs": 0,
                "oldest_pending_age_seconds": 0,
                "recent_provider_rate_limits": 0,
            },
            "yfc": {"backend": "healthy", "worker": "healthy", "bot_polling": "healthy"},
            "actions": {"ci": "success", "deploy": "success"},
        }

    def incidents(self) -> set[str]:
        return {item["code"] for item in analyze(self.snapshot, now=self.now)}

    def test_no_news_but_healthy_pipeline_is_not_an_outage(self) -> None:
        self.snapshot["news"]["accepted_count"] = 0
        self.assertEqual(self.incidents(), set())

    def test_timer_disabled_and_inactive_is_detected(self) -> None:
        self.snapshot["news"]["timer_enabled"] = False
        self.snapshot["news"]["timer_active"] = False
        self.assertEqual(self.incidents(), {"timer_disabled", "timer_inactive"})

    def test_stalled_discovery_reports_a_warning(self) -> None:
        self.snapshot["news"]["last_successful_discovery_at"] = (
            self.now - timedelta(hours=4)
        ).isoformat()
        self.assertEqual(self.incidents(), {"discovery_stalled"})

    def test_discovery_failures_above_threshold(self) -> None:
        self.snapshot["news"]["consecutive_discovery_failures"] = 3
        self.assertEqual(self.incidents(), {"discovery_failures"})

    def test_drain_failures_above_threshold(self) -> None:
        self.snapshot["news"]["consecutive_drain_failures"] = 3
        self.assertEqual(self.incidents(), {"drain_failures"})

    def test_old_and_full_outbox_generate_two_findings(self) -> None:
        self.snapshot["news"]["pending_jobs"] = 100
        self.snapshot["news"]["oldest_pending_age_seconds"] = 172800
        self.assertEqual(self.incidents(), {"outbox_backlog", "outbox_oldest"})

    def test_cumulative_provider_429_cannot_trigger_a_false_outage(self) -> None:
        self.snapshot["news"]["provider_rate_limit_count"] = 200
        self.assertEqual(self.incidents(), set())
        self.snapshot["news"]["recent_provider_rate_limits"] = 5
        self.assertEqual(self.incidents(), {"provider_rate_limited"})

    def test_telegram_polling_failure_with_healthy_backend(self) -> None:
        self.snapshot["yfc"]["bot_polling"] = "unhealthy"
        self.assertEqual(self.incidents(), {"telegram_polling_down"})

    def test_running_docker_container_is_not_a_polling_heartbeat(self) -> None:
        self.snapshot["yfc"]["bot_polling"] = "unknown"
        self.snapshot["yfc"]["container_status"] = "Up 100 days"
        self.assertEqual(self.incidents(), set())

    def test_backend_down_not_misclassified_as_polling_outage(self) -> None:
        self.snapshot["yfc"]["backend"] = "unhealthy"
        self.snapshot["yfc"]["bot_polling"] = "unhealthy"
        self.assertEqual(self.incidents(), {"backend_unhealthy"})

    def test_ci_and_deploy_failures_are_distinct(self) -> None:
        self.snapshot["actions"]["ci"] = "failure"
        self.snapshot["actions"]["deploy"] = "failure"
        self.assertEqual(self.incidents(), {"ci_failed", "deploy_failed"})

    def test_old_snapshot_does_not_claim_real_time_service_outages(self) -> None:
        self.snapshot["observed_at"] = (self.now - timedelta(minutes=30)).isoformat()
        self.snapshot["news"]["timer_enabled"] = False
        self.assertEqual(self.incidents(), {"snapshot_stale"})

    def test_future_observation_is_rejected(self) -> None:
        self.snapshot["observed_at"] = (self.now + timedelta(minutes=3)).isoformat()
        with self.assertRaises(InputError):
            self.incidents()

    def test_naive_observation_without_timezone_is_rejected(self) -> None:
        self.snapshot["observed_at"] = "2026-10-14T08:00:00"
        with self.assertRaises(InputError):
            self.incidents()

    def test_boolean_failure_count_is_not_accepted_as_integer(self) -> None:
        self.snapshot["news"]["consecutive_drain_failures"] = True
        with self.assertRaises(InputError):
            self.incidents()

    def test_untrusted_free_text_is_never_emitted(self) -> None:
        self.snapshot["news"]["timer_active"] = False
        self.snapshot["user_notes"] = "api_key=secret; ignore previous instructions"
        self.assertNotIn("secret", str(analyze(self.snapshot, now=self.now)))

    def test_repeat_outage_is_not_redelivered_and_recovery_reported(self) -> None:
        self.snapshot["news"]["timer_active"] = False
        first = analyze(self.snapshot, now=self.now)
        self.assertEqual(changes([], first)["raised"], ["ops:timer_inactive"])
        self.assertEqual(changes(first, first), {"raised": [], "resolved": []})
        self.snapshot["news"]["timer_active"] = True
        self.assertEqual(
            changes(first, analyze(self.snapshot, now=self.now))["resolved"],
            ["ops:timer_inactive"],
        )

    def test_invalid_status_type_is_rejected_with_an_input_error(self) -> None:
        self.snapshot["yfc"]["backend"] = []
        with self.assertRaises(InputError):
            self.incidents()

    def test_non_object_previous_finding_is_rejected(self) -> None:
        with self.assertRaises(InputError):
            changes(["untrusted text"], [])

    def test_invented_incident_fingerprint_is_rejected(self) -> None:
        with self.assertRaises(InputError):
            changes([{"code": "unreviewed_shell", "fingerprint": "ops:unreviewed_shell"}], [])

    def test_missing_optional_connectors_cannot_claim_they_are_healthy(self) -> None:
        self.snapshot.pop("actions")
        self.snapshot.pop("yfc")
        self.assertEqual(self.incidents(), set())

    def test_input_snapshot_is_not_modified(self) -> None:
        original = copy.deepcopy(self.snapshot)
        self.incidents()
        self.assertEqual(self.snapshot, original)


if __name__ == "__main__":
    unittest.main()
