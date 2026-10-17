"""H-15 #255: deterministic Ops Watch Codex alert integration regression tests."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control_center.codex_usage import normalize, save_snapshot
from ops_watch.collector import _codex_telemetry
from ops_watch.core import analyze, changes
from ops_watch.incident_preview import render
from ops_watch.delivery_contract import _verified_event
from ops_watch.state_store import persist

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


def base(codex):
    return {
        "schema": "hermes-ops-snapshot-v1",
        "observed_at": NOW.isoformat(),
        "news": {
            "timer_enabled": True, "timer_active": True,
            "last_successful_discovery_at": NOW.isoformat(),
            "consecutive_discovery_failures": 0,
            "consecutive_drain_failures": 0,
            "pending_jobs": 0, "oldest_pending_age_seconds": 0,
            "recent_provider_rate_limits": 0,
        },
        "codex": codex,
    }


class CodexOpsAlertTests(unittest.TestCase):
    def test_quota_state_catalog(self):
        cases = [
            ("available", True, set()),
            ("low", True, {"codex_low"}),
            ("exhausted", True, {"codex_exhausted"}),
            ("limited", True, {"codex_exhausted"}),
            ("auth_required", None, {"codex_auth_required"}),
            ("stale", None, {"codex_stale"}),
            ("unavailable", None, {"codex_stale"}),
            ("unknown", None, {"codex_stale"}),
            ("not_configured", None, set()),
        ]
        for status, allowed, expected in cases:
            with self.subTest(status=status):
                found = analyze(base({"status": status, "ordinary_usage_allowed": allowed}), now=NOW)
                self.assertEqual({x["code"] for x in found}, expected)

    def test_unknown_allowance_fails_closed(self):
        findings = analyze(base({"status": "available", "ordinary_usage_allowed": None}), now=NOW)
        self.assertEqual(findings[0]["code"], "codex_stale")

    def test_codex_resolved_text_not_false_recovery(self):
        earlier = analyze(base({"status": "low", "ordinary_usage_allowed": True}), now=NOW)
        current = analyze(base({"status": "exhausted", "ordinary_usage_allowed": True}), now=NOW)
        items = render(changes(earlier, current), current)
        self.assertEqual(len(items), 2)
        removed = next(x for x in items if x["phase"] == "resolved")
        self.assertTrue(removed["title"].startswith("Снят сигнал:"))
        self.assertNotIn("Восстановлено", removed["title"])
        _verified_event((1, "ops:"+removed["code"], removed["phase"],
                         removed["severity"], removed["title"], removed["action"],
                         NOW.isoformat()))

    def test_sender_outbox_cooldown_and_dedup(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            current = analyze(base({"status": "low", "ordinary_usage_allowed": True}), now=NOW)
            first = persist(directory, current, lambda: [], observed=NOW)
            self.assertEqual(first[2], 1)
            second = persist(directory, [], lambda: [], observed=NOW+timedelta(minutes=2))
            self.assertEqual(second[2], 2)
            third = persist(directory, current, lambda: [], observed=NOW+timedelta(minutes=3))
            self.assertEqual(third[2], 2)
            self.assertEqual(third[1], [])
            fourth = persist(directory, [], lambda: [], observed=NOW+timedelta(minutes=40))
            self.assertEqual(fourth[2], 3)

    def test_inaccessible_optional_codex_directory_is_not_a_collection_failure(self):
        # Production deployment runs all tests as a different non-root user
        # with no search permission for /var/lib/hermes-codex-usage.
        with patch.object(Path, "exists", side_effect=PermissionError("restricted")):
            self.assertIsNone(_codex_telemetry(Path("/var/lib/hermes-codex-usage/usage.json"), observed=NOW))

    def test_optional_codex_source_and_stale_read(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/"usage.json"
            self.assertIsNone(_codex_telemetry(target, observed=NOW))
            snap = normalize({
                "ordinaryUsageAllowed": True,
                "rateLimits": {"limitId": "codex",
                               "primary": {"usedPercent": 100, "windowDurationMins": 300}}
            }, NOW)
            save_snapshot(snap, target)
            self.assertEqual(_codex_telemetry(target, observed=NOW)["status"], "exhausted")
            self.assertEqual(_codex_telemetry(target, observed=NOW+timedelta(minutes=11))["status"], "stale")
            target.write_text('{"secret":"must-not-parse"}')
            self.assertEqual(_codex_telemetry(target, observed=NOW)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
