"""No-network VPS resource alerts: sustained thresholds, recovery and dedup."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ops_watch.infrastructure_alerts import observe
from ops_watch.core import InputError, analyze
from ops_watch.collector import once

NOW = datetime(2026, 10, 18, 10, 0, tzinfo=UTC)


def sample(directory: Path, host: str, *, percents=(94, 95, 96),
           age_seconds=0, corrupt=False, source=True) -> None:
    observed = NOW - timedelta(seconds=age_seconds)
    if source:
        data = {"schema": 1, "host": host, "source": "linux_procfs_local",
                "observed_at": observed.isoformat(),
                "metrics": {"cpu_used_percent": percents[0],
                            "ram_used_percent": percents[1],
                            "disk_used_percent": percents[2]}}
        (directory / (host + ".json")).write_text(
            "{PRIVATE-TOKEN: raw" if corrupt else json.dumps(data), encoding="utf-8")
    with sqlite3.connect(directory / "history.sqlite3") as db:
        db.execute("CREATE TABLE IF NOT EXISTS samples "
                   "(host TEXT, observed_at TEXT, cpu REAL, ram REAL, disk REAL)")
        for i in range(3):
            stamp = (observed - timedelta(minutes=i)).isoformat()
            db.execute("INSERT INTO samples VALUES (?,?,?,?,?)",
                       (host, stamp, *percents))


def base(infrastructure):
    return {"schema": "hermes-ops-snapshot-v1",
            "observed_at": NOW.isoformat(),
            "news": {
                "timer_enabled": True, "timer_active": True,
                "last_successful_discovery_at": NOW.isoformat(),
                "consecutive_discovery_failures": 0,
                "consecutive_drain_failures": 0, "pending_jobs": 0,
                "oldest_pending_age_seconds": 0, "recent_provider_rate_limits": 0,
            }, "infrastructure": infrastructure}


class ResourceAlertTests(unittest.TestCase):
    def test_missing_yfc_has_no_fabricated_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = observe(Path(tmp), now=NOW)
            self.assertEqual(report["yfc"]["status"], "not_connected")
            self.assertEqual(report["hermes"]["status"], "not_connected")
            self.assertEqual(analyze(base(report), now=NOW), [])

    def test_three_distinct_samples_required_to_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sample(folder, "hermes")
            info = observe(folder, now=NOW)
            self.assertEqual(info["hermes"]["levels"], {
                "cpu": "high", "ram": "high", "disk": "high"})
            self.assertEqual({f["code"] for f in analyze(base(info), now=NOW)}, {
                "infra_hermes_cpu_high", "infra_hermes_ram_high",
                "infra_hermes_disk_high"})
            with sqlite3.connect(folder / "history.sqlite3") as db:
                db.execute("DELETE FROM samples WHERE observed_at=(SELECT "
                           "MIN(observed_at) FROM samples)")
            self.assertTrue(all(v == "unknown" for v in observe(
                folder, now=NOW)["hermes"]["levels"].values()))

    def test_yfc_is_always_an_independent_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sample(folder, "yfc", percents=(20, 90, 30))
            incidents = analyze(base(observe(folder, now=NOW)), now=NOW)
            self.assertEqual({v["code"] for v in incidents}, {"infra_yfc_ram_high"})

    def test_offline_and_corrupt_distinguished_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sample(folder, "yfc", age_seconds=1200)
            info = observe(folder, now=NOW)
            self.assertEqual(info["yfc"]["status"], "offline")
            self.assertEqual({x["code"] for x in analyze(base(info), now=NOW)},
                             {"infra_yfc_unavailable"})
            sample(folder, "yfc", corrupt=True)
            info = observe(folder, now=NOW)
            self.assertEqual(info["yfc"]["status"], "unknown")
            self.assertNotIn("PRIVATE-TOKEN", str(info))
            self.assertEqual({x["code"] for x in analyze(base(info), now=NOW)},
                             {"infra_yfc_unavailable"})

    def test_one_spike_or_reset_not_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sample(folder, "hermes", percents=(99, 70, 70))
            with sqlite3.connect(folder / "history.sqlite3") as db:
                db.execute("UPDATE samples SET cpu=30 WHERE observed_at="
                           "(SELECT MIN(observed_at) FROM samples)")
            self.assertEqual(observe(folder, now=NOW)["hermes"]["levels"]["cpu"], "unknown")

    def test_recovery_hysteresis_and_previous_alarm_preserved(self):
        status = lambda level: {"hermes": {
            "status": "online", "levels": {"cpu": level, "ram": "normal", "disk": "normal"}},
            "yfc": {"status": "not_connected"}}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            folder.chmod(0o700)
            health = base(status("high"))["news"]
            with patch("ops_watch.collector._state", return_value=True), \
                 patch("ops_watch.collector._read_state", return_value=health), \
                 patch("ops_watch.collector.infrastructure_observe",
                       side_effect=[status("high"), status("unknown"), status("normal")]), \
                 patch("ops_watch.collector._codex_telemetry", return_value=None):
                kwargs = {"agent_guard": {"loaded": True, "enabled": True, "active": True}}
                first = once(folder / "news", folder, NOW, **kwargs)
                second = once(folder / "news", folder, NOW + timedelta(minutes=1), **kwargs)
                third = once(folder / "news", folder, NOW + timedelta(minutes=3), **kwargs)
            self.assertEqual(first["changes"]["raised"], ["ops:infra_hermes_cpu_high"])
            self.assertEqual(second["changes"]["resolved"], [])
            self.assertEqual(third["changes"]["resolved"], ["ops:infra_hermes_cpu_high"])
            self.assertEqual(first["queued_incident_events"], 1)

    def test_untrusted_host_or_level_rejected(self):
        cases = [
            {"hermes": {"status": "online", "levels": {"cpu": "high"}}, "yfc": {"status": "not_connected"}},
            {"hermes": {"status": "online", "levels": {
                "cpu": "high", "ram": "unexpected", "disk": "normal"}},
             "yfc": {"status": "not_connected"}},
            {"hermes": {"status": "green", "levels": {}}, "yfc": {"status": "not_connected"}},
        ]
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(InputError):
                analyze(base(bad), now=NOW)


if __name__ == "__main__":
    unittest.main()
