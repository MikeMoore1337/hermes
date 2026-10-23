"""No-network #294 YFC Telegram polling evidence contract and trust boundary."""
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from control_center import infrastructure_pull
from control_center.infrastructure import hosts, save
from control_center.yfc_polling import read_local, sanitize
from ops_watch.infrastructure_alerts import observe
from ops_watch.core import analyze
from tests.test_infrastructure_monitor import fixture

NOW = datetime(2026, 10, 23, 20, 20, tzinfo=UTC)


def evidence(status="healthy", event="getupdates_success", age=0):
    return {
        "schema": 1, "source_host": "yfc", "status": status,
        "evidence": event,
        "observed_at": (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z"),
    }


def base():
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
    }


class PollingEvidenceTests(unittest.TestCase):
    def test_fresh_success_and_error_are_distinguishable(self):
        self.assertEqual(sanitize(evidence(), now=NOW)["status"], "healthy")
        self.assertEqual(sanitize(evidence("unhealthy", "getupdates_error"),
                                  now=NOW)["status"], "unhealthy")

    def test_missing_bad_identity_wrong_event_and_future_fail_closed(self):
        candidates = [
            None, "healthy", {"status": "healthy"}, {**evidence(), "source_host": "other"},
            {**evidence(), "evidence": "startup"},
            {**evidence(), "observed_at": "not-a-date"},
            {**evidence(), "observed_at": (NOW + timedelta(minutes=4)).isoformat()},
            {**evidence(), "secret": "do-not-leak"},
            {**evidence(), "status": "unhealthy"},
        ]
        for data in candidates:
            with self.subTest(data=str(data)[:40]):
                result = sanitize(data, now=NOW)
                self.assertEqual(result["status"], "unknown")
                self.assertNotIn("secret", str(result))

    def test_stale_heartbeat_cannot_be_healthy_or_resolve(self):
        result = sanitize(evidence(age=121), now=NOW)
        self.assertEqual(result["status"], "stale")
        self.assertNotIn("observed_at", result)

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX ownership only")
    def test_local_file_requires_expected_owner_group_mode_and_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "polling.json"
            payload = {**evidence(), "state": "healthy",
                       "component": "telegram_polling"}
            payload.pop("status")
            path.write_text(json.dumps(payload))
            path.chmod(0o640)
            params = {"expected_uid": os.getuid(), "expected_gid": os.getgid(), "now": NOW}
            self.assertEqual(read_local(path, **params)["status"], "healthy")
            path.chmod(0o666)
            self.assertEqual(read_local(path, **params)["status"], "unknown")
            path.unlink()
            path.symlink_to(Path(directory) / "missing")
            self.assertEqual(read_local(path, **params)["status"], "unknown")
            path.unlink()
            self.assertEqual(read_local(path, **params)["status"], "not_connected")

    def test_yfc_snapshots_preserve_only_sanitized_health_and_expire(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = fixture("yfc", now=NOW)
            snapshot["polling_health"] = evidence("unhealthy", "getupdates_error")
            with patch("control_center.infrastructure.dt.datetime") as clock:
                clock.now.return_value = NOW
                # Do not need synthetic host filesystem writes at historical time;
                # use validated() and a current proof in the persistence test below.
                from control_center.infrastructure import _validated
                checked = _validated(snapshot, "yfc", NOW)
            self.assertEqual(checked["polling_health"]["status"], "unhealthy")
            self.assertEqual(_validated(snapshot, "yfc", NOW + timedelta(minutes=3))[
                "polling_health"]["status"], "stale")

    def test_restricted_ssh_pull_drops_untrusted_extra_and_keeps_verified_proof(self):
        stamp = datetime.now(UTC)
        sample = fixture("yfc", now=stamp)
        sample["polling_health"] = {
            **evidence("unhealthy", "getupdates_error"),
            "observed_at": stamp.isoformat().replace("+00:00", "Z"),
        }
        sample["private_data"] = "never-forward"
        runner = Mock(return_value=Mock(returncode=0, stdout=json.dumps(sample)))
        with patch.object(infrastructure_pull, "endpoint", return_value=("yfc.example", 22)), \
             patch.object(infrastructure_pull, "require_file"), \
             patch.object(infrastructure_pull, "save") as save_mock:
            infrastructure_pull.pull(runner=runner)
        result = save_mock.call_args.args[0]
        self.assertEqual(result["polling_health"]["status"], "unhealthy")
        self.assertNotIn("private_data", result)

    def test_real_resource_snapshot_only_flags_verified_polling_error(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            snap = fixture("yfc", now=NOW)
            # Resource-level evidence uses a purpose-built fixed read-only reader.
            snap["polling_health"] = evidence("unhealthy", "getupdates_error")
            snap["source"] = "linux_procfs_local"
            (root / "yfc.json").write_text(json.dumps(snap))
            info = observe(root, now=NOW)
            self.assertEqual(info["yfc"]["bot_polling"], "unhealthy")
            snapshot = base()
            snapshot["yfc"] = {
                "backend": "unknown", "worker": "unknown",
                "bot_polling": info["yfc"]["bot_polling"],
                "polling_provenance": "verified",
            }
            self.assertEqual([f["code"] for f in analyze(snapshot, now=NOW)],
                             ["telegram_polling_down"])
            snap["polling_health"]["observed_at"] = (
                NOW - timedelta(seconds=125)).isoformat()
            (root / "yfc.json").write_text(json.dumps(snap))
            self.assertNotIn("bot_polling", observe(root, now=NOW)["yfc"])


if __name__ == "__main__":
    unittest.main()
