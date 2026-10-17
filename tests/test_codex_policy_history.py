"""H-15 #255: deterministic quota policy, history retention and HTTP tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig
from control_center.codex_history import read, record
from control_center.codex_policy import decision, may_dispatch
from control_center.codex_usage import error_snapshot, normalize, save_snapshot
from control_center.server import make_handler

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def quota(primary=40, weekly=50, allowed=True, when=NOW, extra=None, reset=True):
    group = {
        "primary": {"usedPercent": primary, "windowDurationMins": 300},
        "secondary": {"usedPercent": weekly, "windowDurationMins": 10080},
    }
    if reset:
        group["primary"]["resetsAt"] = 1792250000
        group["secondary"]["resetsAt"] = 1792550000
    groups = {"codex": group}
    if extra is not None:
        groups["other"] = {"primary": {"usedPercent": extra, "windowDurationMins": 120}}
    return normalize({"ordinaryUsageAllowed": allowed, "rateLimitsByLimitId": groups}, when)


class PolicyTests(unittest.TestCase):
    def evaluate(self, snap, threshold=20, now=NOW):
        return decision(snap, now=now, threshold_percent=threshold)

    def test_both_windows_confirmed(self):
        actual = self.evaluate(quota())
        self.assertEqual(actual["decision"], "ALLOW")
        self.assertEqual(actual["reason"], "quotas_confirmed")

    def test_short_window_exhausted(self):
        self.assertEqual(self.evaluate(quota(primary=100))["decision"], "DEFER")

    def test_weekly_window_exhausted(self):
        self.assertEqual(self.evaluate(quota(weekly=100))["decision"], "DEFER")

    def test_both_windows_exhausted(self):
        self.assertEqual(self.evaluate(quota(100, 100))["decision"], "DEFER")

    def test_recovered_short_does_not_release_exhausted_week(self):
        self.assertEqual(self.evaluate(quota(0, 100))["decision"], "DEFER")

    def test_explicit_provider_denial(self):
        self.assertEqual(self.evaluate(quota(0, 0, False))["reason"], "ordinary_usage_denied")

    def test_missing_ordinary_allowance_is_unknown(self):
        self.assertEqual(self.evaluate(quota(0, 0, None))["decision"], "UNKNOWN")

    def test_missing_reset_timestamp_does_not_fake_exhaustion(self):
        self.assertEqual(self.evaluate(quota(reset=False))["decision"], "ALLOW")

    def test_added_window_must_also_have_quota(self):
        self.assertEqual(self.evaluate(quota(extra=100))["decision"], "DEFER")

    def test_stale_snapshot_unknown_even_if_new_reset_clock_passed(self):
        self.assertEqual(self.evaluate(quota(), now=NOW+timedelta(minutes=11))["decision"], "UNKNOWN")

    def test_provider_auth_and_transport_errors(self):
        for status in ("auth_required", "unavailable"):
            with self.subTest(status=status):
                self.assertEqual(self.evaluate(error_snapshot(status, NOW))["decision"], "UNKNOWN")

    def test_missing_or_invalid_data_fails_closed(self):
        self.assertEqual(self.evaluate(None)["decision"], "UNKNOWN")
        bad = quota()
        bad["limits"][0]["windows"][0]["remaining_percent"] = float("nan")
        self.assertEqual(self.evaluate(bad)["decision"], "UNKNOWN")

    def test_warning_threshold_configurable(self):
        sample = quota(primary=78)
        self.assertEqual(self.evaluate(sample, threshold=25)["decision"], "DEFER")
        self.assertEqual(self.evaluate(sample, threshold=20)["decision"], "ALLOW")
        with self.assertRaises(ValueError):
            self.evaluate(sample, threshold=100)

    def test_confirmed_recovery_and_owner_permission(self):
        denied = self.evaluate(quota(100, 100))
        recovered = self.evaluate(quota(10, 10, True, NOW+timedelta(minutes=1)),
                                  now=NOW+timedelta(minutes=1))
        self.assertFalse(may_dispatch(denied, task_authorized=True))
        self.assertFalse(may_dispatch(recovered, task_authorized=False))
        self.assertTrue(may_dispatch(recovered, task_authorized=True))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "history.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_same_snapshot_dedup_and_hourly_anchor(self):
        sample = quota()
        self.assertTrue(record(sample, self.db))
        self.assertFalse(record(sample, self.db))
        self.assertFalse(record(quota(when=NOW+timedelta(minutes=5)), self.db))
        self.assertTrue(record(quota(when=NOW+timedelta(minutes=31)), self.db))
        self.assertEqual(len(read(self.db, now=NOW+timedelta(hours=1))["samples"]), 2)

    def test_restart_dedup_does_not_repeat_transitions(self):
        record(quota(), self.db)
        record(quota(100, when=NOW+timedelta(minutes=1)), self.db)
        record(quota(100, when=NOW+timedelta(minutes=1)), self.db)
        history = read(self.db, now=NOW+timedelta(minutes=2))
        self.assertEqual(len(history["transitions"]), 1)
        self.assertEqual(history["transitions"][0]["current"], "exhausted")

    def test_failure_preserves_successful_history(self):
        record(quota(), self.db)
        record(error_snapshot("unavailable", NOW+timedelta(minutes=5)), self.db)
        record(error_snapshot("auth_required", NOW+timedelta(minutes=6)), self.db)
        history = read(self.db, now=NOW+timedelta(minutes=7))
        self.assertEqual(len(history["samples"]), 3)
        self.assertEqual(history["last_successful_at"], "2026-10-17T12:00:00Z")
        self.assertEqual(history["transitions"][0]["current"], "auth_required")

    def test_recovery_only_from_new_observation(self):
        record(quota(100, 100), self.db)
        record(quota(100, 100, when=NOW+timedelta(hours=1)), self.db)
        record(quota(30, 50, when=NOW+timedelta(hours=2)), self.db)
        history = read(self.db, now=NOW+timedelta(hours=2))
        self.assertEqual([x["current"] for x in history["transitions"]], ["available"])

    def test_secrets_never_enter_database(self):
        sample = quota()
        sample["access_token"] = "NEVER_STORE_THIS"
        sample["email"] = "NEVER_STORE_THIS@example.net"
        record(sample, self.db)
        self.assertNotIn("NEVER_STORE_THIS", self.db.read_bytes().decode("latin-1"))

    def test_out_of_order_input_keeps_existing_history(self):
        record(quota(when=NOW+timedelta(minutes=10)), self.db)
        self.assertFalse(record(quota(100, when=NOW), self.db))
        self.assertEqual(len(read(self.db, now=NOW+timedelta(minutes=11))["samples"]), 1)

    def test_missing_history_and_retention(self):
        self.assertEqual(read(self.db)["samples"], [])
        record(quota(when=NOW), self.db)
        record(quota(when=NOW+timedelta(days=31)), self.db)
        self.assertEqual(len(read(self.db, now=NOW+timedelta(days=31))["samples"]), 1)

    def test_long_history_samples_cover_entire_requested_month(self):
        for hour in range(600):
            record(quota(primary=30 if hour % 2 else 31,
                         when=NOW+timedelta(hours=hour)), self.db)
        data = read(self.db, now=NOW+timedelta(hours=600), days=30)
        self.assertEqual(len(data["samples"]), 500)
        self.assertEqual(data["samples"][0]["observed_at"], "2026-10-17T12:00:00Z")
        self.assertEqual(data["samples"][-1]["observed_at"],
                         (NOW+timedelta(hours=599)).isoformat(timespec="seconds").replace("+00:00", "Z"))

    def test_invalid_history_not_silently_accepted(self):
        self.db.write_bytes(b"not-sqlite")
        with self.assertRaises(ValueError):
            read(self.db, now=NOW)


class DenyAllOAuth:
    def authenticated(self, _cookie):
        return False


class HistoryHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.overview = root / "overview.json"
        self.codex = root / "usage.json"
        save_snapshot(quota(when=datetime.now(timezone.utc)), self.codex)
        record(quota(when=datetime.now(timezone.utc)), root / "history.sqlite3")
        self.httpd = None

    def tearDown(self):
        self.stop()
        self.tmp.cleanup()

    def start(self, auth=False):
        config = AuthConfig(mode="github") if auth else AuthConfig()
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.overview, codex_path=self.codex,
                         auth_config=config,
                         oauth_service=DenyAllOAuth() if auth else None),
        )
        self.worker = Thread(target=self.httpd.serve_forever, daemon=True)
        self.worker.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.worker.join(timeout=3)
            self.httpd = None

    def get(self, suffix):
        req = Request("http://127.0.0.1:" + str(self.httpd.server_port)
                      + "/api/providers/codex/" + suffix,
                      headers={"Host": "hermes.mikemoore.top"})
        try:
            with urlopen(req, timeout=2) as res:
                return res.status, res.headers, res.read()
        except HTTPError as err:
            return err.code, err.headers, err.read()

    def test_owner_only_both_endpoints(self):
        self.start(auth=True)
        for endpoint in ("policy", "history"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.get(endpoint)[0], 401)

    def test_read_only_policy_and_history_contract(self):
        self.start()
        status, headers, payload = self.get("policy")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(payload)["decision"], "ALLOW")
        status, headers, payload = self.get("history")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(payload)["schema"], 1)
        self.assertEqual(len(json.loads(payload)["samples"]), 1)

    def test_history_days_and_policy_threshold_validation(self):
        self.start()
        for endpoint in ("history?days=1", "history?days=30",
                         "policy?threshold=0", "policy?threshold=50"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.get(endpoint)[0], 200)
        for endpoint in ("history?days=0", "history?days=31",
                         "history?days=x", "history?days=7&threshold=2",
                         "policy?threshold=-1", "policy?threshold=51",
                         "policy?threshold=20&threshold=30",
                         "policy?days=7"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.get(endpoint)[0], 400)

    def test_invalid_snapshot_policy_fails_closed(self):
        self.codex.write_text("invalid json")
        self.start()
        self.assertEqual(json.loads(self.get("policy")[2])["decision"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
