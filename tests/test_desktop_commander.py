"""Offline Desktop Commander contract, privacy and admission tests."""
import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.desktop_commander import (
    CommanderError, device_gate, empty, normalize, read_snapshot, save_snapshot,
)
from control_center.server import make_handler

NOW = dt.datetime(2026, 10, 17, 21, 0, tzinfo=dt.timezone.utc)
DEVICES = """Desktop Commander devices

1. vps1777112993
   Status: Online
   ID: secret-not-for-frontend
   Last seen: 31s ago
   App version: 0.3.0

2. DESKTOP-U6JEQP9
   Status: Offline
   ID: another-secret-id
   Last seen: 2h ago
"""
WHO = {"remote_calls_left_pct": 0, "email": "secret@example.com", "access_token": "LEAK_SECRET"}


class NormalizerTests(unittest.TestCase):
    def test_exhausted_never_promotes_online_to_execution(self):
        data = normalize(WHO, DEVICES, NOW)
        self.assertEqual(data["status"], "exhausted")
        self.assertEqual(data["quota_remaining_percent"], 0)
        self.assertEqual([x["state"] for x in data["devices"]], ["online", "offline"])
        self.assertEqual(data["remote_execution"], "blocked")
        for needle in ("secret@example.com", "LEAK_SECRET", "secret-not-for-frontend"):
            self.assertNotIn(needle, json.dumps(data))

    def test_unknown_quota_never_becomes_available(self):
        data = normalize({"remote_calls_left_pct": True}, DEVICES, NOW)
        self.assertEqual(data["status"], "unknown")
        self.assertEqual(data["quota_remaining_percent"], None)
        self.assertEqual(data["remote_execution"], "unverified")
        for amount in (-1, 101, "0", 0.2):
            self.assertIsNone(normalize({"remote_calls_left_pct": amount}, DEVICES, NOW)["quota_remaining_percent"])

    def test_policy_strictly_separate_from_codex(self):
        data = normalize({"remote_calls_left_pct": 40}, DEVICES, NOW)
        self.assertEqual(device_gate(data, "vps1777112993"), "DENY")
        self.assertEqual(device_gate(data, "vps1777112993", authorized=True), "UNKNOWN")
        self.assertEqual(device_gate(data, "vps1777112993", authorized=True, execution_verified=True), "ALLOW")
        self.assertEqual(device_gate(data, "DESKTOP-U6JEQP9", authorized=True, execution_verified=True), "DEFER")
        self.assertEqual(device_gate(normalize(WHO, DEVICES, NOW), "vps1777112993", authorized=True,
                                     execution_verified=True), "DEFER")
        self.assertEqual(device_gate(empty(), "vps1777112993", authorized=True), "UNKNOWN")

    def test_snapshot_round_trip_stale_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            self.assertEqual(read_snapshot(path)["status"], "not_configured")
            data = normalize(WHO, DEVICES, NOW)
            save_snapshot(data, path)
            self.assertEqual(read_snapshot(path, NOW)["status"], "exhausted")
            stale = read_snapshot(path, NOW + dt.timedelta(hours=1))
            self.assertEqual(stale["status"], "stale")
            self.assertEqual(stale["remote_execution"], "unverified")
            data["email"] = "LEAK_SECRET"
            path.write_text(json.dumps(data))
            with self.assertRaises(CommanderError):
                read_snapshot(path, NOW)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        base = Path(self.dir.name)
        overview = base / "overview.json"
        overview.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "services": [],
        }))
        self.dc = base / "status.json"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                         make_handler(overview, desktop_commander_path=self.dc))
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(3)
        self.dir.cleanup()

    def fetch(self, method="GET", path="/api/providers/desktop-commander"):
        req = Request(f"http://127.0.0.1:{self.httpd.server_port}{path}",
                      headers={"Host": "hermes.mikemoore.top"}, method=method)
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            return error.code, error.headers, error.read()

    def test_not_configured_and_no_store(self):
        status, headers, raw = self.fetch()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(raw)["status"], "not_configured")
        self.assertEqual(self.fetch("HEAD")[2], b"")
        self.assertEqual(self.fetch(path="/api/providers/desktop-commander?x=1")[0], 404)
        self.assertEqual(self.fetch("POST")[0], 501)

    def test_snapshot_and_invalid(self):
        save_snapshot(normalize(WHO, DEVICES), self.dc)
        status, _, raw = self.fetch()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["devices"][0]["name"], "vps1777112993")
        self.assertNotIn(b"LEAK_SECRET", raw)
        self.dc.write_text('{"oops":"LEAK_SECRET"}')
        self.assertEqual(self.fetch()[0], 503)


if __name__ == "__main__":
    unittest.main()
