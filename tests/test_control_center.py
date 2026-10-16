"""Read-only control center: allowlisted systemd, negative HTTP, sanitized data."""
import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.snapshot import collect, unit_state, UNITS
from control_center.server import make_handler


class SnapshotTests(unittest.TestCase):
    def test_allowlist_and_no_sensitive_commands(self):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return type("P", (), {"returncode": 0, "stdout": "LoadState=loaded\nActiveState=active\n"})()
        snapshot = collect(run, dt.datetime(2026, 10, 16, tzinfo=dt.timezone.utc))
        self.assertEqual(len(calls), len(UNITS))
        self.assertEqual(snapshot["mode"], "read_only")
        self.assertEqual(snapshot["generated_at"], "2026-10-16T00:00:00Z")
        self.assertEqual(snapshot["services"][-1]["state"], "unexpected_active")
        for argv, kwargs in calls:
            self.assertEqual(argv[:4], ["systemctl", "show", "--no-pager", "--property=ActiveState"])
            self.assertIn(argv[-1], {unit for _, _, unit, _ in UNITS})
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["timeout"], 3)

    def test_non_running_agent_does_not_report_healthy(self):
        def run(argv, **kwargs):
            return type("P", (), {"returncode": 0, "stdout": "LoadState=loaded\nActiveState=inactive\n"})()
        self.assertEqual(collect(run)["services"][-1]["state"], "blocked")

    def test_missing_unit_unknown(self):
        def run(argv, **kwargs):
            return type("P", (), {"returncode": 0, "stdout": "LoadState=not-found\nActiveState=inactive\n"})()
        self.assertEqual(unit_state("fake.service", run), "unknown")


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "overview.json"
        self.path.write_text(json.dumps({"schema": 1, "mode": "read_only", "services": []}))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.path))
        self.thread = Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def request(self, path, host="hermes.mikemoore.top", method="GET"):
        req = Request(f"http://127.0.0.1:{self.srv.server_port}{path}",
                      headers={"Host": host}, method=method)
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, response.headers, response.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def test_healthz_and_csp(self):
        code, headers, data = self.request("/healthz")
        self.assertEqual((code, data), (200, b"ok"))
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_snapshot_is_read_only(self):
        code, hdr, data = self.request("/api/overview")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(data)["mode"], "read_only")
        self.assertEqual(hdr["Cache-Control"], "no-store")
        self.assertEqual(self.request("/api/overview", method="HEAD")[2], b"")

    def test_missing_snapshot_fail_closed(self):
        self.path.unlink()
        code, _, raw = self.request("/api/overview")
        self.assertEqual(code, 503)
        self.assertEqual(json.loads(raw)["error"], "snapshot_unavailable")

    def test_unknown_route_and_wrong_host(self):
        self.assertEqual(self.request("/../../etc/passwd")[0], 404)
        self.assertEqual(self.request("/", host="attacker.invalid")[0], 400)

    def test_static_assets_exist(self):
        for route in ("/", "/style.css", "/app.js"):
            code, hdr, raw = self.request(route)
            self.assertEqual(code, 200)
            self.assertGreater(len(raw), 200)


if __name__ == "__main__":
    unittest.main()
