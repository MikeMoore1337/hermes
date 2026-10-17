"""History must preserve actual snapshots, omit PII and never synthesize recoveries."""
import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.desktop_commander import normalize, save_snapshot
from control_center.desktop_commander_history import append, read, HistoryError
from control_center.server import make_handler


NOW = dt.datetime(2026, 10, 17, 21, 0, tzinfo=dt.timezone.utc)
DEVICES = "1. vps1777112993\n   Status: Online\n   ID: SENSITIVE_DEVICE_ID\n"


class HistoryTests(unittest.TestCase):
    def test_history_is_bounded_and_privacy_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "history.sqlite3"
            self.assertEqual(read(path, now=NOW)["status"], "not_configured")
            for i in range(530):
                at = NOW - dt.timedelta(minutes=530 - i)
                append(normalize({"remote_calls_left_pct": i % 100,
                                  "email": "SECRET_EMAIL", "access_token": "SECRET_TOKEN"},
                                 DEVICES, at), path, now=NOW if i >= 515 else at)
            result = read(path, days=1, now=NOW)
            self.assertEqual(len(result["points"]), 500)
            self.assertEqual(result["points"][0]["online"], 1)
            self.assertEqual(result["points"][-1]["remaining_percent"], 29)
            raw = path.read_bytes()
            self.assertNotIn(b"SECRET_EMAIL", raw)
            self.assertNotIn(b"SENSITIVE_DEVICE_ID", raw)
            self.assertNotIn(b"SECRET_TOKEN", raw)

    def test_out_of_window_rejected_and_duplicate_deduped(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "history.sqlite3"
            a = normalize({"remote_calls_left_pct": 0}, DEVICES, NOW)
            append(a, path, now=NOW)
            append(a, path, now=NOW)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)
            with self.assertRaises(ValueError):
                append(a, path, now=NOW + dt.timedelta(hours=1))
            self.assertEqual(read(path, now=NOW)["points"][0]["status"], "exhausted")
            for bad in (0, 31, True, "7"):
                with self.assertRaises(ValueError):
                    read(path, days=bad, now=NOW)


class HistoryHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        overview = root / "overview.json"
        overview.write_text(json.dumps({"schema": 1, "mode": "read_only",
                                        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                                        "services": []}))
        self.dc = root / "dc.json"
        data = normalize({"remote_calls_left_pct": 0}, DEVICES)
        save_snapshot(data, self.dc)
        append(data, self.dc.with_name("history.sqlite3"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          make_handler(overview, desktop_commander_path=self.dc))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()

    def get(self, query=""):
        req = Request(f"http://127.0.0.1:{self.server.server_port}/api/providers/desktop-commander/history{query}",
                      headers={"Host": "hermes.mikemoore.top"})
        try:
            with urlopen(req, timeout=2) as res:
                return res.status, res.read()
        except HTTPError as err:
            return err.code, err.read()

    def test_history_route_and_query_validation(self):
        code, raw = self.get("?days=1")
        self.assertEqual(code, 200)
        result = json.loads(raw)
        self.assertEqual(result["days"], 1)
        self.assertEqual(result["points"][-1]["remaining_percent"], 0)
        for q in ("?days=0", "?days=31", "?days=7&days=1",
                  "?days=7&other=x", "?days=x", "?other=x"):
            self.assertEqual(self.get(q)[0], 400, q)
        self.dc.with_name("history.sqlite3").write_text("corrupt history")
        self.assertEqual(self.get()[0], 503)


if __name__ == "__main__":
    unittest.main()
