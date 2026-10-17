"""Owner-only read-only Codex analytics endpoint contract, offline."""
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig
from control_center.server import make_handler
from control_center.codex_analytics import collect


class _OAuth:
    def __init__(self):
        self.allowed = False

    def authenticated(self, _cookie):
        return self.allowed


class AnalyticsApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name) / "codex"
        folder = home / "sessions/2026/10/18"
        folder.mkdir(parents=True)
        folder.joinpath("rollout-2026-10-18T00-00-00-019acd30-197e-7000-8000-000000000001.jsonl").write_text(
            json.dumps({"timestamp": "2026-10-18T00:00:00Z", "type": "event_msg",
                        "payload": {"type": "token_count", "info": {"total_token_usage": {
                            "input_tokens": 100, "output_tokens": 20, "cached_input_tokens": 30
                        }}, "secret": "DO_NOT_EXPOSE"}})+"\n")
        self.database = Path(self.tmp.name) / "analytics.sqlite3"
        collect(home, self.database)
        self.auth = _OAuth()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            analytics_path=self.database, auth_config=AuthConfig(mode="github"),
            oauth_service=self.auth))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.tmp.cleanup()

    def get(self, path, method="GET"):
        req = Request("http://127.0.0.1:"+str(self.server.server_port)+path,
                      headers={"Host": "hermes.mikemoore.top"}, method=method)
        try:
            with urlopen(req, timeout=3) as res:
                return res.status, res.headers, res.read()
        except HTTPError as err:
            return err.code, err.headers, err.read()

    def test_no_owner_no_access(self):
        self.assertEqual(self.get("/api/analytics/codex")[0], 401)
        self.assertEqual(self.get("/control-center/api/analytics/codex")[0], 401)
        self.assertEqual(self.get("/api/analytics/codex", method="POST")[0], 501)

    def test_read_only_no_secret_or_private_path(self):
        self.auth.allowed = True
        status, headers, body = self.get("/api/analytics/codex?period=all")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(body)["tokens"]["total"], 120)
        self.assertIsNone(json.loads(body)["actual_spend_usd"])
        self.assertNotIn(b"DO_NOT_EXPOSE", body)
        self.assertNotIn(str(self.tmp.name).encode(), body)
        self.assertEqual(self.get("/api/analytics/codex?period=all", method="HEAD")[2], b"")
        self.assertEqual(self.get("/api/analytics/codex?period=oops")[0], 400)
        self.assertEqual(self.get("/api/analytics/codex?period=7d&junk=1")[0], 400)
        self.assertEqual(self.get("/api/analytics/codex?period=7d&period=all")[0], 400)


if __name__ == "__main__":
    unittest.main()
