"""Owner-only Desktop Commander API plus additive UI route negative checks."""
import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig
from control_center.desktop_commander import normalize, save_snapshot
from control_center.server import make_handler


class DenyAll:
    def authenticated(self, cookie):
        return False


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        overview = root / "overview.json"
        overview.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "services": [],
        }))
        self.dc = root / "dc.json"
        save_snapshot(normalize({"remote_calls_left_pct": 0},
                                "1. VPS\n   Status: Online\n"), self.dc)
        config = AuthConfig(mode="github", client_id="Ov23abcdefghijk",
                            owner_id=10001, session_secret=b"synthetic-key-over-32-bytes-and-unused")
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(overview, desktop_commander_path=self.dc,
                         auth_config=config, oauth_service=DenyAll()))
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(3)
        self.dir.cleanup()

    def get(self, path):
        request = Request(f"http://127.0.0.1:{self.httpd.server_port}{path}",
                          headers={"Host": "hermes.mikemoore.top"})
        try:
            with urlopen(request, timeout=2) as result:
                return result.status, result.read()
        except HTTPError as exc:
            return exc.code, exc.read()

    def test_private_data_requires_owner(self):
        for path in ("/api/providers/desktop-commander",
                     "/control-center/api/providers/desktop-commander"):
            code, body = self.get(path)
            self.assertEqual(code, 401)
            self.assertIn(b"authentication_required", body)
            self.assertNotIn(b"VPS", body)

    def test_widget_assets_are_static_but_api_remains_private(self):
        index_code, index = self.get("/")
        self.assertEqual(index_code, 200)
        self.assertIn(b'/desktop-commander.js', index)
        self.assertIn(b'/desktop-commander.css', index)
        self.assertEqual(self.get("/desktop-commander.js")[0], 200)
        self.assertEqual(self.get("/desktop-commander.css")[0], 200)
        self.assertEqual(self.get("/desktop-commander.js?x=1")[0], 404)


if __name__ == "__main__":
    unittest.main()
