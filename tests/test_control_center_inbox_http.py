"""Owner-only Operator Inbox HTTP contract on existing Control Center server."""
from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig
from control_center.server import make_handler
from control_center.snapshot import UNITS


class _FakeOAuth:
    def authenticated(self, cookie):
        return cookie == "owner-session"


class InboxHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.snapshot = Path(self.tmp.name) / "overview.json"
        self.snapshot.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "services": [
                {"id": i, "name": label, "unit": unit, "kind": kind,
                 "state": ("failed" if i == "ops" else "blocked" if i == "agent" else "active")}
                for i, label, unit, kind in UNITS],
        }), encoding="utf-8")
        # A non-existing scheduler file returns 'not_configured', no fabricated queue.
        self.scheduler = Path(self.tmp.name) / "missing-scheduler.db"
        self.codex = Path(self.tmp.name) / "missing-quota.json"

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, port, path, *, method="GET", cookie=None, host="hermes.mikemoore.top"):
        headers = {"Host": host}
        if cookie is not None:
            headers["Cookie"] = cookie
        req = Request(f"http://127.0.0.1:{port}{path}", headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as res:
                return res.status, res.headers, res.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def serve(self, *, auth=None, oauth=None):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            snapshot_path=self.snapshot, scheduler_path=self.scheduler,
            codex_path=self.codex,
            auth_config=auth or AuthConfig(mode="proxy"), oauth_service=oauth))
        worker = Thread(target=srv.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), worker.join(timeout=3)))
        return srv.server_port

    def test_existing_proxy_boundary_returns_sanitized_inbox(self):
        port = self.serve()
        code, headers, raw = self.request(port, "/api/operator/inbox")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        data = json.loads(raw)
        self.assertFalse(data["actions_enabled"])
        self.assertEqual(data["summary"]["critical"], 1)
        self.assertEqual(data["sources"]["brc"]["status"], "NOT_AVAILABLE")
        self.assertEqual(data["events"][0]["event_id"], "systemd:ops")
        self.assertNotIn("hermes-ops-watch.timer", raw.decode())
        self.assertEqual(self.request(port, "/api/operator/inbox", method="HEAD")[2], b"")
        self.assertEqual(self.request(port, "/api/operator/inbox?refresh=true")[0], 404)
        self.assertEqual(self.request(port, "/api/operator/inbox", method="POST")[0], 501)
        self.assertEqual(self.request(port, "/api/operator/inbox", host="evil.example")[0], 400)

    def test_oauth_denied_before_sensitive_lookups(self):
        # In OAuth mode a cookie must be verified; no ambient proxy bypass.
        port = self.serve(auth=AuthConfig(mode="github"), oauth=_FakeOAuth())
        code, _, raw = self.request(port, "/api/operator/inbox")
        self.assertEqual(code, 401)
        self.assertEqual(json.loads(raw)["error"], "authentication_required")
        code, _, raw = self.request(port, "/control-center/api/operator/inbox")
        self.assertEqual(code, 401)
        code, _, raw = self.request(
            port, "/api/operator/inbox", cookie="hermes_cc_session=owner-session")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["mode"], "read_only")

    def test_missing_or_stale_snapshot_not_reported_healthy(self):
        port = self.serve()
        self.snapshot.unlink()
        code, _, raw = self.request(port, "/api/operator/inbox")
        self.assertEqual(code, 200)
        data = json.loads(raw)
        self.assertEqual(data["sources"]["systemd"]["status"], "NOT_AVAILABLE")
        self.assertEqual(data["summary"]["available_sources"], 0)
        self.assertEqual(data["summary"]["total"], 0)
        self.assertEqual(data["completeness"], "PARTIAL")
        self.snapshot.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": "2020-01-01T00:00:00+00:00", "services": []}))
        code, _, raw = self.request(port, "/api/operator/inbox")
        self.assertEqual(code, 200)
        data = json.loads(raw)
        self.assertEqual(data["sources"]["systemd"]["status"], "STALE")
        self.assertEqual(data["summary"]["review"], 1)


if __name__ == "__main__":
    unittest.main()
