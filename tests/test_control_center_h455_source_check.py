"""#455: auth-bound source verification must not call tools or grant access."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import tempfile
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
import unittest

from control_center.auth import AuthConfig
from control_center.brc_snapshot import DEVICES, PROJECTS, normalize
from control_center.server import make_handler


class Owner:
    def authenticated(self, cookie):
        return cookie == "test_owner"


class BrcSourceChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h455-source-check-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sanitized.json"
        self.publish()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                auth_config=AuthConfig(mode="github"), oauth_service=Owner(),
                brc_snapshot_path=self.path
            ),
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def publish(self):
        now = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
        device_id = "h15-win-test0001"
        data = normalize(
            {"devices": [
                {"name": name, "deviceId": device_id if i == 0 else f"h15-test-{i:04d}",
                 "online": True, "paused": False, "lastSeen": now - 4000}
                for i, name in enumerate(DEVICES)
            ]},
            {"schema": 1, "status": "catalog", "workspaces": [
                {"name": name, "scope": "sandbox", "root": "/workspace/projects/" + name,
                 "branch": branch,
                 "origin": f"https://github.com/MikeMoore1337/{name}.git",
                 "deviceId": device_id, "device_status": "online",
                 "git_verified": False}
                for name, branch in PROJECTS.items()
            ]},
            now_ms=now,
        )
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def get(self, suffix, *, owner=False, host="localhost:9133", method="GET"):
        headers = {"Host": host}
        if owner:
            headers["Cookie"] = "hermes_cc_session=test_owner"
        request = Request(
            f"http://127.0.0.1:{self.server.server_port}" + suffix,
            headers=headers, method=method
        )
        try:
            res = build_opener(ProxyHandler({})).open(request, timeout=5)
        except HTTPError as error:
            res = error
        with res:
            return res.status, res.headers, res.read()

    def test_owner_check_is_read_only_and_truthful(self):
        before = self.path.read_bytes()
        code, headers, payload = self.get(
            "/api/providers/hermes-brc/source-check", owner=True
        )
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        info = json.loads(payload)
        self.assertEqual(info["check"], "snapshot_validity_only")
        self.assertEqual(info["verification"]["snapshot"], "valid")
        self.assertEqual(info["verification"]["tools"], "not_probed")
        self.assertEqual(info["verification"]["relay"], "not_probed")
        self.assertEqual(info["verification"]["git"], "not_probed")
        self.assertEqual(info["verification"]["onboarding"], "disabled")
        self.assertEqual(info["verification"]["native_host"], "disabled")
        self.assertEqual(len(info["devices"]), 3)
        self.assertEqual([d["command_execution"] for d in info["devices"]],
                         ["not_verified"] * 3)
        self.assertNotIn(b"deviceId", payload)
        self.assertNotIn(b"host-private", payload)
        self.assertEqual(self.path.read_bytes(), before)

    def test_guest_query_wrong_host_and_head(self):
        route = "/api/providers/hermes-brc/source-check"
        self.assertEqual(self.get(route)[0], 401)
        self.assertEqual(self.get("/control-center" + route)[0], 401)
        self.assertEqual(self.get(route + "?deviceId=guess", owner=True)[0], 404)
        self.assertEqual(self.get(route, host="evil.example", owner=True)[0], 400)
        code, headers, body = self.get(route, owner=True, method="HEAD")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_fail_closed_on_stale_forged_or_symlinked(self):
        route = "/api/providers/hermes-brc/source-check"
        data = json.loads(self.path.read_text())
        data["observed_at"] = "2020-01-01T00:00:00Z"
        self.path.write_text(json.dumps(data))
        self.assertEqual(self.get(route, owner=True)[0], 503)
        self.publish()
        data = json.loads(self.path.read_text())
        data["native_host_access"] = True
        self.path.write_text(json.dumps(data))
        self.assertEqual(self.get(route, owner=True)[0], 503)
        self.publish()
        valid = self.path.with_name("valid.json")
        valid.write_bytes(self.path.read_bytes())
        self.path.unlink()
        self.path.symlink_to(valid)
        self.assertEqual(self.get(route, owner=True)[0], 503)


if __name__ == "__main__":
    unittest.main()
