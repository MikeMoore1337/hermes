"""Read-only Hermes BRC Control Center endpoint contract (#455)."""
from __future__ import annotations

import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.brc_snapshot import (
    DEVICES, PROJECTS, SnapshotRejected, normalize, read_snapshot,
)
from control_center.server import make_handler


def safe_observation(now: dt.datetime):
    now_ms = int(now.timestamp() * 1000)
    names = ("h15-win-05be75515428", "h15-hermes-ab005bc0e0ea",
             "h15-yfc-c6ee0d53e858")
    devices = {"devices": [
        {"name": label, "deviceId": identity, "online": True,
         "paused": False, "lastSeen": now_ms - 1000}
        for label, identity in zip(DEVICES, names)
    ]}
    catalog = {"schema": 1, "status": "catalog", "workspaces": [
        {"name": name, "scope": "sandbox", "deviceId": names[0],
         "root": f"/workspace/projects/{name}", "branch": branch,
         "origin": f"https://github.com/MikeMoore1337/{name}.git",
         "device_status": "online", "git_verified": False}
        for name, branch in PROJECTS.items()
    ]}
    return normalize(devices, catalog, now_ms=now_ms)


class SnapshotReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "snapshot.json"
        self.now = dt.datetime.now(dt.timezone.utc)
        self.public = safe_observation(self.now)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_then_valid_snapshot_is_read_only(self):
        with self.assertRaises(SnapshotRejected):
            read_snapshot(self.path, now=self.now)
        self.path.write_text(json.dumps(self.public), encoding="utf-8")
        result = read_snapshot(self.path, now=self.now)
        self.assertEqual(result, self.public)
        self.assertNotIn("deviceId", json.dumps(result))
        self.assertFalse(result["native_host_access"])
        self.assertFalse(result["execution_verified"])

    def test_stale_forged_private_or_oversized_snapshot_rejected(self):
        self.path.write_text(json.dumps(self.public), encoding="utf-8")
        with self.assertRaisesRegex(SnapshotRejected, "stale"):
            read_snapshot(self.path, now=self.now + dt.timedelta(minutes=8))
        for update in (
            lambda x: x.update({"deviceId": "SECRET_SENTINEL"}),
            lambda x: x["devices"][0].update({"command_execution": "verified"}),
            lambda x: x["workspaces"][0].update({"root": "/host-private/hermes"}),
            lambda x: x.update({"native_host_access": True}),
            lambda x: x["devices"][1].update({"name": "unapproved"}),
            lambda x: x.update({"observed_at": "1990-01-01T00:00:00Z"}),
        ):
            payload = json.loads(json.dumps(self.public))
            update(payload)
            self.path.write_text(json.dumps(payload), encoding="utf-8")
            with self.subTest(update=update), self.assertRaises(SnapshotRejected):
                read_snapshot(self.path, now=self.now)
        self.path.write_bytes(b"x" * 17000)
        with self.assertRaises(SnapshotRejected):
            read_snapshot(self.path, now=self.now)


class SnapshotHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        overview = base / "overview.json"
        overview.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "services": [],
        }), encoding="utf-8")
        self.path = base / "brc.json"
        self.http = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(overview, brc_snapshot_path=self.path))
        self.thread = Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(3)
        self.tmp.cleanup()

    def get(self, method="GET", path="/api/providers/hermes-brc"):
        req = Request(
            f"http://127.0.0.1:{self.http.server_port}{path}",
            headers={"Host": "hermes.mikemoore.top"}, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            return error.code, error.headers, error.read()

    def test_unavailable_status_query_guard_and_no_mutations(self):
        status, headers, raw = self.get()
        self.assertEqual(status, 503)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(b"SECRET_SENTINEL", raw)
        self.assertEqual(self.get(path="/api/providers/hermes-brc?q=1")[0], 404)
        self.assertEqual(self.get(method="POST")[0], 501)
        self.assertEqual(self.get(method="HEAD")[2], b"")

    def test_only_sanitized_snapshot_served_without_secrets(self):
        data = safe_observation(dt.datetime.now(dt.timezone.utc))
        self.path.write_text(json.dumps(data), encoding="utf-8")
        status, headers, raw = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(raw), data)
        self.assertNotIn(b"h15-win-", raw)
        self.assertFalse(json.loads(raw)["execution_verified"])
        self.assertEqual(self.get(path="/control-center/api/providers/hermes-brc")[0], 200)
        tampered = dict(data, malicious_token="SECRET_SENTINEL")
        self.path.write_text(json.dumps(tampered), encoding="utf-8")
        self.assertEqual(self.get()[0], 503)
        self.assertNotIn(b"SECRET_SENTINEL", self.get()[2])


if __name__ == "__main__":
    unittest.main()
