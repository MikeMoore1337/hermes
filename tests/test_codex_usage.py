"""Codex read-only usage collector, validation, RPC and authenticated HTTP contract."""
import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from queue import Queue
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.codex_usage import (
    AuthRequired, UsageError, normalize, error_snapshot, query_app_server,
    read_snapshot, save_snapshot, window,
)
from control_center.server import make_handler

NOW = dt.datetime(2026, 10, 17, 12, 0, tzinfo=dt.timezone.utc)


def provider_data():
    return {
        "rateLimitsByLimitId": {
            "codex": {
                "primary": {"usedPercent": 40, "windowDurationMins": 300, "resetsAt": 1792240000},
                "secondary": {"usedPercent": 85, "windowDurationMins": 10080, "resetsAt": 1792540000},
            },
            "codex_spark": {
                "primary": {"usedPercent": 20, "windowDurationMins": 300},
                "secondary": None,
            },
        },
        "ordinaryUsageAllowed": True,
        "accessToken": "LEAK_NOT_ALLOWED",
        "email": "LEAK_NOT_ALLOWED@example.com",
    }


class NormalizationTests(unittest.TestCase):
    def test_multi_windows_and_redaction(self):
        result = normalize(provider_data(), NOW)
        self.assertEqual(result["status"], "low")
        self.assertEqual(result["observed_at"], "2026-10-17T12:00:00Z")
        self.assertEqual([v["limit_id"] for v in result["limits"]], ["codex", "codex_spark"])
        self.assertEqual(result["limits"][0]["windows"][0]["remaining_percent"], 60)
        self.assertEqual(result["limits"][0]["windows"][1]["duration_minutes"], 10080)
        self.assertNotIn("LEAK_NOT_ALLOWED", json.dumps(result))

    def test_single_and_absent_windows(self):
        data = normalize({"rateLimits": {"primary": {"usedPercent": 100},
                                         "secondary": None}}, NOW)
        self.assertEqual(data["status"], "exhausted")
        self.assertEqual(data["limits"][0]["windows"][0]["remaining_percent"], 0)
        self.assertEqual(normalize({"rateLimits": None}, NOW)["status"], "unknown")

    def test_explicit_denial_and_mixed(self):
        data = provider_data()
        data["ordinaryUsageAllowed"] = False
        self.assertEqual(normalize(data, NOW)["status"], "exhausted")
        data["ordinaryUsageAllowed"] = None
        data["rateLimitsByLimitId"]["codex"]["rateLimitReachedType"] = "primary"
        self.assertEqual(normalize(data, NOW)["status"], "limited")

    def test_window_validation(self):
        for v in (-1, 101, float("nan"), True, "45"):
            self.assertIsNone(window({"usedPercent": v}))
        self.assertEqual(window({"usedPercent": 25, "windowDurationMins": 0,
                                 "resetsAt": "bad"})["resets_at"], None)
        with self.assertRaises(UsageError):
            normalize([])

    def test_snapshot_status_and_ttl(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "usage.json"
            self.assertEqual(read_snapshot(path)["status"], "not_configured")
            save_snapshot(normalize(provider_data(), NOW), path)
            self.assertEqual(read_snapshot(path, NOW)["status"], "low")
            self.assertEqual(read_snapshot(path, NOW + dt.timedelta(minutes=20))["status"], "stale")
            tampered = normalize(provider_data(), NOW)
            tampered["access_token"] = "must-not-leak"
            path.write_text(json.dumps(tampered))
            with self.assertRaises(UsageError):
                read_snapshot(path)
            path.write_text('{"schema":999}')
            with self.assertRaises(UsageError):
                read_snapshot(path)

    def test_probe_failure_excludes_error_text(self):
        self.assertEqual(error_snapshot("auth_required", NOW)["limits"], [])
        self.assertNotIn("token", json.dumps(error_snapshot("unavailable", NOW)))


class FakeInput:
    def __init__(self, proc):
        self.proc = proc
        self.buffer = ""

    def write(self, value):
        self.buffer += value

    def flush(self):
        request = json.loads(self.buffer)
        self.buffer = ""
        if request.get("id") == 1:
            self.proc.events.put(json.dumps({"method": "random/notification", "params": {}})+"\n")
            self.proc.events.put(json.dumps({"id": 1, "result": {"server": "ok"}})+"\n")
        elif request.get("id") == 2:
            if self.proc.denied:
                response = {"id": 2, "error": {"code": -32600, "message": "chatgpt authentication required"}}
            else:
                response = {"id": 2, "result": provider_data()}
            self.proc.events.put(json.dumps(response)+"\n")


class FakeProcess:
    def __init__(self, denied=False):
        self.denied = denied
        self.events = Queue()
        self.stdin = FakeInput(self)
        self.stdout = self
        self.stopped = False

    def __iter__(self):
        while True:
            value = self.events.get()
            if value is None:
                return
            yield value

    def poll(self):
        return 0 if self.stopped else None

    def terminate(self):
        self.stopped = True
        self.events.put(None)

    def kill(self):
        self.terminate()

    def communicate(self, timeout=None):
        return "", ""


class RpcTests(unittest.TestCase):
    def test_rpc_handshake_and_notifications(self):
        with patch("control_center.codex_usage.subprocess.Popen", return_value=FakeProcess()) as popen:
            self.assertEqual(normalize(query_app_server())["status"], "low")
            self.assertEqual(popen.call_args.args[0], ["codex", "app-server"])

    def test_auth_required(self):
        with patch("control_center.codex_usage.subprocess.Popen", return_value=FakeProcess(denied=True)):
            with self.assertRaises(AuthRequired):
                query_app_server()


class CodexHttpTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.snapshot = root / "overview.json"
        self.snapshot.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "services": [],
        }))
        self.codex = root / "codex.json"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                         make_handler(self.snapshot, codex_path=self.codex))
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.dir.cleanup()

    def request(self, method="GET"):
        req = Request("http://127.0.0.1:"+str(self.httpd.server_port)+"/api/providers/codex",
                      headers={"Host": "hermes.mikemoore.top"}, method=method)
        try:
            with urlopen(req, timeout=2) as res:
                return res.status, res.headers, res.read()
        except HTTPError as err:
            return err.code, err.headers, err.read()

    def test_not_configured_and_no_cache(self):
        code, headers, body = self.request()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(json.loads(body)["status"], "not_configured")
        self.assertEqual(self.request("HEAD")[2], b"")

    def test_live_and_invalid(self):
        save_snapshot(normalize(provider_data()), self.codex)
        self.assertEqual(json.loads(self.request()[2])["status"], "low")
        self.codex.write_text("bad json")
        self.assertEqual(self.request()[0], 503)


if __name__ == "__main__":
    unittest.main()
