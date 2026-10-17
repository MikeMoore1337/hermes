"""H-15 #271: owner-only read-only queue projection and negative HTTP routes."""
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from codex_scheduler import Approval, Scheduler
from codex_scheduler.status import read_status, StatusUnavailable
from control_center.auth import AuthConfig
from control_center.codex_usage import normalize, save_snapshot
from control_center.server import make_handler

NOW = datetime.now(timezone.utc)
REPO = "MikeMoore1337/hermes"
RESOURCES = {"max_runtime_seconds": 30, "max_memory_mb": 256, "max_output_bytes": 4096}


def _decode(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return {}


class NoOAuth:
    def authenticated(self, value):
        return False


class QueueStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "jobs.sqlite3"
        self.usage = root / "usage.json"
        self.queue = Scheduler(self.db, repositories={REPO}, models={"mock"},
                               clock=lambda: NOW.timestamp())
        sample = normalize({"ordinaryUsageAllowed": True, "rateLimitsByLimitId":
             {"codex": {"primary": {"usedPercent": 30, "windowDurationMins": 300},
                        "secondary": {"usedPercent": 40, "windowDurationMins": 10080}}}}, NOW)
        save_snapshot(sample, self.usage)
        self.http = None

    def tearDown(self):
        if self.http:
            self.http.shutdown()
            self.http.server_close()
            self.thread.join(timeout=3)
        self.tmp.cleanup()

    def start(self, *, github=False):
        conf = AuthConfig(mode="github") if github else AuthConfig()
        self.http = ThreadingHTTPServer(("127.0.0.1", 0),
             make_handler(self.usage, codex_path=self.usage,
                          scheduler_path=self.db, auth_config=conf,
                          oauth_service=NoOAuth() if github else None))
        self.thread = Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def request(self, route, method="GET"):
        req = Request(f"http://127.0.0.1:{self.http.server_port}{route}",
                      headers={"Host": "hermes.mikemoore.top"}, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, _decode(response.read())
        except HTTPError as error:
            return error.code, _decode(error.read())

    def test_missing_db_not_mistaken_for_live_worker(self):
        base = read_status(self.db)
        self.assertEqual(base["queue_state"], "not_configured")
        self.assertFalse(base["execution_enabled"])
        self.assertEqual(base["counts"]["running"], 0)

    def test_projection_counts_and_privacy(self):
        self.queue.initialize()
        self.queue.register_approval(Approval("verified-owner-1000", "MikeMoore1337",
            REPO, ("inspect",), "mock", "low", RESOURCES,
            (NOW + timedelta(days=2)).isoformat()), verified_owner="MikeMoore1337")
        task = self.queue.submit({"schema_version": 1, "requested_at": NOW.isoformat(),
           "expires_at": (NOW + timedelta(days=1)).isoformat(),
           "initiator": "MikeMoore1337", "approval_id": "verified-owner-1000",
           "repository": REPO, "allowed_operations": ["inspect"],
           "model": "mock", "effort": "low", "resource_limits": RESOURCES,
           "idempotency_key": "synthetic-task-1000"})
        self.start()
        code, body = self.request("/api/codex/tasks")
        self.assertEqual(code, 200)
        self.assertEqual(body["counts"]["queued"], 1)
        self.assertEqual(body["jobs"][0]["job_id"], task["job_id"])
        self.assertFalse(body["execution_enabled"])
        self.assertEqual(body["quota"]["decision"], "ALLOW")
        dump = json.dumps(body)
        for secret in ("approval_id", "idempotency_key", "resource_limits",
                       "model", "access_token", "CODEX_HOME"):
            self.assertNotIn(secret, dump)
        self.assertEqual(self.request("/api/codex/tasks?key=1")[0], 404)
        self.assertEqual(self.request("/api/codex/tasks", method="POST")[0], 501)

    def test_denied_without_github_session(self):
        self.start(github=True)
        self.assertEqual(self.request("/api/codex/tasks")[0], 401)

    def test_missing_database_read_only_and_corrupt_database(self):
        self.start()
        self.assertEqual(self.request("/api/codex/tasks")[1]["queue_state"], "not_configured")
        self.db.write_bytes(b"not a sqlite database")
        self.assertEqual(self.request("/api/codex/tasks")[0], 503)

    def test_symlink_db_fail_closed(self):
        target = Path(self.tmp.name) / "other.sqlite"
        target.write_text("decoy")
        self.db.symlink_to(target)
        with self.assertRaises(StatusUnavailable):
            read_status(self.db)


if __name__ == "__main__":
    unittest.main()
