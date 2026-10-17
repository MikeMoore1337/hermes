"""H-15 #271: synthetic, no Codex CLI, network, credentials or billed inference."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3
import tempfile
from pathlib import Path
import unittest

from control_center.codex_usage import normalize, error_snapshot
from control_center.codex_scheduler import Approval, Scheduler, QuotaWorker, ValidationError, ConflictError

BASE = datetime(2026, 10, 17, 15, 0, tzinfo=timezone.utc)
REPO = "MikeMoore1337/hermes"
LIMITS = {"max_runtime_seconds": 30, "max_memory_mb": 256, "max_output_bytes": 8192}
APPROVAL_ID = "owner-proof-20261017"
KEY = "unique-job-request-one"


def at(moment):
    return moment.isoformat().replace("+00:00", "Z")


def snapshot(moment=BASE, short=30, week=40, ordinary=True, extra=None):
    groups = {"codex": {"primary": {"usedPercent": short, "windowDurationMins": 300},
                         "secondary": {"usedPercent": week, "windowDurationMins": 10080}}}
    if extra is not None:
        groups["other"] = {"primary": {"usedPercent": extra, "windowDurationMins": 30}}
    return normalize({"ordinaryUsageAllowed": ordinary, "rateLimitsByLimitId": groups}, moment)


class MockExecutor:
    def __init__(self, outcome=(True, "mock:artifact1")):
        self.calls = 0
        self.outcome = outcome

    def execute(self, job):
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scheduler.sqlite3"
        self.now = BASE
        self.queue = Scheduler(self.path, repositories={REPO}, models={"test-codex"},
                               clock=lambda: self.now.timestamp())
        self.queue.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def approve(self, *, expiry=timedelta(days=2), ops=("inspect", "test"),
                max_runtime=30, approval_id=APPROVAL_ID):
        grant = Approval(approval_id, "MikeMoore1337", REPO, ops,
                         "test-codex", "medium",
                         {**LIMITS, "max_runtime_seconds": max_runtime},
                         at(self.now + expiry))
        self.queue.register_approval(grant, verified_owner="MikeMoore1337")
        return grant

    def request(self, **overrides):
        task = {
            "schema_version": 1,
            "requested_at": at(BASE), "expires_at": at(BASE + timedelta(days=1)),
            "initiator": "MikeMoore1337", "approval_id": APPROVAL_ID,
            "repository": REPO, "allowed_operations": ["inspect"],
            "model": "test-codex", "effort": "medium",
            "resource_limits": dict(LIMITS), "idempotency_key": KEY,
        }
        task.update(overrides)
        return task

    def create(self):
        self.approve()
        return self.queue.submit(self.request())

    def worker(self, source=None, executor=None):
        tool = executor or MockExecutor()
        return QuotaWorker(self.queue, source or (lambda: snapshot(self.now)),
                           tool, "synthetic-worker-01"), tool

    def test_authorized_submission_and_idempotent_result(self):
        first = self.create()
        self.assertEqual(first["status"], "queued")
        self.assertEqual(first["schema_version"], 1)
        self.assertEqual(first["attempt_count"], 0)
        self.assertEqual(first["job_id"], self.queue.submit(self.request())["job_id"])
        worker, mock = self.worker()
        self.assertEqual(worker.tick()["decision"], "succeeded")
        self.assertEqual(mock.calls, 1)
        self.assertIsNone(worker.tick())
        receipt = self.queue.acknowledge_result(first["job_id"])
        same = self.queue.acknowledge_result(first["job_id"])
        self.assertEqual(receipt["delivered_at"], same["delivered_at"])
        self.assertEqual(receipt["result_ref"], "mock:artifact1")
        self.assertEqual(mock.calls, 1)

    def test_owner_approval_is_required_and_immutable(self):
        with self.assertRaises(ValidationError):
            self.queue.submit(self.request())
        with self.assertRaises(ValidationError):
            self.queue.register_approval(Approval(APPROVAL_ID, "MikeMoore1337",
                REPO, ("inspect",), "test-codex", "medium", LIMITS,
                at(BASE + timedelta(days=1))), verified_owner="unknown")
        self.approve()
        with self.assertRaises(ConflictError):
            self.approve(ops=("patch",))

    def test_schema_scope_budget_identity_rejections(self):
        self.approve()
        invalid = [
            {"job_id": "forged"}, {"status": "succeeded"},
            {"command": "rm -rf /"}, {"idempotency_key": "short"},
            {"repository": "someone/other"}, {"model": "unknown"},
            {"allowed_operations": ["patch"]}, {"allowed_operations": ["shell"]},
            {"allowed_operations": ["inspect", "inspect"]},
            {"resource_limits": {**LIMITS, "max_memory_mb": 4096}},
            {"schema_version": True}, {"expires_at": at(BASE + timedelta(days=9))},
            {"approval_id": "forged-approval-123"},
        ]
        for extra in invalid:
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                self.queue.submit(self.request(**extra))
        first = self.queue.submit(self.request())
        with self.assertRaises(ConflictError):
            self.queue.submit(self.request(allowed_operations=["test"]))
        self.assertEqual(first["job_id"], self.queue.submit(self.request())["job_id"])

    def test_approval_expiry_before_submission_and_before_launch(self):
        with self.assertRaises(ValidationError):
            self.approve(expiry=timedelta(seconds=-1))
        self.approve(expiry=timedelta(days=1))
        j = self.queue.submit(self.request())
        self.now += timedelta(days=1, seconds=1)
        self.assertIsNone(self.queue.claim("synthetic-worker-01"))
        self.assertEqual(self.queue.get(j["job_id"])["status"], "cancelled")

    def test_two_competing_claims_are_serialized(self):
        job = self.create()
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = list(pool.map(self.queue.claim,
                                 ["synthetic-worker-01", "synthetic-worker-02"]))
        self.assertEqual(sum(x is not None for x in (a, b)), 1)
        claimed = a or b
        self.assertEqual(claimed["job_id"], job["job_id"])
        with self.assertRaises(ConflictError):
            self.queue.assess(job["job_id"], "synthetic-worker-wrong",
                              claimed["fencing_token"], snapshot(self.now))

    def test_defer_all_quota_windows_and_resume_only_on_new_snapshot(self):
        cases = [(100, 40), (30, 100), (100, 100), (0, 100)]
        for short, week in cases:
            with self.subTest(short=short, week=week):
                j = self.create() if self.queue.get(self._jid if hasattr(self, "_jid") else "") is None else None
                if j:
                    self._jid = j["job_id"]
                tool = MockExecutor()
                self.assertEqual(self.worker(lambda: snapshot(self.now, short, week), tool)[0].tick()["decision"], "DEFER")
                self.assertEqual(tool.calls, 0)
                self.assertEqual(self.queue.get(self._jid)["status"], "deferred")
                self.now += timedelta(minutes=1)
        tool = MockExecutor()
        w, _ = self.worker(lambda: snapshot(self.now, 5, 5), tool)
        self.assertEqual(w.tick()["decision"], "succeeded")
        self.assertEqual(tool.calls, 1)
        self.assertEqual(self.queue.get(self._jid)["attempt_count"], 1)

    def test_unknown_auth_stale_and_dynamic_window_stop(self):
        self.create()
        cases = [None, error_snapshot("auth_required", self.now),
                 snapshot(self.now, ordinary=None), snapshot(self.now, extra=100),
                 snapshot(self.now - timedelta(minutes=11))]
        for sample in cases:
            w, tool = self.worker(lambda sample=sample: sample)
            result = w.tick()
            self.assertIn(result["decision"], ("UNKNOWN", "DEFER"))
            self.assertEqual(tool.calls, 0)
            self.assertEqual(self.queue.get(result["job_id"])["attempt_count"], 0)

    def test_claim_lease_recovery_does_not_repeat_started_model(self):
        first = self.create()
        c = self.queue.claim("synthetic-worker-01")
        self.now += timedelta(seconds=130)
        self.assertEqual(self.queue.recover()["unstarted_claims_recovered"], 1)
        second = self.queue.claim("synthetic-worker-02")
        self.assertGreater(second["fencing_token"], c["fencing_token"])
        with self.assertRaises(ConflictError):
            self.queue.assess(first["job_id"], "synthetic-worker-01",
                              c["fencing_token"], snapshot(self.now))
        verdict = self.queue.assess(first["job_id"], "synthetic-worker-02",
                                    second["fencing_token"], snapshot(self.now))
        self.assertEqual(verdict["decision"], "ALLOW")
        restarted = Scheduler(self.path, repositories={REPO}, models={"test-codex"},
                              clock=lambda: self.now.timestamp())
        # Lost model start ACK, crash, VPS restart: must not infer old process stopped.
        self.now += timedelta(seconds=61)
        self.assertEqual(restarted.recover()["uncertain_blocked"], 1)
        self.assertEqual(restarted.get(first["job_id"])["status"], "blocked")
        self.assertIsNone(restarted.claim("synthetic-worker-03"))
        with self.assertRaises(ConflictError):
            restarted.finish(first["job_id"], "synthetic-worker-02",
                             second["fencing_token"], succeeded=True)
        with self.assertRaises(ValidationError):
            restarted.release_safety_latch(first["job_id"], process_termination_verified=False)
        restarted.release_safety_latch(first["job_id"], process_termination_verified=True)
        self.assertIsNone(restarted.claim("synthetic-worker-03"))

    def test_cancel_unstarted_and_running_are_distinct(self):
        first = self.create()
        self.assertEqual(self.queue.cancel(first["job_id"])["status"], "cancelled")
        self.assertIsNone(self.queue.claim("synthetic-worker-01"))
        self.assertEqual(self.queue.cancel(first["job_id"])["status"], "cancelled")
        self.approve(approval_id="owner-proof-20261018")
        j2 = self.queue.submit(self.request(idempotency_key="unique-job-request-two",
                     approval_id="owner-proof-20261018"))
        c = self.queue.claim("synthetic-worker-01")
        self.queue.assess(j2["job_id"], "synthetic-worker-01",
                          c["fencing_token"], snapshot(self.now))
        self.assertEqual(self.queue.cancel(j2["job_id"])["status"], "running")
        out = self.queue.finish(j2["job_id"], "synthetic-worker-01",
                                c["fencing_token"], succeeded=True,
                                result_ref="mock:late-result")
        self.assertEqual(out["status"], "blocked")
        self.assertIsNone(self.queue.claim("synthetic-worker-02"))

    def test_lost_result_ack_and_executor_exception(self):
        self.create()
        exe = MockExecutor()
        self.worker(executor=exe)[0].tick()
        restart = Scheduler(self.path, repositories={REPO}, models={"test-codex"},
                            clock=lambda: self.now.timestamp())
        self.assertEqual(restart.acknowledge_result(self.queue.get(
            self.queue.submit(self.request())["job_id"])["job_id"])["status"], "succeeded")
        self.assertEqual(exe.calls, 1)
        self.approve(approval_id="owner-proof-20261018")
        req = self.request(approval_id="owner-proof-20261018",
                           idempotency_key="unique-job-request-two")
        second = self.queue.submit(req)
        broken = MockExecutor(RuntimeError("synthetic termination"))
        self.assertEqual(self.worker(executor=broken)[0].tick()["decision"], "BLOCKED")
        self.assertEqual(self.queue.get(second["job_id"])["status"], "blocked")
        self.assertEqual(broken.calls, 1)
        self.assertIsNone(self.queue.claim("synthetic-worker-01"))

    def test_cancel_deferred_and_storage_errors_fail_closed(self):
        job = self.create()
        w, _ = self.worker(lambda: None)
        self.assertEqual(w.tick()["decision"], "UNKNOWN")
        self.assertEqual(self.queue.cancel(job["job_id"])["status"], "cancelled")
        self.assertIsNone(self.queue.claim("synthetic-worker-01"))
        self.path.unlink()
        with self.assertRaises(sqlite3.OperationalError):
            # Read-only connection is intentionally unable to create the journal.
            sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)

    def test_retention_only_removes_terminal_certain_tasks(self):
        job = self.create()
        self.queue.cancel(job["job_id"])
        self.now += timedelta(days=31)
        self.assertEqual(self.queue.prune(), 1)


if __name__ == "__main__":
    unittest.main()
