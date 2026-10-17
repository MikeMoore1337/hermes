"""Durable, fail-closed, single-host Codex task admission and recovery.

No HTTP write API or model calls. Operator approval is a privileged *local*
operation, not something a task payload or quota snapshot can provide.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Callable, Protocol
from uuid import uuid4

from control_center.codex_policy import decision, may_dispatch

SCHEMA_VERSION = 1
OPERATIONS = frozenset({"inspect", "test", "patch", "prepare_pr"})
EFFORTS = frozenset({"low", "medium", "high"})
REQUIRED = frozenset({
    "schema_version", "requested_at", "expires_at", "initiator", "approval_id",
    "repository", "allowed_operations", "model", "effort", "resource_limits",
    "idempotency_key",
})
LIMIT_KEYS = frozenset({"max_runtime_seconds", "max_memory_mb", "max_output_bytes"})
DEFAULT_DB = Path("/var/lib/hermes-codex-scheduler/jobs.sqlite3")
MAX_JOBS = 1000
MAX_RETENTION_DAYS = 30
LEASE_SECONDS = 120
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_KEY = re.compile(r"^[A-Za-z0-9_-]{12,128}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,80}/[A-Za-z0-9_.-]{1,80}$")


class ValidationError(ValueError):
    pass


class ConflictError(ValueError):
    pass


def _utc(value: str) -> float:
    if type(value) is not str:
        raise ValidationError("timestamp_required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        result = parsed.timestamp()
        if not 0 < result < 4102444800:  # before year 2100
            raise ValueError("timestamp out of range")
        return result
    except (ValueError, OverflowError) as exc:
        raise ValidationError("timestamp_invalid") from exc


def _iso(timestamp: float | None) -> str | None:
    return (datetime.fromtimestamp(timestamp, timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z")
            if timestamp is not None else None)


def _json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _limits(value: object) -> dict:
    if type(value) is not dict or set(value) != LIMIT_KEYS:
        raise ValidationError("resource_limits_invalid")
    ranges = {"max_runtime_seconds": (1, 3600), "max_memory_mb": (128, 4096),
              "max_output_bytes": (128, 65536)}
    for key, (low, high) in ranges.items():
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValidationError("resource_limit_invalid")
    return value.copy()


def _ops(value: object) -> tuple[str, ...]:
    if type(value) is not list or not value or len(value) > len(OPERATIONS):
        raise ValidationError("operations_invalid")
    if any(type(x) is not str or x not in OPERATIONS for x in value):
        raise ValidationError("operations_invalid")
    if len(set(value)) != len(value):
        raise ValidationError("operations_duplicate")
    return tuple(sorted(value))


@dataclass(frozen=True)
class Approval:
    approval_id: str
    initiator: str
    repository: str
    allowed_operations: tuple[str, ...]
    model: str
    effort: str
    resource_limits: dict
    expires_at: str


class Executor(Protocol):
    def execute(self, job: dict) -> tuple[bool, str | None]:
        """Return success and an opaque bounded artifact reference, never raw text."""
        ...


class Scheduler:
    def __init__(self, db: Path, *, repositories: set[str],
                 models: set[str], owner_identity: str = "MikeMoore1337",
                 clock: Callable[[], float] = time.time,
                 group_readable: bool = False):
        self.db = Path(db)
        self.repositories = frozenset(repositories)
        self.models = frozenset(models)
        self.owner_identity = owner_identity
        self.clock = clock
        self.group_readable = group_readable

    @contextmanager
    def _connect(self):
        if self.db.is_symlink() or self.db.parent.is_symlink():
            raise ValidationError("database_symlink")
        self.db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(str(self.db), timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if os.name == "posix":
            os.chmod(self.db, 0o640 if self.group_readable else 0o600)
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        with self._connect() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS approvals (
                  approval_id TEXT PRIMARY KEY, initiator TEXT NOT NULL,
                  repository TEXT NOT NULL, operations TEXT NOT NULL,
                  model TEXT NOT NULL, effort TEXT NOT NULL,
                  limits TEXT NOT NULL, expires REAL NOT NULL, digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                  job_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
                  created REAL NOT NULL, requested REAL NOT NULL,
                  updated REAL NOT NULL, expires REAL NOT NULL,
                  initiator TEXT NOT NULL, approval_id TEXT NOT NULL,
                  approval_expires REAL NOT NULL, repository TEXT NOT NULL,
                  operations TEXT NOT NULL, model TEXT NOT NULL,
                  effort TEXT NOT NULL, limits TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL UNIQUE,
                  request_digest TEXT NOT NULL, status TEXT NOT NULL,
                  attempt_count INTEGER NOT NULL DEFAULT 0,
                  started REAL, finished REAL, result_ref TEXT,
                  last_error_code TEXT, lease_owner TEXT,
                  fencing_token INTEGER NOT NULL DEFAULT 0,
                  lease_until REAL, invocation_state TEXT NOT NULL DEFAULT 'never',
                  delivered REAL, cancellation_requested INTEGER NOT NULL DEFAULT 0,
                  FOREIGN KEY(approval_id) REFERENCES approvals(approval_id)
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_claim
                  ON jobs(status, created);
            """)

    def _validate_approval(self, a: Approval) -> tuple:
        if not isinstance(a, Approval) or not _KEY.fullmatch(a.approval_id):
            raise ValidationError("approval_invalid")
        if a.initiator != self.owner_identity or a.repository not in self.repositories:
            raise ValidationError("approval_scope_denied")
        if not _REPO.fullmatch(a.repository) or a.model not in self.models or a.effort not in EFFORTS:
            raise ValidationError("approval_model_invalid")
        operations = _ops(list(a.allowed_operations))
        limits = _limits(a.resource_limits)
        return operations, limits, _utc(a.expires_at)

    def register_approval(self, approval: Approval, *, verified_owner: str) -> None:
        """Trusted OFFLINE operator boundary. Never expose this through HTTP/jobs JSON.

        The caller must have independently verified the owner's exact signed
        intent/scope. This method is unavailable to the read-only UI.
        """
        if verified_owner != self.owner_identity:
            raise ValidationError("owner_verification_required")
        ops, limits, expiry = self._validate_approval(approval)
        if expiry <= self.clock():
            raise ValidationError("approval_expired")
        values = (approval.approval_id, approval.initiator, approval.repository,
                  _json(ops), approval.model, approval.effort, _json(limits), expiry)
        digest = hashlib.sha256(_json(values).encode()).hexdigest()
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            existing = c.execute("SELECT digest FROM approvals WHERE approval_id=?",
                                 (approval.approval_id,)).fetchone()
            if existing and existing["digest"] != digest:
                raise ConflictError("approval_immutable")
            if not existing:
                c.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?)",
                          (*values, digest))
            c.commit()

    def submit(self, request: dict) -> dict:
        """Request has NO caller-selected job_id/status/scope extension."""
        if type(request) is not dict or set(request) != REQUIRED:
            raise ValidationError("task_schema_invalid")
        if type(request["schema_version"]) is not int or request["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("task_schema_version")
        for key in ("initiator", "approval_id", "model", "effort", "idempotency_key"):
            if type(request[key]) is not str:
                raise ValidationError("task_string_invalid")
        if request["initiator"] != self.owner_identity or not _KEY.fullmatch(request["approval_id"]):
            raise ValidationError("task_authorization_invalid")
        if not _KEY.fullmatch(request["idempotency_key"]):
            raise ValidationError("idempotency_key_invalid")
        repo = request["repository"]
        if type(repo) is not str or not _REPO.fullmatch(repo) or repo not in self.repositories:
            raise ValidationError("repository_denied")
        ops = _ops(request["allowed_operations"])
        limits = _limits(request["resource_limits"])
        if request["model"] not in self.models or request["effort"] not in EFFORTS:
            raise ValidationError("model_denied")
        requested, expires = _utc(request["requested_at"]), _utc(request["expires_at"])
        now = self.clock()
        if requested > now + 120 or expires <= max(now, requested):
            raise ValidationError("task_expired_or_future")
        if expires - now > 7 * 86400:
            raise ValidationError("task_ttl_exceeded")
        identity = (request["schema_version"], requested, expires, request["initiator"],
                    request["approval_id"], repo, ops, request["model"],
                    request["effort"], limits, request["idempotency_key"])
        digest = hashlib.sha256(_json(identity).encode()).hexdigest()
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            existing = c.execute("SELECT * FROM jobs WHERE idempotency_key=?",
                                 (request["idempotency_key"],)).fetchone()
            if existing:
                if existing["request_digest"] != digest:
                    raise ConflictError("idempotency_scope_mismatch")
                c.commit()
                return self._public(existing)
            approval = c.execute("SELECT * FROM approvals WHERE approval_id=?",
                                 (request["approval_id"],)).fetchone()
            if not approval or approval["expires"] <= now or expires > approval["expires"]:
                raise ValidationError("approval_missing_or_expired")
            if (approval["initiator"] != request["initiator"]
                    or approval["repository"] != repo
                    or not set(ops).issubset(json.loads(approval["operations"]))
                    or approval["model"] != request["model"]
                    or approval["effort"] != request["effort"]):
                raise ValidationError("approval_scope_mismatch")
            allowed_limits = json.loads(approval["limits"])
            if any(limits[k] > allowed_limits[k] for k in LIMIT_KEYS):
                raise ValidationError("approval_budget_exceeded")
            if c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= MAX_JOBS:
                raise ValidationError("queue_capacity")
            job_id = str(uuid4())
            c.execute("""
                INSERT INTO jobs(job_id,schema_version,created,requested,updated,expires,
                   initiator,approval_id,approval_expires,repository,operations,model,
                   effort,limits,idempotency_key,request_digest,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, SCHEMA_VERSION, now, requested, now, expires,
                 request["initiator"], request["approval_id"], approval["expires"],
                 repo, _json(ops), request["model"], request["effort"], _json(limits),
                 request["idempotency_key"], digest, "queued"))
            result = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            c.commit()
            return self._public(result)

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        keys = ("job_id", "schema_version", "initiator", "approval_id", "repository",
                "model", "effort", "idempotency_key", "status", "attempt_count",
                "result_ref", "last_error_code", "fencing_token", "invocation_state",
                "cancellation_requested")
        out = {key: row[key] for key in keys}
        for key in ("created", "requested", "updated", "expires", "approval_expires",
                    "started", "finished", "delivered"):
            out[key + "_at" if key not in ("created", "requested", "updated", "expires") else
                {"created": "created_at", "requested": "requested_at",
                 "updated": "updated_at", "expires": "expires_at"}[key]] = _iso(row[key])
        out["allowed_operations"] = json.loads(row["operations"])
        out["resource_limits"] = json.loads(row["limits"])
        return out

    def get(self, job_id: str) -> dict | None:
        with self._connect() as c:
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            return self._public(row) if row else None

    def _expire(self, c: sqlite3.Connection, now: float) -> None:
        c.execute("""UPDATE jobs SET status='cancelled', finished=?, updated=?,
                       last_error_code='task_expired'
                       WHERE status IN ('queued','deferred') AND expires<=?""",
                  (now, now, now))
        c.execute("""UPDATE jobs SET status='cancelled', finished=?, updated=?,
                       last_error_code='approval_expired'
                       WHERE status IN ('queued','deferred') AND approval_expires<=?""",
                  (now, now, now))

    def recover(self) -> dict:
        """Startup and periodic recovery. Uncertain invocation blocks ALL new starts."""
        now = self.clock()
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            self._expire(c, now)
            claimed = c.execute("""UPDATE jobs SET status='deferred', updated=?,
                           lease_owner=NULL, lease_until=NULL,
                           last_error_code='claim_recovered'
                           WHERE status='claimed' AND lease_until<=?
                             AND invocation_state='never'""", (now, now)).rowcount
            running = c.execute("""UPDATE jobs SET status='blocked',
                           invocation_state='uncertain', updated=?,
                           last_error_code='recovery_manual_review'
                           WHERE status='running' AND lease_until<=?""",
                                (now, now)).rowcount
            c.commit()
        return {"unstarted_claims_recovered": claimed, "uncertain_blocked": running}

    def claim(self, worker_id: str) -> dict | None:
        if type(worker_id) is not str or not _KEY.fullmatch(worker_id):
            raise ValidationError("worker_id_invalid")
        now = self.clock()
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            self._expire(c, now)
            # A possible orphan process is NEVER cleared just because a lease expired.
            if c.execute("""SELECT 1 FROM jobs WHERE
                 status='running' OR (status='blocked' AND invocation_state='uncertain')
                 OR (status='claimed' AND lease_until>?) LIMIT 1""", (now,)).fetchone():
                c.commit()
                return None
            c.execute("""UPDATE jobs SET status='deferred', updated=?,
                last_error_code='claim_recovered', lease_owner=NULL, lease_until=NULL
                WHERE status='claimed' AND lease_until<=? AND invocation_state='never'""",
                      (now, now))
            row = c.execute("""SELECT * FROM jobs WHERE status IN ('queued','deferred')
                AND requested<=? ORDER BY created, job_id LIMIT 1""", (now,)).fetchone()
            if row is None:
                c.commit()
                return None
            token = row["fencing_token"] + 1
            c.execute("""UPDATE jobs SET status='claimed',updated=?,lease_owner=?,
                lease_until=?,fencing_token=? WHERE job_id=? AND status=?""",
                      (now, worker_id, now + LEASE_SECONDS, token,
                       row["job_id"], row["status"]))
            claimed = c.execute("SELECT * FROM jobs WHERE job_id=?",
                                (row["job_id"],)).fetchone()
            c.commit()
            return self._public(claimed)

    def assess(self, job_id: str, worker_id: str, token: int, snapshot: dict | None) -> dict:
        """Quota/owner gates immediately before irreversible start reservation."""
        now = self.clock()
        verdict = decision(snapshot, now=datetime.fromtimestamp(now, timezone.utc))
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row or row["status"] != "claimed" or row["lease_owner"] != worker_id or row["fencing_token"] != token:
                raise ConflictError("fencing_rejected")
            approval = c.execute("SELECT * FROM approvals WHERE approval_id=?",
                                 (row["approval_id"],)).fetchone()
            owner_valid = bool(approval and approval["expires"] > now
                and row["expires"] > now and row["approval_expires"] > now
                and approval["repository"] == row["repository"]
                and approval["model"] == row["model"] and approval["effort"] == row["effort"]
                and set(json.loads(row["operations"])).issubset(json.loads(approval["operations"]))
                and all(json.loads(row["limits"])[k] <= json.loads(approval["limits"])[k]
                        for k in LIMIT_KEYS))
            if not owner_valid:
                c.execute("""UPDATE jobs SET status='blocked', updated=?,
                    last_error_code='approval_invalid', lease_owner=NULL,
                    lease_until=NULL WHERE job_id=?""", (now, job_id))
                c.commit()
                return {"decision": "BLOCKED", "reason": "approval_invalid"}
            if not may_dispatch(verdict, task_authorized=owner_valid):
                why = verdict["reason"]
                c.execute("""UPDATE jobs SET status='deferred',updated=?,
                    last_error_code=?,lease_owner=NULL,lease_until=NULL
                    WHERE job_id=?""", (now, why, job_id))
                c.commit()
                return verdict
            # Durable pre-call reservation. Any crash after this line is uncertain.
            # No external model call occurs inside or before this transaction.
            c.execute("""UPDATE jobs SET status='running',updated=?,started=?,
                attempt_count=attempt_count+1,invocation_state='uncertain',
                lease_until=?,last_error_code=NULL WHERE job_id=?""",
                (now, now, now + json.loads(row["limits"])["max_runtime_seconds"] + 30,
                 job_id))
            c.commit()
            return {"decision": "ALLOW", "reason": verdict["reason"]}

    def finish(self, job_id: str, worker_id: str, token: int, *,
               succeeded: bool, result_ref: str | None = None) -> dict:
        now = self.clock()
        if result_ref is not None and (type(result_ref) is not str or
                not re.fullmatch(r"[a-zA-Z0-9_./:-]{1,200}", result_ref)):
            raise ValidationError("result_ref_invalid")
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if (not row or row["status"] != "running" or row["lease_owner"] != worker_id
                    or row["fencing_token"] != token):
                raise ConflictError("fencing_rejected")
            if row["cancellation_requested"]:
                status, code = "blocked", "cancelled_during_inference"
                invocation = "uncertain"
            else:
                status = "succeeded" if succeeded else "failed"
                code, invocation = (None if succeeded else "executor_failed"), "finished"
            c.execute("""UPDATE jobs SET status=?,updated=?,finished=?,result_ref=?,
                last_error_code=?,invocation_state=?,lease_owner=NULL,lease_until=NULL
                WHERE job_id=?""",
                (status, now, now, result_ref if status == "succeeded" else None,
                 code, invocation, job_id))
            result = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            c.commit()
            return self._public(result)

    def fail_uncertain(self, job_id: str, worker_id: str, token: int) -> None:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("""UPDATE jobs SET status='blocked',invocation_state='uncertain',
                last_error_code='executor_outcome_unknown',updated=?
                WHERE job_id=? AND status='running' AND lease_owner=?
                  AND fencing_token=?""", (self.clock(), job_id, worker_id, token))
            c.commit()

    def cancel(self, job_id: str) -> dict | None:
        now = self.clock()
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row:
                c.commit()
                return None
            if row["status"] in ("queued", "deferred", "claimed"):
                # Claimed is strictly pre-invocation. Fencing denies stale owner.
                c.execute("""UPDATE jobs SET status='cancelled',updated=?,finished=?,
                    last_error_code='owner_cancelled',lease_owner=NULL,lease_until=NULL
                    WHERE job_id=?""", (now, now, job_id))
            elif row["status"] == "running":
                # An external process may continue; leave latch and require operator.
                c.execute("""UPDATE jobs SET cancellation_requested=1,updated=?,
                    last_error_code='cancel_requested' WHERE job_id=?""", (now, job_id))
            result = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            c.commit()
            return self._public(result)

    def acknowledge_result(self, job_id: str) -> dict | None:
        """Idempotent receipt of an already committed result; never runs executor."""
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row or row["status"] != "succeeded" or not row["result_ref"]:
                c.commit()
                return None
            if row["delivered"] is None:
                c.execute("UPDATE jobs SET delivered=? WHERE job_id=?",
                          (self.clock(), job_id))
            result = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            c.commit()
            return self._public(result)

    def release_safety_latch(self, job_id: str, *,
                             process_termination_verified: bool) -> None:
        """Privileged manual reconciliation ONLY after checking actual process state."""
        if process_termination_verified is not True:
            raise ValidationError("manual_process_verification_required")
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT status,invocation_state FROM jobs WHERE job_id=?",
                            (job_id,)).fetchone()
            if not row or tuple(row) != ("blocked", "uncertain"):
                raise ConflictError("no_uncertain_latch")
            c.execute("""UPDATE jobs SET invocation_state='reviewed',updated=?,
                last_error_code='manual_review_completed' WHERE job_id=?""",
                      (self.clock(), job_id))
            c.commit()

    def prune(self, days: int = MAX_RETENTION_DAYS) -> int:
        if type(days) is not int or not 1 <= days <= MAX_RETENTION_DAYS:
            raise ValidationError("retention_invalid")
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            removed = c.execute("""DELETE FROM jobs WHERE
                status IN ('succeeded','failed','cancelled','blocked')
                AND invocation_state != 'uncertain' AND updated<?""",
                (self.clock() - days * 86400,)).rowcount
            c.commit()
            return removed


class QuotaWorker:
    """Single synthetic/live-neutral tick. No daemon or timer is installed."""
    def __init__(self, scheduler: Scheduler, snapshot: Callable[[], dict | None],
                 executor: Executor, worker_id: str = "hermes-serial-worker"):
        self.scheduler, self.snapshot, self.executor = scheduler, snapshot, executor
        self.worker_id = worker_id

    def tick(self) -> dict | None:
        job = self.scheduler.claim(self.worker_id)
        if job is None:
            return None
        jid, token = job["job_id"], job["fencing_token"]
        try:
            snap = self.snapshot()
        except Exception:
            snap = None
        verdict = self.scheduler.assess(jid, self.worker_id, token, snap)
        if verdict["decision"] != "ALLOW":
            return {"job_id": jid, **verdict}
        # The uncertainty latch was persisted before any external side effect.
        try:
            succeeded, result_ref = self.executor.execute(job)
            saved = self.scheduler.finish(jid, self.worker_id, token,
                                          succeeded=bool(succeeded), result_ref=result_ref)
            return {"job_id": jid, "decision": saved["status"]}
        except Exception:
            self.scheduler.fail_uncertain(jid, self.worker_id, token)
            return {"job_id": jid, "decision": "BLOCKED", "reason": "executor_outcome_unknown"}
