"""One-shot, opt-in Skill Evals receipt/fencing lane (Hermes #349).

Not wired to H-15 device presence, Codex scheduler, H-01 or systemd.
No network listener, auto-retry, durable job queue or shell execution.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import time
from typing import Callable

from .protocol import (
    AdmissionDenied, OperatorGates, validate_job, verify_grant,
    verify_operator_gates,
)

_SHA = re.compile(r"^[0-9a-f]{64}$")


def _private_dir(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise AdmissionDenied("private_evidence_directory_required")
    for component in [path, *path.parents]:
        if component.is_symlink():
            raise AdmissionDenied("symlink_in_evidence_path")
    status = path.stat()
    if status.st_mode & 0o077 or (hasattr(os, "getuid") and status.st_uid != os.getuid()):
        raise AdmissionDenied("evidence_directory_permissions")


def _durable_json(path: Path, record: dict) -> None:
    """Persist an outcome without leaking CLI output or granting a retry."""
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temp = path.with_name("." + path.name + ".tmp")
    if temp.exists() or temp.is_symlink():
        raise AdmissionDenied("unfinished_receipt_write")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()


class OneShotLedger:
    """Single local worker; a claimed job remains spent after any crash.

    Requires an already-provisioned private directory. Never starts processes
    itself. The trusted caller supplies a strictly scoped executor callback.
    """

    def __init__(self, root: Path, *, enabled: bool = False):
        self.root = Path(root)
        self.enabled = enabled

    @contextmanager
    def _worker_lock(self):
        _private_dir(self.root)
        path = self.root / "worker.lock"
        if path.is_symlink():
            raise AdmissionDenied("unsafe_worker_lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError as exc:
            raise AdmissionDenied("worker_already_busy") from exc
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def run_once(self, job: dict, grant: dict, *, approval_key: bytes,
                 revoked_approvals: frozenset[str],
                 gates: OperatorGates, runner: Callable[[dict], dict] | None,
                 clock: float | None = None) -> dict:
        """Owner-run, explicit one-shot only. No queue, no reconnect replay."""
        if self.enabled is not True:
            raise AdmissionDenied("execution_disabled_by_default")
        now = time.time() if clock is None else clock
        checked = validate_job(job, clock=now)
        verify_grant(grant, checked, key=approval_key, revoked=revoked_approvals,
                     clock=now)
        verify_operator_gates(gates)
        if runner is None or not callable(runner):
            raise AdmissionDenied("trusted_fixed_executor_missing")
        # A stated dollar budget is not a hard limit; external provider hard-stop
        # attestation must be independently verified before constructing gates.
        with self._worker_lock():
            receipt = self.root / (checked["job_id"] + ".json")
            if receipt.exists() or receipt.is_symlink():
                raise AdmissionDenied("job_already_claimed_no_replay")
            # Claim DURABLY before callback; any uncertain outcome is non-retryable.
            _durable_json(receipt, {
                "job_id": checked["job_id"], "state": "claimed",
                "approval_id": checked["approval_id"], "provider": checked["provider"],
            })
            try:
                answer = runner(checked)
                if (type(answer) is not dict or set(answer) !=
                        {"outcome", "artifact_sha256"} or
                        answer["outcome"] not in ("succeeded", "failed") or
                        type(answer["artifact_sha256"]) is not str or
                        not _SHA.fullmatch(answer["artifact_sha256"])):
                    raise AdmissionDenied("executor_receipt_invalid")
                result = {
                    "job_id": checked["job_id"], "state": answer["outcome"],
                    "artifact_sha256": answer["artifact_sha256"],
                }
                _durable_json(receipt, result)
                return result
            except BaseException:
                # Even if the executor has already sent model requests, do not retry.
                # If this state write fails, prior 'claimed' remains on disk.
                _durable_json(receipt, {
                    "job_id": checked["job_id"], "state": "uncertain_do_not_retry",
                })
                raise

    def state(self, job_id: str) -> str:
        if type(job_id) is not str or not re.fullmatch(r"^[a-z][a-z0-9-]{11,63}$", job_id):
            raise AdmissionDenied("invalid_job_id")
        _private_dir(self.root)
        path = self.root / (job_id + ".json")
        if not path.exists():
            return "not_submitted"
        if path.is_symlink():
            raise AdmissionDenied("unsafe_receipt")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeError) as exc:
            raise AdmissionDenied("invalid_receipt") from exc
        state = data.get("state")
        if state not in ("claimed", "succeeded", "failed", "uncertain_do_not_retry"):
            raise AdmissionDenied("invalid_receipt_state")
        return state
