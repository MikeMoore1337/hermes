"""Minimal durable H-04 CI snapshot. No Telegram or Ops modifications here.

One trusted root-owned atomic record, always a single strictly typed newest run.
UNKNOWN/stale/queued cannot prove a recovery. Never persist raw GitHub data,
token, job logs, repository URLs or user-supplied descriptions.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DIR = Path("/var/lib/hermes-qa-watch")
FILE = "ci-signal.json"
SCHEMA = "hermes-qa-ci-signal-v1"
MAX_BYTES = 2048
FRESH_FOR = timedelta(minutes=32)
HEAD = re.compile(r"[0-9a-f]{40}\Z")
STATES = frozenset({"SUCCESS", "FAILURE", "RUNNING", "UNKNOWN"})
REPO = "MikeMoore1337/hermes"
WORKFLOW = "workflow-381262090"


class SignalError(ValueError):
    """Fixed codes only."""


def _strict(item: object) -> dict[str, Any]:
    if type(item) is not dict or set(item) != {
        "schema", "repo", "workflow", "status", "run_id", "head_sha",
        "observed_at",
    }:
        raise SignalError("signal_schema_invalid")
    if item["schema"] != SCHEMA or item["repo"] != REPO or item["workflow"] != WORKFLOW:
        raise SignalError("signal_source_invalid")
    if type(item["status"]) is not str or item["status"] not in STATES:
        raise SignalError("signal_status_invalid")
    if type(item["run_id"]) is not int or not 0 <= item["run_id"] <= 10**18:
        raise SignalError("signal_run_id_invalid")
    if (item["head_sha"] is not None and
            (type(item["head_sha"]) is not str or not HEAD.fullmatch(item["head_sha"]))):
        raise SignalError("signal_sha_invalid")
    if (item["status"] in {"SUCCESS", "FAILURE", "RUNNING"} and
            (item["run_id"] == 0 or item["head_sha"] is None)):
        raise SignalError("signal_missing_run")
    if (item["status"] == "UNKNOWN" and
            (item["run_id"] != 0 or item["head_sha"] is not None)):
        raise SignalError("signal_unknown_has_run")
    date = item["observed_at"]
    if type(date) is not str or len(date) > 40:
        raise SignalError("signal_timestamp_invalid")
    try:
        time = datetime.fromisoformat(date)
    except ValueError:
        raise SignalError("signal_timestamp_invalid") from None
    if time.tzinfo is None or time.utcoffset() != timedelta(0):
        raise SignalError("signal_timestamp_invalid")
    return item


def _dir(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise SignalError("signal_directory_invalid")
    info = directory.stat()
    if (info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise SignalError("signal_directory_unsafe")


def read(directory: Path = DIR) -> dict[str, Any] | None:
    _dir(directory)
    path = directory / FILE
    if not path.exists():
        if path.is_symlink():
            raise SignalError("signal_file_unsafe")
        return None
    if path.is_symlink():
        raise SignalError("signal_file_unsafe")
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 1 <= info.st_size <= MAX_BYTES):
        raise SignalError("signal_file_unsafe")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_BYTES+1)
        if len(raw) > MAX_BYTES:
            raise SignalError("signal_oversize")
        return _strict(json.loads(raw))
    except (OSError, ValueError, UnicodeError) as e:
        if isinstance(e, SignalError):
            raise
        raise SignalError("signal_file_invalid") from None


def from_ci(result: dict[str, object], *, now: datetime) -> dict[str, object]:
    if type(result) is not dict or result.get("status") not in STATES:
        raise SignalError("ci_result_invalid")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise SignalError("signal_clock_invalid")
    state = result["status"]
    item = {
        "schema": SCHEMA, "repo": REPO, "workflow": WORKFLOW,
        "status": state, "run_id": 0 if state == "UNKNOWN" else result.get("run_id"),
        "head_sha": None if state == "UNKNOWN" else result.get("head_sha"),
        "observed_at": now.astimezone(UTC).isoformat(),
    }
    return _strict(item)


def store(item: dict[str, object], *, directory: Path = DIR) -> str:
    """Write one record; reject stale run order and fabricated recovery."""
    record = _strict(item)
    _dir(directory)
    previous = read(directory)
    if previous is not None:
        old_id, new_id = previous["run_id"], record["run_id"]
        if new_id and old_id and new_id < old_id:
            raise SignalError("run_id_moved_backward")
        if (new_id == old_id and old_id > 0
                and previous["status"] == "FAILURE"
                and record["status"] == "SUCCESS"):
            raise SignalError("same_run_cannot_prove_recovery")
        if (datetime.fromisoformat(record["observed_at"]) <
                datetime.fromisoformat(previous["observed_at"])):
            raise SignalError("timestamp_moved_backward")
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_BYTES:
        raise SignalError("signal_oversize")
    fd, name = tempfile.mkstemp(prefix=".ci-signal-", dir=directory)
    temp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as sink:
            sink.write(payload)
            sink.flush()
            os.fsync(sink.fileno())
        os.replace(temp, directory / FILE)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temp.unlink(missing_ok=True)
    return "STORED_SAFE_CI_SIGNAL"


def observed_status(
    directory: Path = DIR, *, now: datetime | None = None,
) -> str | None:
    """Return SUCCESS/FAILURE only if fresh, else None (never recovery)."""
    item = read(directory)
    if item is None:
        return None
    instant = now or datetime.now(UTC)
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise SignalError("signal_clock_invalid")
    age = instant.astimezone(UTC) - datetime.fromisoformat(item["observed_at"])
    if age < -timedelta(minutes=1) or age > FRESH_FOR:
        return None
    return item["status"] if item["status"] in ("SUCCESS", "FAILURE") else None
