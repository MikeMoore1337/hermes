"""Bounded read-only YFC polling evidence from an actual bot getUpdates result.

Never infer Telegram health from Docker container health or VPS resource uptime.
Untrusted, stale, missing and ill-formed evidence cannot prove recovery.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import stat

LOCAL = Path("/var/lib/hermes-infra-read/polling/polling.json")
MAX_BYTES = 512
MAX_AGE = timedelta(seconds=120)
MAX_FUTURE = timedelta(seconds=30)
STATES = frozenset({"healthy", "unhealthy", "unknown", "stale", "not_connected"})
EVENTS = {
    "healthy": frozenset({"getupdates_success"}),
    "unhealthy": frozenset({"getupdates_error", "polling_conflict"}),
}


def _empty(status: str = "unknown") -> dict:
    return {"schema": 1, "source_host": "yfc", "status": status}


def sanitize(raw: object, *, now: datetime | None = None) -> dict:
    """Recheck a remote declaration by pinned host, state, event and UTC age."""
    at = now or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("timezone_required")
    if not isinstance(raw, dict) or raw.get("schema") != 1 or raw.get("source_host") != "yfc":
        return _empty()
    if set(raw) == {"schema", "source_host", "status"} and raw["status"] in {
        "unknown", "stale", "not_connected",
    }:
        return _empty(raw["status"])
    if set(raw) != {"schema", "source_host", "status", "observed_at", "evidence"}:
        return _empty()
    status = raw.get("status")
    event = raw.get("evidence")
    if (not isinstance(status, str) or not isinstance(event, str)
            or status not in EVENTS or event not in EVENTS[status]):
        return _empty()
    date = raw.get("observed_at")
    if not isinstance(date, str) or len(date) > 40:
        return _empty()
    try:
        stamp = datetime.fromisoformat(date.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return _empty()
    if stamp.tzinfo is None:
        return _empty()
    age = at.astimezone(timezone.utc) - stamp.astimezone(timezone.utc)
    if age < -MAX_FUTURE:
        return _empty()
    if age > MAX_AGE:
        return _empty("stale")
    return {
        "schema": 1, "source_host": "yfc", "status": status,
        "observed_at": stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "evidence": event,
    }


def read_local(
    path: Path = LOCAL, *, now: datetime | None = None,
    expected_uid: int = 10001, expected_gid: int | None = None,
) -> dict:
    """Read only the dedicated bounded bot status file as restricted SSH user."""
    try:
        if path.is_symlink():
            return _empty()
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES or info.st_size < 1:
            return _empty()
        if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o640:
            return _empty()
        if expected_gid is None:
            import grp
            expected_gid = grp.getgrnam("hermes-infra-read").gr_gid
        if info.st_gid != expected_gid:
            return _empty()
        raw = json.loads(path.read_text(encoding="utf-8"))
        # Producer calls the field "state"; never accept its assertion alone.
        if isinstance(raw, dict):
            raw = dict(raw)
            raw["status"] = raw.pop("state", None)
            raw.pop("component", None)
        return sanitize(raw, now=now)
    except FileNotFoundError:
        return _empty("not_connected")
    except (PermissionError, OSError, UnicodeError, ValueError, TypeError, KeyError,
            OverflowError, json.JSONDecodeError):
        return _empty()
