"""Bounded, sanitized SQLite history for the existing Codex one-shot collector.

The collector is the only writer; the owner-only Control Center reads mode=ro.
Provider failures are observations, never deletion of previous successful data.
No model calls, credentials, account identifiers or Telegram sends.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

DEFAULT_HISTORY = Path("/var/lib/hermes-codex-usage/history.sqlite3")
RETENTION_DAYS = 30
ANCHOR_SECONDS = 1800
MAX_SAMPLES = 2200
MAX_TRANSITIONS = 500


def _parse_time(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("timezone_required")
    return stamp.astimezone(timezone.utc)


def _sanitize(snapshot: dict) -> dict:
    """Explicit allowlist; do not store unknown fields even if a caller adds them."""
    status = snapshot.get("status")
    if status not in ("available", "low", "limited", "exhausted", "unknown", "auth_required", "unavailable"):
        raise ValueError("invalid_status")
    observed = snapshot.get("observed_at")
    if not isinstance(observed, str):
        raise ValueError("invalid_timestamp")
    _parse_time(observed)
    allowed = snapshot.get("ordinary_usage_allowed")
    if allowed is not None and type(allowed) is not bool:
        raise ValueError("invalid_allowance")
    groups = snapshot.get("limits")
    if not isinstance(groups, list) or len(groups) > 24:
        raise ValueError("invalid_groups")
    limits = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("limit_id"), str):
            raise ValueError("invalid_group")
        limit_id = group["limit_id"]
        if not 1 <= len(limit_id) <= 64 or not all(c.isascii() and (c.isalnum() or c in "._-") for c in limit_id):
            raise ValueError("invalid_limit_id")
        windows = group.get("windows")
        if not isinstance(windows, list) or not 1 <= len(windows) <= 2:
            raise ValueError("invalid_windows")
        normalized = []
        for w in windows:
            if not isinstance(w, dict):
                raise ValueError("invalid_window")
            used, remaining = w.get("used_percent"), w.get("remaining_percent")
            if (type(used) not in (int, float) or type(remaining) not in (int, float)
                    or not math.isfinite(used) or not math.isfinite(remaining)
                    or not 0 <= used <= 100 or abs(used + remaining - 100) > .02):
                raise ValueError("invalid_percent")
            duration, reset = w.get("duration_minutes"), w.get("resets_at")
            if duration is not None and (type(duration) is not int or not 0 < duration <= 525600):
                raise ValueError("invalid_duration")
            if reset is not None and (type(reset) is not int or not 0 <= reset <= 253402300799):
                raise ValueError("invalid_reset")
            normalized.append({"used_percent": used, "remaining_percent": remaining,
                               "duration_minutes": duration, "resets_at": reset})
        limits.append({"limit_id": limit_id, "windows": normalized})
    if status in ("auth_required", "unavailable") and limits:
        raise ValueError("failure_must_not_have_windows")
    return {"observed_at": observed, "status": status,
            "ordinary_usage_allowed": allowed, "limits": limits}


def record(snapshot: dict, path: Path = DEFAULT_HISTORY) -> bool:
    """Idempotent consecutive dedup, periodic anchor, state transitions and pruning."""
    safe = _sanitize(snapshot)
    canonical = json.dumps({k: v for k, v in safe.items() if k != "observed_at"},
                           sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    observed = _parse_time(safe["observed_at"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("history_symlink_denied")
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS samples ("
                   "id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, "
                   "status TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                   "record_json TEXT NOT NULL, UNIQUE(observed_at,fingerprint))")
        db.execute("CREATE TABLE IF NOT EXISTS transitions ("
                   "id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, "
                   "previous_status TEXT, current_status TEXT NOT NULL)")
        previous = db.execute(
            "SELECT observed_at,status,fingerprint FROM samples ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if previous and _parse_time(previous[0]) > observed:
            # Reject clock rollback; keep existing records and fail closed.
            db.commit()
            return False
        if previous and previous[2] == fingerprint and (
            observed - _parse_time(previous[0])
        ).total_seconds() < ANCHOR_SECONDS:
            db.commit()
            return False
        cursor = db.execute(
            "INSERT OR IGNORE INTO samples(observed_at,status,fingerprint,record_json) "
            "VALUES (?,?,?,?)",
            (safe["observed_at"], safe["status"], fingerprint,
             json.dumps(safe, separators=(",", ":"))),
        )
        if cursor.rowcount and previous and previous[1] != safe["status"]:
            db.execute("INSERT INTO transitions(observed_at,previous_status,current_status) "
                       "VALUES (?,?,?)", (safe["observed_at"], previous[1], safe["status"]))
        cutoff = (observed - timedelta(days=RETENTION_DAYS)).isoformat()
        db.execute("DELETE FROM samples WHERE observed_at < ?", (cutoff,))
        db.execute("DELETE FROM transitions WHERE observed_at < ?", (cutoff,))
        db.execute("DELETE FROM samples WHERE id NOT IN "
                   "(SELECT id FROM samples ORDER BY id DESC LIMIT ?)", (MAX_SAMPLES,))
        db.execute("DELETE FROM transitions WHERE id NOT IN "
                   "(SELECT id FROM transitions ORDER BY id DESC LIMIT ?)", (MAX_TRANSITIONS,))
        db.commit()
    os.chmod(path, 0o640)
    return bool(cursor.rowcount)


def read(path: Path = DEFAULT_HISTORY, *, now: datetime | None = None,
         days: int = 7, limit: int = 500) -> dict:
    """Bounded SQLite read-only query; missing history is an empty history."""
    if not 1 <= days <= RETENTION_DAYS or not 1 <= limit <= 500:
        raise ValueError("invalid_history_request")
    empty = {"schema": 1, "samples": [], "transitions": [], "last_successful_at": None}
    if path.is_symlink() or not path.is_file():
        return empty
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since = (current - timedelta(days=days)).isoformat()
    uri = path.absolute().as_uri() + "?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=2) as db:
            rows = db.execute("SELECT record_json FROM samples WHERE observed_at>=? "
                              "ORDER BY observed_at DESC,id DESC LIMIT ?", (since, limit)).fetchall()
            changes = db.execute("SELECT observed_at,previous_status,current_status "
                                 "FROM transitions WHERE observed_at>=? "
                                 "ORDER BY observed_at DESC,id DESC LIMIT 50", (since,)).fetchall()
            recent = db.execute("SELECT observed_at FROM samples WHERE status IN "
                                "('available','low','limited','exhausted') "
                                "ORDER BY observed_at DESC,id DESC LIMIT 1").fetchone()
        return {
            "schema": 1,
            "samples": list(reversed([json.loads(item[0]) for item in rows])),
            "transitions": [{"observed_at": at, "previous": previous, "current": current}
                            for at, previous, current in changes],
            "last_successful_at": recent[0] if recent else None,
        }
    except (sqlite3.Error, json.JSONDecodeError) as exc:
        raise ValueError("invalid_history") from exc
