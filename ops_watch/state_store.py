"""Transactional local outbox for Ops Watch. No network or delivery permissions.

A single SQLite transaction stores the canonical incident state and new/
resolved transitions. JSON files are derivative views and may be regenerated.
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .core import INCIDENT_CODES, InputError, changes
from .incident_preview import render

DATABASE = "incidents.sqlite3"
MAX_EVENTS = 1000
MAX_STATE_BYTES = 16384


def _connection(directory: Path) -> sqlite3.Connection:
    path = directory / DATABASE
    if path.is_symlink():
        raise InputError("unsafe_outbox_db")
    try:
        if not path.exists():
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        info = path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise InputError("unsafe_outbox_db")
        db = sqlite3.connect(path, timeout=2)
        db.execute("PRAGMA busy_timeout=2000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        return db
    except (OSError, sqlite3.Error) as exc:
        raise InputError("outbox_unavailable") from exc


def _safe_findings(items: Any) -> list[dict[str, str]]:
    """Store only approved incident IDs, never raw input values."""
    if not isinstance(items, list) or len(items) > len(INCIDENT_CODES):
        raise InputError("invalid_current_incidents")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or type(item.get("code")) is not str:
            raise InputError("invalid_current_incidents")
        code = item["code"]
        if (code not in INCIDENT_CODES or item.get("fingerprint") != f"ops:{code}"
                or code in seen):
            raise InputError("invalid_current_incidents")
        seen.add(code)
        result.append({"code": code, "fingerprint": f"ops:{code}"})
    return sorted(result, key=lambda x: x["code"])


def persist(
    directory: Path,
    current: list[dict[str, Any]],
    legacy_loader: Callable[[], list[dict[str, Any]]],
    *,
    observed: datetime,
) -> tuple[dict[str, list[str]], list[dict[str, str]], int]:
    """Store one coherent transition set with no send, retry or data loss.

    On first use, migrate the old JSON findings once. If a derived JSON write
    failed on a prior run, SQLite remains authoritative, so later passes do
    not generate duplicate transitions.
    """
    if observed.tzinfo is None:
        raise InputError("observed_timezone_required")
    safe_current = _safe_findings(current)
    try:
        with closing(_connection(directory)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS state ("
                "id INTEGER PRIMARY KEY CHECK(id=1), findings_json TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "fingerprint TEXT NOT NULL, phase TEXT NOT NULL, "
                "severity TEXT NOT NULL, title TEXT NOT NULL, "
                "action TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            row = db.execute("SELECT findings_json FROM state WHERE id=1").fetchone()
            if row is None:
                previous = _safe_findings(legacy_loader())
                previous_raw = json.dumps(previous, sort_keys=True, separators=(",", ":"))
                if len(previous_raw) > MAX_STATE_BYTES:
                    raise InputError("legacy_state_oversize")
                db.execute(
                    "INSERT INTO state(id,findings_json) VALUES(1,?)",
                    (previous_raw,),
                )
            else:
                if type(row[0]) is not str or len(row[0]) > MAX_STATE_BYTES:
                    raise InputError("corrupt_outbox_state")
                try:
                    previous = json.loads(row[0])
                except ValueError as exc:
                    raise InputError("corrupt_outbox_state") from exc
                previous = _safe_findings(previous)
            delta = changes(previous, safe_current)
            previews = render(delta, safe_current)
            event_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if event_count + len(previews) > MAX_EVENTS:
                raise InputError("outbox_full")
            when = observed.astimezone(UTC).isoformat()
            for item in previews:
                db.execute(
                    "INSERT INTO events "
                    "(fingerprint,phase,severity,title,action,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        "ops:" + item["code"], item["phase"], item["severity"],
                        item["title"], item["action"], when,
                    ),
                )
            current_json = json.dumps(safe_current, sort_keys=True, separators=(",", ":"))
            if len(current_json) > MAX_STATE_BYTES:
                raise InputError("current_state_oversize")
            db.execute("UPDATE state SET findings_json=? WHERE id=1", (current_json,))
            db.commit()
            return delta, previews, event_count + len(previews)
    except sqlite3.Error as exc:
        raise InputError("outbox_unavailable") from exc


def inspect(directory: Path, *, max_items: int = 50) -> list[dict[str, Any]]:
    """Read a bounded durable local queue. No acknowledgment or delivery."""
    if type(max_items) is not int or not 1 <= max_items <= 50:
        raise InputError("outbox_inspection_limit")
    db_path = directory / DATABASE
    if db_path.is_symlink() or not db_path.is_file():
        raise InputError("outbox_unavailable")
    info = db_path.stat(follow_symlinks=False)
    if (stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()
            or not stat.S_ISREG(info.st_mode)):
        raise InputError("unsafe_outbox_db")
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
            rows = db.execute(
                "SELECT id,fingerprint,phase,severity,title,action,created_at "
                "FROM events ORDER BY id DESC LIMIT ?", (max_items,)
            ).fetchall()
    except sqlite3.Error as exc:
        raise InputError("outbox_unavailable") from exc
    return [
        {
            "id": id_, "fingerprint": fingerprint, "phase": phase,
            "severity": severity, "title": title, "action": action,
            "created_at": created_at,
        }
        for id_, fingerprint, phase, severity, title, action, created_at in rows
    ]
