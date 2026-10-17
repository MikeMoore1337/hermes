"""Bounded, read-only history projection for Desktop Commander quota/device metadata."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import sqlite3

from control_center.desktop_commander import (
    SOURCE, SCHEMA, TTL_SECONDS, utc_now, iso, read_snapshot, CommanderError,
)

MAX_RECORDS = 3000
RETENTION_DAYS = 30
MAX_CHART_POINTS = 500
DDL = """CREATE TABLE IF NOT EXISTS observations (
    observed_at TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    remaining INTEGER,
    online_count INTEGER NOT NULL,
    offline_count INTEGER NOT NULL
)"""


class HistoryError(Exception):
    pass


def append(snapshot, path, now=None):
    """Persist only reduced metrics; never names, IDs, tokens or raw tool responses."""
    if snapshot.get("source") != SOURCE or snapshot.get("schema") != SCHEMA:
        raise ValueError("invalid source")
    date = snapshot.get("observed_at")
    if not isinstance(date, str):
        raise ValueError("missing observation")
    current = now or utc_now()
    moment = dt.datetime.fromisoformat(date.replace("Z", "+00:00"))
    if moment.tzinfo is None or abs((current - moment).total_seconds()) > TTL_SECONDS:
        raise ValueError("invalid observation time")
    remaining = snapshot.get("quota_remaining_percent")
    if remaining is not None and (type(remaining) is not int or not 0 <= remaining <= 100):
        raise ValueError("invalid quota")
    status = snapshot.get("status")
    if status not in ("monitored", "exhausted", "unknown", "unavailable", "auth_required"):
        raise ValueError("invalid observation status")
    devices = snapshot.get("devices")
    if not isinstance(devices, list) or len(devices) > 16 or any(
            not isinstance(v, dict) or v.get("state") not in ("online", "offline", "unknown")
            for v in devices):
        raise ValueError("invalid devices")
    online = sum(1 for v in devices if v["state"] == "online")
    offline = sum(1 for v in devices if v["state"] == "offline")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=5) as conn:
        conn.execute(DDL)
        conn.execute("INSERT OR IGNORE INTO observations VALUES (?, ?, ?, ?, ?)",
                     (date, status, remaining, online, offline))
        cutoff = iso(current - dt.timedelta(days=RETENTION_DAYS))
        conn.execute("DELETE FROM observations WHERE observed_at < ?", (cutoff,))
        conn.execute("""DELETE FROM observations WHERE observed_at NOT IN (
            SELECT observed_at FROM observations ORDER BY observed_at DESC LIMIT ?)""",
                     (MAX_RECORDS,))
    os.chmod(path, 0o640)


def read(path, days=7, now=None):
    """Read-only SQLite connection with bounded results; no database creation."""
    if type(days) is not int or not 1 <= days <= 30:
        raise ValueError("invalid days")
    path = Path(path)
    if not path.exists():
        return {"schema": SCHEMA, "source": SOURCE, "status": "not_configured",
                "days": days, "points": []}
    try:
        cutoff = iso((now or utc_now()) - dt.timedelta(days=days))
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=3) as conn:
            rows = conn.execute(
                """SELECT observed_at, status, remaining, online_count, offline_count
                   FROM observations WHERE observed_at >= ? ORDER BY observed_at ASC
                   LIMIT ?""", (cutoff, MAX_RECORDS + 1)).fetchall()
        if len(rows) > MAX_RECORDS:
            raise HistoryError("oversized_history")
        # Downsample over the entire interval, retaining the first and last.
        if len(rows) > MAX_CHART_POINTS:
            rows = [rows[i * (len(rows) - 1) // (MAX_CHART_POINTS - 1)]
                    for i in range(MAX_CHART_POINTS)]
        points = []
        for when, status, pct, online, offline in rows:
            if (not isinstance(when, str) or not isinstance(status, str)
                    or status not in ("monitored", "exhausted", "unknown",
                                      "unavailable", "auth_required")
                    or pct is not None and (type(pct) is not int or not 0 <= pct <= 100)
                    or any(type(x) is not int or not 0 <= x <= 16 for x in (online, offline))):
                raise HistoryError("invalid_history")
            points.append({"at": when, "remaining_percent": pct,
                           "online": online, "offline": offline, "status": status})
        return {"schema": SCHEMA, "source": SOURCE, "status": "available",
                "days": days, "points": points}
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise HistoryError("history_unavailable") from exc
