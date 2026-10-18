"""Bounded, SQLite-only history for official GitHub token-scoped rate resources."""
from __future__ import annotations

import datetime as dt
import math
import os
from pathlib import Path
import sqlite3

from control_center.github_rate_limit import OUTPUT, RESOURCES, SOURCE

DB = OUTPUT.with_name("github-history.sqlite3")
RETENTION = 30
MAX_POINTS = 500


def _date(value: str) -> dt.datetime:
    date = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise ValueError("time")
    return date.astimezone(dt.timezone.utc)


def append(snapshot: dict, path: Path = DB, *, group: str | None = None) -> None:
    if snapshot.get("source") != SOURCE or snapshot.get("status") != "ok":
        raise ValueError("invalid_source")
    observed = snapshot.get("observed_at")
    _date(observed)
    items = snapshot.get("resources")
    if not isinstance(items, list) or len(items) > len(RESOURCES):
        raise ValueError("invalid_resources")
    rows = []
    for entry in items:
        if not isinstance(entry, dict) or entry.get("resource") not in RESOURCES:
            raise ValueError("invalid_resource")
        limit, remaining = entry.get("quota_limit"), entry.get("remaining")
        if (type(limit) is not int or type(remaining) is not int
                or limit < 0 or not 0 <= remaining <= limit):
            raise ValueError("invalid_limits")
        percentage = 100 * remaining / limit if limit > 0 else None
        rows.append((observed, entry["resource"], remaining,
                     limit, None if percentage is None else round(percentage, 2)))
    if path.is_symlink():
        raise ValueError("symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=3) as con:
        con.execute("PRAGMA busy_timeout=3000")
        con.execute("BEGIN IMMEDIATE")
        con.execute("""CREATE TABLE IF NOT EXISTS samples (
            observed_at TEXT NOT NULL, resource TEXT NOT NULL,
            remaining INTEGER NOT NULL, quota_limit INTEGER NOT NULL,
            remaining_percent REAL,
            PRIMARY KEY(observed_at,resource))""")
        con.executemany("INSERT OR IGNORE INTO samples VALUES (?,?,?,?,?)", rows)
        cutoff = (_date(observed)-dt.timedelta(days=RETENTION)).isoformat()
        con.execute("DELETE FROM samples WHERE observed_at < ?", (cutoff,))
    os.chmod(path,0o640)
    if group:
        import grp
        os.chown(path,0,grp.getgrnam(group).gr_gid)


def read(path: Path = DB, *, resource: str, days: int = 7,
         now: dt.datetime | None = None) -> dict:
    if resource not in RESOURCES or type(days) is not int or days not in (1,7,30):
        raise ValueError("invalid_filter")
    result = {"schema":1,"source":"github-rate-limit-history",
              "resource":resource,"days":days,"points":[]}
    if path.is_symlink() or not path.is_file():
        return result
    date = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    since = (date-dt.timedelta(days=days)).isoformat()
    try:
        with sqlite3.connect(path.absolute().as_uri()+"?mode=ro",
                             uri=True,timeout=2) as conn:
            raw=conn.execute(
                "SELECT observed_at,remaining_percent,remaining,quota_limit "
                "FROM samples WHERE resource=? AND observed_at>=? "
                "ORDER BY observed_at LIMIT 35000",(resource,since)).fetchall()
        if len(raw)>35000:
            raise ValueError("oversized_history")
        points=[]
        for observed,percent,remaining,limit in raw:
            _date(observed)
            if type(limit) is not int or type(remaining) is not int or not 0<=remaining<=limit:
                raise ValueError("invalid_value")
            if percent is not None and (
                    type(percent) not in (int,float) or
                    not math.isfinite(percent) or not 0<=percent<=100):
                raise ValueError("invalid_percentage")
            points.append({"at":observed,"remaining_percent":percent})
        if len(points)>MAX_POINTS:
            points=[points[(i*(len(points)-1))//(MAX_POINTS-1)]
                    for i in range(MAX_POINTS)]
        result["points"]=points
        return result
    except (sqlite3.Error,TypeError,AttributeError,OverflowError) as exc:
        raise ValueError("history_unavailable") from exc
