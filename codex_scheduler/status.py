"""Sanitized read-only scheduler telemetry. Never opens the write connection."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from urllib.parse import quote

from control_center.codex_policy import decision
from .core import DEFAULT_DB


class StatusUnavailable(ValueError):
    pass


def read_status(db: Path = DEFAULT_DB, *, quota_snapshot: dict | None = None) -> dict:
    quota = decision(quota_snapshot)
    base = {
        "schema": 1, "mode": "read_only", "execution_enabled": False,
        "quota": quota, "queue_state": "not_configured",
        "counts": {"queued": 0, "deferred": 0, "running": 0,
                   "blocked": 0, "completed": 0},
        "last_successful_at": None, "recovery_errors": 0, "jobs": [],
    }
    target = Path(db)
    if target.is_symlink() or target.parent.is_symlink():
        raise StatusUnavailable("unsafe_queue_path")
    if not target.is_file():
        return base
    uri = f"file:{quote(str(target.resolve()))}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=2) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("""SELECT job_id,created,updated,status,
                 last_error_code,finished FROM jobs
                 ORDER BY created DESC LIMIT 50""").fetchall()
            counts = c.execute("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status").fetchall()
            last = c.execute("SELECT MAX(finished) FROM jobs WHERE status='succeeded'").fetchone()[0]
            recovery = c.execute("""SELECT COUNT(*) FROM jobs WHERE status='blocked'
                       AND invocation_state='uncertain'""").fetchone()[0]
    except (sqlite3.Error, OSError) as exc:
        raise StatusUnavailable("queue_unavailable") from exc
    for item in counts:
        status = item["status"]
        if status in ("queued", "deferred", "running", "blocked"):
            base["counts"][status] += item["n"]
        elif status == "claimed":
            base["counts"]["running"] += item["n"]
        elif status in ("succeeded", "failed", "cancelled"):
            base["counts"]["completed"] += item["n"]
    def utc(value):
        return (datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
                .replace("+00:00", "Z") if value is not None else None)
    base["queue_state"] = "available"
    base["recovery_errors"] = recovery
    base["last_successful_at"] = utc(last)
    base["jobs"] = [{
        "job_id": row["job_id"], "status": row["status"],
        "created_at": utc(row["created"]), "updated_at": utc(row["updated"]),
        "wait_reason": row["last_error_code"] if row["status"] in
            ("deferred", "blocked", "cancelled") else None,
        "manual_review": row["status"] == "blocked",
    } for row in rows]
    return base
