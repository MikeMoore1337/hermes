"""Fixed-schema, read-only VPS resource signals for the existing Ops Watch timer.

Never opens a network connection, executes a command, stores raw metrics in incident
records or treats an unconfigured YFC source as an outage.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import math
from pathlib import Path
import sqlite3
from typing import Any

ROOT = Path("/var/lib/hermes-control-center/infrastructure")
HOSTS = ("hermes", "yfc")
METRICS = {"cpu": "cpu_used_percent", "ram": "ram_used_percent",
           "disk": "disk_used_percent"}
HIGH = 90.0
RECOVERED = 80.0
MAX_AGE = timedelta(minutes=3)
OFFLINE_AGE = timedelta(minutes=15)
MAX_FUTURE = timedelta(seconds=30)


def _date(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid_time")
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise ValueError("invalid_timezone")
    return date.astimezone(UTC)


def _percent(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
        raise ValueError("invalid_percent")
    return float(value)


def _history(directory: Path, host: str, now: datetime) -> list[tuple[datetime, dict[str, float | None]]]:
    db = directory / "history.sqlite3"
    if db.is_symlink() or not db.is_file():
        return []
    if db.stat().st_size > 50_000_000:
        raise ValueError("history_oversize")
    rows = []
    # mode=ro and no creation; parameterized fixed-table query.
    uri = db.absolute().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=1) as conn:
        for at, cpu, ram, disk in conn.execute(
            "SELECT observed_at,cpu,ram,disk FROM samples WHERE host=? "
            "ORDER BY observed_at DESC LIMIT 3", (host,)):
            timestamp = _date(at)
            if timestamp > now + MAX_FUTURE:
                raise ValueError("future_history")
            values: dict[str, float | None] = {}
            for key, value in zip(METRICS, (cpu, ram, disk)):
                values[key] = None if value is None else _percent(value)
            rows.append((timestamp, values))
    return rows


def _levels(rows: list[tuple[datetime, dict[str, float | None]]],
            now: datetime) -> dict[str, str]:
    result = {key: "unknown" for key in METRICS}
    if len(rows) != 3 or now - rows[0][0] > MAX_AGE:
        return result
    if any(not timedelta(seconds=30) <= rows[i][0] - rows[i+1][0]
           <= timedelta(minutes=3) for i in range(2)):
        return result
    for name in METRICS:
        values = [values[name] for _, values in rows]
        if any(value is None for value in values):
            continue
        if all(value >= HIGH for value in values):
            result[name] = "high"
        elif all(value <= RECOVERED for value in values):
            result[name] = "normal"
    return result


def observe(directory: Path = ROOT, *, now: datetime | None = None) -> dict[str, Any]:
    """Return two bounded statuses; never expose raw CPU, paths, SSH or secrets."""
    at = now or datetime.now(UTC)
    if at.tzinfo is None:
        raise ValueError("timezone_required")
    at = at.astimezone(UTC)
    result: dict[str, Any] = {}
    for host in HOSTS:
        path = directory / (host + ".json")
        result[host] = {"status": "not_connected"}
        try:
            if path.is_symlink():
                raise ValueError("source_symlink")
            if not path.is_file():
                # A previously observed host that loses its source file is offline;
                # a never-configured YFC host is not an incident.
                rows = _history(directory, host, at)
                if rows and at - rows[0][0] > OFFLINE_AGE:
                    result[host] = {"status": "offline"}
                continue
            if path.stat().st_size > 16384:
                raise ValueError("source_oversized")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(raw, dict) or raw.get("schema") != 1 or
                    raw.get("host") != host or raw.get("source") != "linux_procfs_local"):
                raise ValueError("source_identity")
            stamp = _date(raw.get("observed_at"))
            if stamp > at + MAX_FUTURE:
                raise ValueError("future_source")
            metrics = raw.get("metrics")
            if not isinstance(metrics, dict):
                raise ValueError("source_metrics")
            for field in ("ram_used_percent", "disk_used_percent"):
                _percent(metrics.get(field))
            cpu = metrics.get("cpu_used_percent")
            if cpu is not None:
                _percent(cpu)
            if at - stamp > OFFLINE_AGE:
                result[host] = {"status": "offline"}
            elif at - stamp > MAX_AGE:
                result[host] = {"status": "stale"}
            else:
                levels = _levels(_history(directory, host, at), at)
                result[host] = {"status": "online", "levels": levels}
        except (OSError, ValueError, UnicodeError, TypeError, sqlite3.Error,
                OverflowError):
            # Invalid or inaccessible data must not erase a confirmed incident.
            result[host] = {"status": "unknown"}
    return result
