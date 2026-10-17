"""Bounded, metadata-only Codex rollout analytics for H-15 / #272.

Codex owns its session JSONL files. This collector never starts Codex,
opens auth.json, or stores user messages, model responses, tools' arguments,
repository paths, or secrets. It is DISABLED until separately provisioned.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3

DEFAULT_DB = Path("/var/lib/hermes-codex-usage/analytics.sqlite3")
MAX_LINE = 128 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 100_000
RETENTION_DAYS = 90
SAFE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
SESSION = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$")
PROJECTS = {"hermes": "Hermes", "your-fitness-coach": "Your Fitness Coach",
            "second-brain": "Second Brain"}
FIELDS = ("input_tokens", "output_tokens", "cached_input_tokens")
# Standard API rates per 1M tokens, NOT subscription billing; pinned 2026-10-18.
# Source: https://developers.openai.com/api/docs/models/gpt-5.3-codex
# Source: https://developers.openai.com/api/docs/models/gpt-5.2-codex
PRICES_V1 = {"gpt-5.3-codex": (1.75, 0.175, 14.0),
             "gpt-5.2-codex": (1.75, 0.175, 14.0)}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def ident(value):
    return value if isinstance(value, str) and SAFE.fullmatch(value) else None


def project_from_cwd(cwd):
    # A directory name is a weak attribution, not proof of a Git remote.
    if not isinstance(cwd, str) or len(cwd) > 4096:
        return "unattributed"
    # Never send the actual cwd to the web service or SQLite.
    name = cwd.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return PROJECTS.get(name, "unattributed")


def _guarded(path: Path, root: Path):
    if root.is_symlink() or not root.is_dir() or path.is_symlink():
        return False
    try:
        path.relative_to(root)
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return False
        current = path.parent
        while current != root:
            if current.is_symlink():
                return False
            current = current.parent
        return True
    except (OSError, ValueError):
        return False


def _files(home: Path):
    root = home / "sessions"
    if not root.is_dir() or root.is_symlink():
        return []
    files = []
    # No recursive glob over arbitrary home; exactly sessions/YYYY/MM/DD/rollout-*.
    for year in sorted(root.iterdir()):
        if year.is_symlink() or not year.is_dir() or not re.fullmatch(r"\d{4}", year.name):
            continue
        for month in sorted(year.iterdir()):
            if month.is_symlink() or not month.is_dir() or not re.fullmatch(r"\d{2}", month.name):
                continue
            for day in sorted(month.iterdir()):
                if day.is_symlink() or not day.is_dir() or not re.fullmatch(r"\d{2}", day.name):
                    continue
                for path in sorted(day.iterdir()):
                    if path.name.startswith("rollout-") and SESSION.search(path.name) and _guarded(path, root):
                        files.append(path)
                    if len(files) >= 3000:
                        return files
    return files


def _schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS files (
          name TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL,
          session_id TEXT NOT NULL, model TEXT, effort TEXT, project TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS counters (
          session_id TEXT PRIMARY KEY, input_tokens INTEGER NOT NULL,
          output_tokens INTEGER NOT NULL, cached_input_tokens INTEGER
        );
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, session_id TEXT NOT NULL, observed_at TEXT NOT NULL,
          kind TEXT NOT NULL, model TEXT, effort TEXT, project TEXT NOT NULL,
          input_tokens INTEGER, output_tokens INTEGER, cached_input_tokens INTEGER,
          quality TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_time ON events(observed_at);
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY CHECK (id=1), collected_at TEXT NOT NULL,
          scanned_files INTEGER NOT NULL, invalid_events INTEGER NOT NULL,
          incomplete_files INTEGER NOT NULL
        );
    """)


def _count(value):
    return value if type(value) is int and 0 <= value <= 10**13 else None


def _process(db, record, session, observed, position, name, model, effort, project):
    if not isinstance(record, dict):
        return model, effort, project, 1
    typ = record.get("type")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return model, effort, project, 0
    if typ == "session_meta":
        # Do not store the full metadata record or cwd.
        return model, effort, project_from_cwd(payload.get("cwd")), 0
    if typ == "turn_context":
        model = ident(payload.get("model")) or None
        effort = ident(payload.get("effort") or payload.get("reasoning_effort")) or None
        return model, effort, project, 0
    if typ != "event_msg":
        return model, effort, project, 0
    kind = payload.get("type")
    if kind in ("task_started", "task_complete"):
        db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (f"{name}:{position}", session, observed, kind, model,
                    effort, project, None, None, None, "verified"))
        return model, effort, project, 0
    if kind != "token_count":
        return model, effort, project, 0
    info = payload.get("info")
    total = info.get("total_token_usage") if isinstance(info, dict) else None
    if not isinstance(total, dict):
        return model, effort, project, 0
    current = [_count(total.get(key)) for key in FIELDS]
    if current[0] is None or current[1] is None:
        return model, effort, project, 1
    previous = db.execute("SELECT input_tokens,output_tokens,cached_input_tokens "
                          "FROM counters WHERE session_id=?", (session,)).fetchone()
    if previous is None:
        previous = (0, 0, 0 if current[2] is not None else None)
    if current[0] < previous[0] or current[1] < previous[1] or (
            current[2] is not None and previous[2] is not None and current[2] < previous[2]):
        # A reset/partial history cannot be treated as more spend.
        return model, effort, project, 1
    delta = [current[i] - previous[i] if current[i] is not None and previous[i] is not None
             else None for i in range(3)]
    if not any(value for value in delta if value is not None):
        # Repeated rate-limit-only token_count is NOT an incremental usage event.
        return model, effort, project, 0
    db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
               (f"{name}:{position}", session, observed, "usage", model, effort,
                project, *delta, "verified" if delta[2] is not None and model else "partial"))
    db.execute("INSERT INTO counters VALUES (?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET "
               "input_tokens=excluded.input_tokens,output_tokens=excluded.output_tokens,"
               "cached_input_tokens=excluded.cached_input_tokens",
               (session, current[0], current[1], current[2]))
    return model, effort, project, 0


def collect(home: Path, database: Path = DEFAULT_DB, *, now=None):
    """Single bounded transaction, safe cursor and crash backfill.

    Run only as hermes-codex; CODEX_HOME should point to its isolated auth home.
    """
    now = now or datetime.now(timezone.utc)
    if home.is_symlink() or database.is_symlink():
        raise ValueError("symlink_denied")
    if not (home / "sessions").is_dir():
        raise ValueError("codex_sessions_unavailable")
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists() and database.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("analytics_db_capacity")
    stats = {"scanned_files": 0, "invalid_events": 0, "incomplete_files": 0}
    budget = MAX_SCAN_BYTES
    with sqlite3.connect(database, timeout=5) as db:
        db.execute("PRAGMA busy_timeout=5000")
        _schema(db)
        db.execute("BEGIN IMMEDIATE")
        for path in _files(home):
            if budget <= 0:
                stats["incomplete_files"] += 1
                break
            relative = path.relative_to(home / "sessions").as_posix()
            match = SESSION.search(path.name)
            session = match.group(1)
            inode = path.stat().st_ino
            previous = db.execute("SELECT inode,offset,model,effort,project FROM files WHERE name=?",
                                  (relative,)).fetchone()
            if previous and previous[0] == inode:
                offset, model, effort, project = previous[1:]
            else:
                offset, model, effort, project = 0, None, None, "unattributed"
                # New inode with the same session ID cannot be blindly counted twice.
                if previous:
                    stats["invalid_events"] += 1
                    continue
            # O_NOFOLLOW prevents a last-moment symlink substitution on Linux.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                with os.fdopen(fd, "rb") as stream:
                    if os.fstat(stream.fileno()).st_ino != inode:
                        raise ValueError("file_changed")
                    stream.seek(offset)
                    while budget > 0:
                        start = stream.tell()
                        line = stream.readline(min(MAX_LINE + 1, budget))
                        if not line:
                            break
                        budget -= len(line)
                        if not line.endswith(b"\n"):
                            if len(line) <= MAX_LINE and stream.tell() == os.fstat(stream.fileno()).st_size:
                                stats["incomplete_files"] += 1
                                break  # trailing incomplete JSONL, retry from start next tick
                            # Large row (typically prompt/response) discarded, not parsed or stored.
                            while line and not line.endswith(b"\n") and budget > 0:
                                line = stream.readline(min(MAX_LINE + 1, budget))
                                budget -= len(line)
                            if not line.endswith(b"\n"):
                                stats["incomplete_files"] += 1
                                break
                            offset = stream.tell()
                            stats["invalid_events"] += 1
                            continue
                        offset = stream.tell()
                        # Only parse known metadata record families.
                        if not any(marker in line for marker in
                                   (b'"token_count"', b'"task_started"', b'"task_complete"',
                                    b'"session_meta"', b'"turn_context"')):
                            continue
                        try:
                            entry = json.loads(line)
                            observed = timestamp(entry.get("timestamp"))
                            if observed is None:
                                raise ValueError("invalid_timestamp")
                            model, effort, project, invalid = _process(
                                db, entry, session, observed, start, relative,
                                model, effort, project)
                            stats["invalid_events"] += invalid
                        except (ValueError, TypeError, UnicodeDecodeError, sqlite3.IntegrityError):
                            stats["invalid_events"] += 1
            except (OSError, ValueError):
                raise ValueError("analytics_file_unavailable") from None
            db.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                       "inode=excluded.inode,offset=excluded.offset,model=excluded.model,"
                       "effort=excluded.effort,project=excluded.project",
                       (relative, inode, offset, session, model, effort, project))
            stats["scanned_files"] += 1
        cutoff = (now - timedelta(days=RETENTION_DAYS)).isoformat()
        db.execute("DELETE FROM events WHERE observed_at<?", (cutoff,))
        db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY observed_at DESC "
                   "LIMIT -1 OFFSET ?)", (MAX_EVENTS,))
        db.execute("INSERT INTO scans VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                   "collected_at=excluded.collected_at,scanned_files=excluded.scanned_files,"
                   "invalid_events=excluded.invalid_events,incomplete_files=excluded.incomplete_files",
                   (now.isoformat(), stats["scanned_files"], stats["invalid_events"],
                    stats["incomplete_files"]))
        db.commit()
    os.chmod(database, 0o640)
    return stats


def _union_seconds(intervals):
    total, end = 0.0, None
    for start, finish in sorted(intervals):
        if end is None or start > end:
            total += (finish - start).total_seconds()
            end = finish
        elif finish > end:
            total += (finish - end).total_seconds()
            end = finish
    return round(total)


def read(database: Path = DEFAULT_DB, *, period="7d", now=None):
    if period not in ("24h", "7d", "30d", "all"):
        raise ValueError("invalid_period")
    empty = {"schema": 1, "source": "codex-local-rollout-jsonl", "period": period,
             "quality": "unknown", "observed_at": None, "sessions": None,
             "completed_turns": None, "duration_seconds": None,
             "tokens": {"input": None, "output": None, "cached_input": None, "total": None},
             "api_equivalent_usd": None, "actual_spend_usd": None,
             "price_version": "2026-10-18-v1", "pricing_coverage": None,
             "models": [], "projects": [], "tasks": [],
             "daily": [], "invalid_events": None, "incomplete_files": None,
             "notes": ["No verified local Codex usage telemetry available"]}
    if database.is_symlink() or not database.is_file():
        return empty
    now = now or datetime.now(timezone.utc)
    start = {"24h": now - timedelta(days=1), "7d": now - timedelta(days=7),
             "30d": now - timedelta(days=30), "all": datetime(1970, 1, 1, tzinfo=timezone.utc)}[period]
    try:
        uri = database.absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as db:
            scan = db.execute("SELECT collected_at,invalid_events,incomplete_files FROM scans "
                              "WHERE id=1").fetchone()
            rows = db.execute("SELECT session_id,observed_at,kind,model,effort,project,"
                              "input_tokens,output_tokens,cached_input_tokens,quality "
                              "FROM events WHERE observed_at>=? ORDER BY observed_at ASC LIMIT ?",
                              (start.isoformat(), MAX_EVENTS)).fetchall()
    except sqlite3.Error as exc:
        raise ValueError("analytics_unavailable") from exc
    if not scan or not rows:
        if scan:
            empty.update(observed_at=scan[0], invalid_events=scan[1],
                         incomplete_files=scan[2], sessions=0, completed_turns=0)
            empty["notes"] = ["No observed events in this period; not evidence of idle time"]
        return empty
    sessions, by_model, by_project, daily, intervals, active = set(), {}, {}, {}, [], {}
    sums = [0, 0, 0]
    cache_complete = True
    price_total, priced, usage_count = 0.0, 0, 0
    turns = 0
    for session, time, kind, model, effort, project, inp, out, cached, quality in rows:
        sessions.add(session)
        if kind == "task_started":
            active[session] = datetime.fromisoformat(time)
        elif kind == "task_complete":
            turns += 1
            begin = active.pop(session, None)
            finish = datetime.fromisoformat(time)
            if begin is not None and finish >= begin:
                intervals.append((begin, finish))
        elif kind == "usage":
            usage_count += 1
            sums[0] += inp
            sums[1] += out
            if cached is None:
                cache_complete = False
            else:
                sums[2] += cached
            key = model or "unattributed"
            for target, label in ((by_model, key), (by_project, project)):
                item = target.setdefault(label, {"name": label, "input": 0, "output": 0, "cached": 0})
                item["input"] += inp
                item["output"] += out
                item["cached"] += cached or 0
            day = time[:10]
            item = daily.setdefault(day, {"date": day, "input": 0, "output": 0, "cached": 0})
            item["input"] += inp
            item["output"] += out
            item["cached"] += cached or 0
            if key in PRICES_V1 and cached is not None:
                raw, cache_rate, output_rate = PRICES_V1[key]
                price_total += ((inp-cached)*raw + cached*cache_rate + out*output_rate)/1e6
                priced += 1
    quality = ("partial" if scan[1] or scan[2] or not cache_complete or priced < usage_count
               or any(x["name"] == "unattributed" for x in by_model.values()) else "verified")
    empty.update(quality=quality, observed_at=scan[0], sessions=len(sessions),
                 completed_turns=turns, duration_seconds=_union_seconds(intervals) if intervals else None,
                 tokens={"input": sums[0], "output": sums[1],
                         "cached_input": sums[2] if cache_complete else None,
                         "total": sums[0]+sums[1]},
                 api_equivalent_usd=round(price_total, 6) if priced else None,
                 pricing_coverage=round(priced / usage_count, 3) if usage_count else None,
                 models=sorted(by_model.values(), key=lambda x: -x["input"])[:30],
                 projects=sorted(by_project.values(), key=lambda x: -x["input"])[:30],
                 daily=sorted(daily.values())[-90:], invalid_events=scan[1],
                 incomplete_files=scan[2],
                 notes=["Real subscription charges unknown",
                        "Task attribution unavailable without verified session-to-job link",
                        "Duration is a union of observed completed Codex turns, not idle time"])
    return empty


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home", type=Path)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    args = parser.parse_args()
    home = args.codex_home or Path(os.environ.get("CODEX_HOME", ""))
    if not home.is_absolute():
        parser.error("absolute CODEX_HOME required")
    result = collect(home, args.database)
    print(json.dumps({"status": "ok", **result}))


if __name__ == "__main__":
    main()
