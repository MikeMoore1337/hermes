"""H-30 #467: bounded *synthetic-only* SQLite FTS5 metadata index.

No permanent database, privileged ingest, real agent sessions, vault access,
network, external files, raw prompts or search API. All source URIs in fixtures
are illustrative claims, NOT independently authenticated receipts.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

SCHEMA = "h30-synthetic-metadata-v1"
PROJECT = "hermes"
SCOPE = "synthetic:hermes"
MAX_RECORDS = 256
MAX_TOMBSTONES = 256
MAX_RESULTS = 20
RETENTION_DAYS = 30
DAY = 86400
FIELDS = frozenset({
    "schema_version", "task_id", "project_id", "kind", "title",
    "timestamp", "source_uri", "revision", "scope", "status", "revoked",
})
KINDS = frozenset({"issue", "pr", "ci", "deploy"})
STATUSES = frozenset({"verified", "stale", "unknown"})
ID = re.compile(r"H-demo-[0-9]{4}\Z")
URI = re.compile(r"https://github\.com/MikeMoore1337/hermes/(?:issues|pull|actions/runs)/[0-9]{5,10}\Z")
QUERY = re.compile(r"[\w\s-]{1,80}\Z", re.UNICODE)
PRIVATE = re.compile(
    r"(?:ghp_|github_pat_|sk-[A-Za-z0-9]|bearer\b|password\b|"
    r"secret\b|token\s*[=:]|vault\b|/home/|/users/|/etc/|"
    r"[A-Za-z]:\\|\\\\|\.\./|\bprivate[_ -]path\b)",
    re.IGNORECASE,
)
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class IndexDenied(ValueError):
    """Sanitized reason: never echo user-controlled raw values."""


def _check_time(value: Any) -> int:
    if type(value) is not int or not 1700000000 <= value <= 2100000000:
        raise IndexDenied("TIMESTAMP_INVALID")
    return value


def _validate(record: Any, now: int) -> dict:
    if type(record) is not dict or set(record) != FIELDS:
        raise IndexDenied("FIELD_ALLOWLIST")
    if record["schema_version"] != 1:
        raise IndexDenied("SCHEMA_VERSION")
    if (type(record["project_id"]) is not str or
            record["project_id"] != PROJECT or
            type(record["scope"]) is not str or record["scope"] != SCOPE):
        raise IndexDenied("PROJECT_SCOPE_DENIED")
    if type(record["task_id"]) is not str or not ID.fullmatch(record["task_id"]):
        raise IndexDenied("TASK_ID_DENIED")
    if type(record["kind"]) is not str or record["kind"] not in KINDS:
        raise IndexDenied("KIND_DENIED")
    title = record["title"]
    if (type(title) is not str or not 1 <= len(title) <= 120 or
            not 1 <= len(title.encode("utf-8")) <= 240 or
            PRIVATE.search(title) or any(ord(c) < 32 for c in title)):
        raise IndexDenied("UNSAFE_TITLE")
    stamp = _check_time(record["timestamp"])
    if stamp < now - RETENTION_DAYS * DAY or stamp > now + 120:
        raise IndexDenied("OUT_OF_RETENTION")
    if (type(record["revision"]) is not int or
            not 1 <= record["revision"] <= 1000000):
        raise IndexDenied("REVISION_INVALID")
    if type(record["revoked"]) is not bool or record["revoked"]:
        raise IndexDenied("REVOKED_INPUT")
    state = record["status"]
    if type(state) is not str or state not in STATUSES:
        raise IndexDenied("STATUS_INVALID")
    uri = record["source_uri"]
    if uri is not None and (
            type(uri) is not str or not URI.fullmatch(uri) or PRIVATE.search(uri)):
        raise IndexDenied("SOURCE_URI_DENIED")
    if state == "verified" and uri is None:
        raise IndexDenied("VERIFIED_WITHOUT_SOURCE")
    if uri is not None:
        route = {"issue": "/issues/", "pr": "/pull/",
                 "ci": "/actions/runs/", "deploy": "/actions/runs/"}[record["kind"]]
        if route not in uri:
            raise IndexDenied("SOURCE_TYPE_DENIED")
    return dict(record)


class SyntheticIndex:
    """Per-instance hardcoded project and in-memory-only capability.

    This object cannot import arbitrary rows via file paths, external SQL,
    network clients or caller-chosen namespaces. It is NOT a secure real-user
    authorization boundary; the only consumer is offline synthetic tests.
    """

    def __init__(self, *, now: int):
        self.now = _check_time(now)
        self.deleted_ids: set[str] = set()
        try:
            self.db = sqlite3.connect(":memory:")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute(
                "CREATE TABLE tasks("
                "task_id TEXT PRIMARY KEY, project TEXT NOT NULL, kind TEXT NOT NULL,"
                "title TEXT NOT NULL, ts INTEGER NOT NULL, source TEXT,"
                "revision INTEGER NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL)"
            )
            self.db.execute(
                "CREATE VIRTUAL TABLE title_fts USING fts5("
                "title, tokenize='unicode61 remove_diacritics 2')"
            )
        except sqlite3.Error as exc:
            raise IndexDenied("FTS5_NOT_AVAILABLE") from exc

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _prune(self):
        cutoff = self.now - RETENTION_DAYS * DAY
        ids = [r[0] for r in self.db.execute(
            "SELECT task_id FROM tasks WHERE ts < ?", (cutoff,)).fetchall()]
        with self.db:
            for task_id in ids:
                self._erase(task_id)
        # In this synthetic-only index expiration intentionally forbids replay.
        if len(self.deleted_ids) + len(ids) > MAX_TOMBSTONES:
            raise IndexDenied("TOMBSTONES_EXHAUSTED")
        self.deleted_ids.update(ids)

    def _erase(self, task_id: str):
        row = self.db.execute(
            "SELECT rowid FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is not None:
            self.db.execute("DELETE FROM title_fts WHERE rowid=?", (row[0],))
            self.db.execute("DELETE FROM tasks WHERE task_id=?", (task_id,))

    def upsert(self, record: dict) -> str:
        data = _validate(record, self.now)
        self._prune()
        task_id = data["task_id"]
        if task_id in self.deleted_ids:
            raise IndexDenied("REVOKED_OR_DELETED")
        row = self.db.execute(
            "SELECT revision, project, kind, title, ts, source, scope, status "
            "FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        new_fields = (data["revision"], data["project_id"], data["kind"],
                      data["title"], data["timestamp"], data["source_uri"],
                      data["scope"], data["status"])
        if row is not None:
            if data["revision"] < row[0]:
                raise IndexDenied("STALE_REVISION")
            if data["revision"] == row[0]:
                if row == new_fields:
                    return "UNCHANGED"
                raise IndexDenied("REVISION_CONFLICT")
        if row is None and self.count() >= MAX_RECORDS:
            raise IndexDenied("RECORD_CAP")
        with self.db:
            self._erase(task_id)
            cur = self.db.execute(
                "INSERT INTO tasks(task_id,project,kind,title,ts,source,revision,scope,status) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (task_id, data["project_id"], data["kind"], data["title"],
                 data["timestamp"], data["source_uri"], data["revision"],
                 data["scope"], data["status"]),
            )
            self.db.execute(
                "INSERT INTO title_fts(rowid,title) VALUES (?,?)",
                (cur.lastrowid, data["title"]))
        return "UPDATED" if row is not None else "INSERTED"

    def remove(self, task_id: str) -> bool:
        if type(task_id) is not str or not ID.fullmatch(task_id):
            raise IndexDenied("TASK_ID_DENIED")
        if task_id in self.deleted_ids:
            return False
        if len(self.deleted_ids) >= MAX_TOMBSTONES:
            raise IndexDenied("TOMBSTONES_EXHAUSTED")
        row = self.db.execute(
            "SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            return False
        with self.db:
            self._erase(task_id)
        self.deleted_ids.add(task_id)
        return True

    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM tasks").fetchone()[0]

    def search(self, query: str, *, project_id: str, kind: str | None = None,
               status: str = "verified", since: int | None = None,
               until: int | None = None, limit: int = 8) -> list[dict]:
        # A scoped synthetic demonstration, NOT a production access check.
        if type(project_id) is not str or project_id != PROJECT:
            raise IndexDenied("PROJECT_SCOPE_DENIED")
        if kind is not None and (type(kind) is not str or kind not in KINDS):
            raise IndexDenied("KIND_DENIED")
        if type(status) is not str or status not in STATUSES:
            raise IndexDenied("STATUS_INVALID")
        if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
            raise IndexDenied("RESULT_CAP")
        if since is not None:
            since = _check_time(since)
        if until is not None:
            until = _check_time(until)
        if since is not None and until is not None and since > until:
            raise IndexDenied("TIME_WINDOW_INVALID")
        if (type(query) is not str or not QUERY.fullmatch(query) or
                PRIVATE.search(query) or any(ord(c) < 32 and c not in " \t"
                                         for c in query)):
            raise IndexDenied("QUERY_DENIED")
        terms = re.findall(r"\w+", query, flags=re.UNICODE)
        if not 1 <= len(terms) <= 6 or any(len(t) > 32 for t in terms):
            raise IndexDenied("QUERY_DENIED")
        # No SQL/FTS syntax from the caller is ever spliced in.
        expression = " AND ".join('"' + t + '"' for t in terms)
        where = ["title_fts MATCH ?", "t.project=?", "t.scope=?", "t.status=?",
                 "t.ts>=?"]
        params: list[Any] = [expression, PROJECT, SCOPE, status,
                             self.now - RETENTION_DAYS * DAY]
        if kind is not None:
            where.append("t.kind=?")
            params.append(kind)
        if since is not None:
            where.append("t.ts>=?")
            params.append(since)
        if until is not None:
            where.append("t.ts<=?")
            params.append(until)
        params.append(limit)
        rows = self.db.execute(
            "SELECT t.task_id,t.project,t.kind,t.title,t.ts,t.source,t.revision,"
            "t.scope,t.status FROM title_fts JOIN tasks t ON title_fts.rowid=t.rowid "
            "WHERE " + " AND ".join(where) +
            " ORDER BY t.ts DESC, t.task_id LIMIT ?", params,
        ).fetchall()
        return [{
            "task_id": r[0], "project_id": r[1], "kind": r[2],
            "title": r[3], "timestamp": r[4], "source_uri": r[5],
            "revision": r[6], "scope": r[7], "status": r[8],
            "source_authenticated": False,
        } for r in rows]

    def limits(self) -> dict:
        # SQLite in-memory page count is NOT process RSS or peak CPU.
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        size = self.db.execute("PRAGMA page_size").fetchone()[0]
        return {
            "sqlite_main_bytes": pages * size,
            "retention_days": RETENTION_DAYS,
            "record_cap": MAX_RECORDS, "result_cap": MAX_RESULTS,
            "tombstone_cap": MAX_TOMBSTONES,
            "persistent_disk_bytes": 0, "backend": ":memory:",
        }


def sample(task_id: str, title: str, *, now: int, kind: str = "issue",
           status: str = "verified", revision: int = 1,
           source_uri: str | None = None) -> dict:
    """ONLY generate synthetic IDs from a known static test namespace."""
    if source_uri is None and status == "verified":
        n = int(task_id.rsplit("-", 1)[1])
        segment = {"issue": "issues", "pr": "pull",
                   "ci": "actions/runs", "deploy": "actions/runs"}[kind]
        source_uri = f"https://github.com/MikeMoore1337/hermes/{segment}/{9900000+n}"
    return {
        "schema_version": 1, "task_id": task_id, "project_id": PROJECT,
        "kind": kind, "title": title, "timestamp": now, "source_uri": source_uri,
        "revision": revision, "scope": SCOPE, "status": status, "revoked": False,
    }
