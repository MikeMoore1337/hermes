"""Research-only SQLite reservation fixture for Hermes #474 / #475.

NOT wired to Hermes native Kanban, an agent launcher, or a model provider.
This is NOT a live admission gate, durable production journal, or second queue.
A test-supplied 'grant_verified' flag is not authenticated owner approval.

Experiments demonstrate one irreversible reservation for one logical external
operation, including across retries with changed revision or approval ID.
The caller must independently enforce owner approval, allowlists, quota,
isolation, provider cancellation and authentic receipts before any model call.
"""
from __future__ import annotations

from pathlib import Path
import re
import sqlite3

OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
APPROVAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")

FIRST_ONLY = "RESERVED_FIRST_ATTEMPT_ONLY"
REPLAY_BLOCKED = "BLOCK_EXISTING_OR_UNCERTAIN"
NO_APPROVAL = "DENY_UNVERIFIED_APPROVAL"
EXPIRED = "DENY_EXPIRED_APPROVAL"


class InvalidFixture(ValueError):
    pass


def _require_id(value, pattern, name):
    if type(value) is not str or not pattern.fullmatch(value):
        raise InvalidFixture(name)
    return value


def initialize_temporary_fixture(db_path: Path) -> None:
    """Create only the explicit test database path; no Hermes DB operations."""
    if type(db_path) is not Path:
        raise InvalidFixture("path")
    with sqlite3.connect(db_path, timeout=5, isolation_level=None) as db:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("""
                CREATE TABLE IF NOT EXISTS synthetic_pre_call_reservations (
                    operation_key TEXT PRIMARY KEY NOT NULL,
                    revision TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    reserved_at INTEGER NOT NULL
                )
            """)
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise


def reserve_once(
    db_path: Path,
    *,
    operation_key: str,
    revision: str,
    approval_id: str,
    grant_verified: bool,
    grant_expires_at: int,
    now: int,
) -> str:
    """Atomically record a first-only intent, NEVER execute an external call.

    A reservation persists even if the owner approval or source revision later
    changes. A timed-out or crashed caller must NOT delete it or automatically
    retry. A missing table fails closed instead of self-initializing a journal.
    """
    if type(db_path) is not Path:
        raise InvalidFixture("path")
    _require_id(operation_key, OPERATION, "operation_key")
    _require_id(revision, REVISION, "revision")
    _require_id(approval_id, APPROVAL, "approval_id")
    if type(grant_verified) is not bool:
        raise InvalidFixture("grant_verified")
    if type(grant_expires_at) is not int or type(now) is not int:
        raise InvalidFixture("time_schema")
    if not grant_verified:
        return NO_APPROVAL
    if now >= grant_expires_at:
        return EXPIRED

    with sqlite3.connect(db_path, timeout=5, isolation_level=None) as db:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "INSERT INTO synthetic_pre_call_reservations "
                "(operation_key, revision, approval_id, reserved_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(operation_key) DO NOTHING",
                (operation_key, revision, approval_id, now),
            )
            inserted = db.execute("SELECT changes()").fetchone()[0]
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return FIRST_ONLY if inserted == 1 else REPLAY_BLOCKED


def read_record(db_path: Path, operation_key: str):
    """Independent readback; absence means 'unknown', not authorization."""
    if type(db_path) is not Path:
        raise InvalidFixture("path")
    _require_id(operation_key, OPERATION, "operation_key")
    # URI mode=ro avoids accidentally creating a new DB when evidence is gone.
    import urllib.parse
    uri = "file:" + urllib.parse.quote(str(db_path.resolve()), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        return db.execute(
            "SELECT operation_key, revision, approval_id, reserved_at "
            "FROM synthetic_pre_call_reservations WHERE operation_key=?",
            (operation_key,),
        ).fetchone()
