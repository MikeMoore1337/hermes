"""H454: persistent fail-closed effect-replay ledger for a future Win32 agent.

This library DOES NOT grant access, validate owner permissions, connect to
a relay, run commands or modify original source files. Only a caller that
has INDEPENDENTLY verified a one-use owner-issued authorization may reserve
an effect. Never accept ChatGPT/MCP fields as proof of that authorization.

Reserved IDs are never reused even after process failure or Windows reboot.
There is deliberately no delete, expiry cleanup, requeue, or auto-retry API.
The state directory must already be owner-provisioned with restricted OS ACLs.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

SCHEMA = "h454-native-effect-ledger-v1"
MAX_RECORDS = 50000
MAX_DB_BYTES = 32 * 1024 * 1024
DEVICE = "h454-win-01335a1f6e6705b4"
PROJECTS = frozenset({
    "hermes", "your-fitness-coach", "ai-development-toolkit", "second-brain",
})
OPERATIONS = frozenset({"file_write", "file_edit", "file_delete", "process_run"})
ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


class LedgerDenied(Exception):
    """Controlled denial; never include SQLite messages or private paths."""


@dataclass(frozen=True, slots=True)
class EffectIdentity:
    """An operation ID and SHA256 scope hash, not an authorization token."""

    operation_id: str
    device_id: str
    project: str
    operation: str
    scope_sha256: str
    expires_at: int


def validate(identity: EffectIdentity, *, now: int) -> None:
    if (type(identity) is not EffectIdentity
        or type(identity.operation_id) is not str
        or ID.fullmatch(identity.operation_id) is None
        or identity.device_id != DEVICE
        or identity.project not in PROJECTS
        or identity.operation not in OPERATIONS
        or type(identity.scope_sha256) is not str
        or HASH.fullmatch(identity.scope_sha256) is None
        or type(identity.expires_at) is not int
        or type(now) is not int
        or identity.expires_at < now
        or identity.expires_at > now + 600):
        raise LedgerDenied("effect_identity_denied")


def _check_state_dir(directory: Path) -> None:
    if (not directory.is_absolute()
        or directory.is_symlink()
        or (hasattr(directory, "is_junction") and directory.is_junction())):
        raise LedgerDenied("state_dir_not_trusted")
    try:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise LedgerDenied("state_dir_not_trusted")
    except OSError as exc:
        raise LedgerDenied("state_dir_not_trusted") from exc


def _check_db(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LedgerDenied("ledger_unavailable") from exc
    if (path.is_symlink()
        or (hasattr(path, "is_junction") and path.is_junction())
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > MAX_DB_BYTES):
        raise LedgerDenied("unsafe_ledger_file")


def _connect(directory: Path) -> sqlite3.Connection:
    _check_state_dir(directory)
    path = directory / "native-effects.sqlite3"
    _check_db(path)
    try:
        connection = sqlite3.connect(path, timeout=2.0, isolation_level=None)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=2000")
        connection.execute("CREATE TABLE IF NOT EXISTS effects ("
                           "operation_id TEXT PRIMARY KEY,"
                           "device_id TEXT NOT NULL,"
                           "project TEXT NOT NULL,"
                           "operation TEXT NOT NULL,"
                           "scope_sha256 TEXT NOT NULL,"
                           "expires_at INTEGER NOT NULL,"
                           "state TEXT NOT NULL CHECK(state IN ('reserved','completed','failed')))")
        # SQLite writes only IDs and hashes; never host commands, arguments,
        # file paths, file content, process output, bearer or tokens.
        _check_db(path)
        return connection
    except (sqlite3.Error, OSError, LedgerDenied) as exc:
        if "connection" in locals():
            connection.close()
        raise LedgerDenied("ledger_unavailable") from exc


def claim(directory: Path, identity: EffectIdentity, *,
          now: int | None = None) -> str:
    """Durably reserve once *before* any possible effect, or refuse.

    Return RESERVED_ONCE only on the first successful atomic reservation.
    All subsequent requests for that identifier return ALREADY_RESERVED,
    regardless of scope, completion, restart, expired grant or transport.
    Returns no capability to execute anything; the caller must independently
    verify its signed/owner-issued grant AND OS ACLs, not trust this method.
    """
    timestamp = int(time.time()) if now is None else now
    validate(identity, now=timestamp)
    connection = _connect(directory)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT operation_id FROM effects WHERE operation_id=?",
            (identity.operation_id,)
        ).fetchone()
        if existing is not None:
            connection.execute("COMMIT")
            return "ALREADY_RESERVED"
        count = connection.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        if count >= MAX_RECORDS:
            raise LedgerDenied("receipt_capacity_exhausted")
        connection.execute(
            "INSERT INTO effects VALUES (?,?,?,?,?,?,?)",
            (identity.operation_id, identity.device_id, identity.project,
             identity.operation, identity.scope_sha256, identity.expires_at,
             "reserved")
        )
        connection.execute("COMMIT")
        return "RESERVED_ONCE"
    except LedgerDenied:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, OSError) as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise LedgerDenied("ledger_unavailable") from exc
    finally:
        connection.close()


def complete(directory: Path, identity: EffectIdentity,
             *, success: bool) -> str:
    """Mark result without ever enabling re-execution.

    A failed operation remains consumed; a transaction ambiguity may have
    already caused an effect before a connection failure. Manual inspection
    and a fresh grant + different operation ID are required to retry.
    """
    if type(success) is not bool:
        raise LedgerDenied("invalid_completion")
    # A completed operation may be older than the original grant TTL, but
    # its canonical identity fields must still be fully validated.
    validate(identity, now=identity.expires_at - 600)
    connection = _connect(directory)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT device_id,project,operation,scope_sha256,expires_at,state "
            "FROM effects WHERE operation_id=?", (identity.operation_id,)
        ).fetchone()
        expected = (identity.device_id, identity.project, identity.operation,
                    identity.scope_sha256, identity.expires_at, "reserved")
        if row != expected:
            raise LedgerDenied("receipt_identity_or_state_mismatch")
        connection.execute(
            "UPDATE effects SET state=? WHERE operation_id=? AND state='reserved'",
            ("completed" if success else "failed", identity.operation_id)
        )
        connection.execute("COMMIT")
        return "RECORDED"
    except LedgerDenied:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, OSError) as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise LedgerDenied("ledger_unavailable") from exc
    finally:
        connection.close()


def inspect(directory: Path, operation_id: str) -> str:
    """Only bounded receipt status; never return operation scope or secrets."""
    if type(operation_id) is not str or ID.fullmatch(operation_id) is None:
        raise LedgerDenied("invalid_operation_id")
    connection = _connect(directory)
    try:
        record = connection.execute(
            "SELECT state FROM effects WHERE operation_id=?", (operation_id,)
        ).fetchone()
        return record[0] if record is not None else "unknown"
    except (sqlite3.Error, OSError) as exc:
        raise LedgerDenied("ledger_unavailable") from exc
    finally:
        connection.close()
