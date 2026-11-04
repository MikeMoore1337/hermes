#!/usr/bin/env python3
"""Read-only credential-regression gate for two DISPOSABLE SQLite copies.

This script cannot authorize or perform a production restore. It refuses any
snapshot that would reintroduce a previously revoked/changed credential. An
unchanged credential set does NOT establish database binary compatibility.
Never point it at the running relay database; use independent SQLite backups.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat


class CredentialRegressionDenied(Exception):
    """Machine-readable, sanitized failure; never includes a credential."""


# Strict source-to-current equality for retained identities. The snapshot may
# omit newer grants (availability risk); it may NOT restore any older grant.
IDENTITY_FIELDS = {
    "users": ("id", "username", "password_hash"),
    "oauth_clients": ("client_id", "client_secret", "metadata"),
    "auth_codes": ("code", "client_id", "user_id", "code_challenge",
                   "redirect_uri", "scopes", "resource", "expires_at"),
    "tokens": ("token_hash", "kind", "client_id", "user_id", "scopes",
               "resource", "expires_at", "revoked"),
    "devices": ("device_id", "user_id", "token_hash", "paused"),
    "device_codes": ("device_code", "user_id", "approved", "denied",
                     "device_id", "expires_at"),
    "api_keys": ("key_hash", "user_id", "revoked"),
}
REQUIRED = frozenset(IDENTITY_FIELDS) - {"api_keys"}
MAX_BYTES = 2 * 1024 ** 3


def _secure_file(path: Path, root: Path) -> tuple[int, int, int]:
    if path.parent != root or path.is_symlink():
        raise CredentialRegressionDenied("UNSAFE_COPY_PATH")
    try:
        meta = path.lstat()
    except OSError as exc:
        raise CredentialRegressionDenied("COPY_UNAVAILABLE") from exc
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
        raise CredentialRegressionDenied("UNSAFE_COPY_TYPE")
    if meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise CredentialRegressionDenied("UNSAFE_COPY_PERMISSIONS")
    if not 1024 <= meta.st_size <= MAX_BYTES:
        raise CredentialRegressionDenied("UNEXPECTED_COPY_SIZE")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise CredentialRegressionDenied("UNSAFE_COPY_SIDECAR")
    return meta.st_dev, meta.st_ino, meta.st_mtime_ns


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _state(conn: sqlite3.Connection) -> dict[str, dict[object, tuple]]:
    if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise CredentialRegressionDenied("SQLITE_INTEGRITY_FAILED")
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if not REQUIRED.issubset(tables):
        raise CredentialRegressionDenied("AUTH_SCHEMA_INCOMPATIBLE")
    result: dict[str, dict[object, tuple]] = {}
    for name, fields in IDENTITY_FIELDS.items():
        if name not in tables:
            continue
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({name})")}
        if not set(fields).issubset(cols):
            raise CredentialRegressionDenied("AUTH_SCHEMA_INCOMPATIBLE")
        rows = conn.execute(f"SELECT {','.join(fields)} FROM {name}").fetchall()
        if len({r[0] for r in rows}) != len(rows):
            raise CredentialRegressionDenied("AUTH_SCHEMA_INCOMPATIBLE")
        result[name] = {r[0]: r[1:] for r in rows}
    return result


def _schema_contract(conn: sqlite3.Connection) -> tuple:
    """Compare all explicit schema objects, including non-auth tables.

    Schema equality is necessary for binary rollback compatibility but cannot
    prove that either old or new Node runtime understands all stored values.
    """
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'view', 'trigger') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 4097"
    ).fetchall()
    if len(rows) > 4096:
        raise CredentialRegressionDenied("UNEXPECTED_SCHEMA_SIZE")
    return (
        tuple(rows),
        conn.execute("PRAGMA user_version").fetchone()[0],
        conn.execute("PRAGMA application_id").fetchone()[0],
    )


def compare_disposable_copies(snapshot_copy: Path, current_copy: Path) -> str:
    if os.name != "posix":
        raise CredentialRegressionDenied("POSIX_OFFLINE_COPIES_REQUIRED")
    snapshot_copy, current_copy = Path(snapshot_copy), Path(current_copy)
    root = snapshot_copy.parent
    if (root.is_symlink() or not root.is_dir() or
            root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077 or
            current_copy.parent != root or snapshot_copy == current_copy):
        raise CredentialRegressionDenied("PRIVATE_DISPOSABLE_DIRECTORY_REQUIRED")
    before = []
    for p in (snapshot_copy, current_copy):
        before.append((_secure_file(p, root), _sha256(p)))
    try:
        with closing(sqlite3.connect(snapshot_copy.absolute().as_uri() + "?mode=ro&immutable=1", uri=True)) as a, \
             closing(sqlite3.connect(current_copy.absolute().as_uri() + "?mode=ro&immutable=1", uri=True)) as b:
            a.execute("PRAGMA query_only=ON")
            b.execute("PRAGMA query_only=ON")
            saved, current = _state(a), _state(b)
            saved_schema, current_schema = _schema_contract(a), _schema_contract(b)
    except sqlite3.DatabaseError as exc:
        raise CredentialRegressionDenied("SQLITE_READ_REFUSED") from exc
    if saved.keys() != current.keys() or saved_schema != current_schema:
        raise CredentialRegressionDenied("AUTH_SCHEMA_CHANGED")
    for name, identities in saved.items():
        for key, old_fields in identities.items():
            if key not in current[name] or current[name][key] != old_fields:
                raise CredentialRegressionDenied("STALE_SECURITY_STATE")
    for p, (identity, digest) in zip((snapshot_copy, current_copy), before):
        if _secure_file(p, root) != identity or _sha256(p) != digest:
            raise CredentialRegressionDenied("COPY_CHANGED_DURING_CHECK")
    return "PASS_READ_ONLY_NO_CREDENTIAL_REINTRODUCTION"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-copy", type=Path, required=True)
    parser.add_argument("--current-copy", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_disposable_copies(args.snapshot_copy, args.current_copy)
    except (CredentialRegressionDenied, OSError, ValueError):
        print("H15_STALE_RESTORE_GUARD=REFUSED_OR_INCONCLUSIVE")
        print("H15_PRODUCTION_RESTORE=NOT_AUTHORIZED")
        return 2
    print("H15_STALE_RESTORE_GUARD=" + result)
    print("H15_PRODUCTION_RESTORE=NOT_AUTHORIZED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
