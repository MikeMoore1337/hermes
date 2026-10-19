#!/usr/bin/env python3
"""H-15: read-only restore rehearsal of an already-created relay SQLite backup.

This NEVER writes to the live relay state. Only a new disposable copy inside
a secure scratch directory is opened writable, then deleted. No secret values,
table names, user records or path names are printed on success or failure.
This is not authorization to start a resident relay or enable public MCP.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile


class RestoreRehearsalDenied(ValueError):
    pass


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _secure_dir(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise RestoreRehearsalDenied("insecure_directory")
    metadata = directory.stat()
    if (metadata.st_uid != os.geteuid()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o077):
        raise RestoreRehearsalDenied("insecure_directory_owner_or_mode")


def _validate_sqlite(connection: sqlite3.Connection) -> tuple[int, int, int]:
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise RestoreRehearsalDenied("integrity_check_failed")
    table_count = connection.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchone()[0]
    if not 1 <= table_count <= 2000:
        raise RestoreRehearsalDenied("unexpected_database_schema")
    return (
        table_count,
        connection.execute("PRAGMA user_version").fetchone()[0],
        connection.execute("PRAGMA page_count").fetchone()[0],
    )


def rehearse_restore(snapshot: Path, scratch_root: Path) -> dict[str, object]:
    _secure_dir(snapshot.parent)
    _secure_dir(scratch_root)
    if snapshot.parent.resolve() == scratch_root.resolve():
        raise RestoreRehearsalDenied("scratch_must_be_separate_from_backup")
    if snapshot.is_symlink() or not snapshot.is_file():
        raise RestoreRehearsalDenied("unsafe_snapshot_file")
    metadata = snapshot.stat()
    if (not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or not 4096 <= metadata.st_size <= 2 * 1024 ** 3):
        raise RestoreRehearsalDenied("unsafe_snapshot_owner_or_size")
    # An atomic SQLite online backup should be self-contained. Ignore neither
    # stray WAL files nor old SHM files: they are a recovery ambiguity.
    if any(Path(str(snapshot) + suffix).exists()
           or Path(str(snapshot) + suffix).is_symlink()
           for suffix in ("-wal", "-shm")):
        raise RestoreRehearsalDenied("unexpected_snapshot_sidecar")
    with snapshot.open("rb") as handle:
        if handle.read(16) != b"SQLite format 3\x00":
            raise RestoreRehearsalDenied("invalid_sqlite_header")
    before = _digest(snapshot)
    with tempfile.TemporaryDirectory(prefix="h15-disposable-restore-", dir=scratch_root) as temp:
        restored = Path(temp) / "relay-restored.sqlite"
        # immutable=1 guarantees no WAL sidecar creation or writes to
        # the protected source; the snapshot itself is never altered.
        with sqlite3.connect(snapshot.resolve().as_uri() + "?mode=ro&immutable=1",
                             uri=True, timeout=10) as source:
            original_schema = _validate_sqlite(source)
            with sqlite3.connect(restored, timeout=10) as destination:
                source.backup(destination, pages=100, sleep=0.1)
                restored_schema = _validate_sqlite(destination)
        if original_schema != restored_schema:
            raise RestoreRehearsalDenied("schema_or_page_count_mismatch")
        os.chmod(restored, 0o600)
        # A newly opened connection must see the restored durable data.
        with sqlite3.connect(restored.resolve().as_uri() + "?mode=ro&immutable=1",
                             uri=True, timeout=10) as reopened:
            if _validate_sqlite(reopened) != original_schema:
                raise RestoreRehearsalDenied("reopen_integrity_mismatch")
        if _digest(snapshot) != before:
            raise RestoreRehearsalDenied("source_changed_during_rehearsal")
    return {
        "status": "PASS_DISPOSABLE_ONLY",
        "snapshot_sha256": before,
        "tables_checked": original_schema[0],
        "live_sqlite_modified": False,
        "restored_into_production": False,
        "oauth_or_mcp_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--scratch-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = rehearse_restore(args.snapshot, args.scratch_dir)
    except (RestoreRehearsalDenied, OSError, sqlite3.DatabaseError, RuntimeError):
        print("H15_SQLITE_RESTORE_REHEARSAL=REFUSED_OR_INCONCLUSIVE")
        print("H15_SQLITE_PRODUCTION_RESTORE=NO")
        return 2
    print("H15_SQLITE_RESTORE_REHEARSAL=" + result["status"])
    print("H15_SQLITE_SNAPSHOT_SHA256=" + result["snapshot_sha256"])
    print("H15_SQLITE_PRODUCTION_RESTORE=NO")
    print("H15_REMOTE_MCP_ACTIVATION=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
