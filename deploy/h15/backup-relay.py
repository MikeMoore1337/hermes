#!/usr/bin/env python3
"""H-15: take an atomic SQLite online backup without stopping a live relay.

No retention deletion or auto-scheduling; operator must approve activation.
Never reads/prints OAuth tokens or SQLite content.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile


def backup_sqlite(source: Path, backup_dir: Path) -> Path:
    if not source.is_file() or source.is_symlink():
        raise ValueError("SQLite source missing or unsafe")
    if not backup_dir.is_dir() or backup_dir.is_symlink():
        raise ValueError("Backup directory missing or unsafe")
    if backup_dir.stat().st_mode & 0o077:
        raise PermissionError("Backup directory must not be group/world accessible")
    if source.resolve().parent == backup_dir.resolve():
        raise ValueError("Backup and active SQLite directory must differ")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_dir / f"relay-{timestamp}.sqlite3"
    # Existing snapshots are never overwritten; tempfile is mode 0600.
    fd, temp_name = tempfile.mkstemp(prefix=".relay-backup-", suffix=".tmp", dir=backup_dir)
    os.close(fd)
    temp = Path(temp_name)
    try:
        with sqlite3.connect(f"file:{source.absolute()}?mode=ro", uri=True, timeout=10) as live:
            with sqlite3.connect(temp, timeout=10) as snapshot:
                live.backup(snapshot, pages=100, sleep=0.1)
                ok = snapshot.execute("PRAGMA quick_check").fetchone()[0]
                if ok != "ok":
                    raise RuntimeError("SQLite snapshot quick_check failed")
        os.chmod(temp, 0o600)
        with temp.open("rb") as file:
            os.fsync(file.fileno())
        # Filename includes microseconds; refuse overwrites explicitly.
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("Backup filename collision")
        os.replace(temp, destination)
        dir_fd = os.open(backup_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return destination
    finally:
        temp.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path,
                        default=Path("/var/lib/hermes-brc-relay/relay.sqlite"))
    parser.add_argument("--backup-dir", type=Path,
                        default=Path("/var/backups/hermes-brc-relay"))
    args = parser.parse_args()
    target = backup_sqlite(args.database, args.backup_dir)
    print("H15_BRC_SQLITE_BACKUP=PASS")
    print(f"BACKUP_FILE={target}")
    print("RESTORE_TEST=NOT_PERFORMED")


if __name__ == "__main__":
    main()
