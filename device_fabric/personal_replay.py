"""Bounded, durable at-most-once IDs for the personal READ-only agent."""
from __future__ import annotations

import hashlib
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat

MAX_RECORDS = 50_000
MAX_BYTES = 32 * 1024 * 1024
REPARSE = 0x400
APPLICATION_ID = 0x48343534


class ReplayDenied(ValueError):
    """A refusal never includes a request ID or host path."""


class PersonalReplay:
    """Reserve a request before READ; a crash never makes it executable again.

    The caller must supply the already owner-protected personal state directory.
    No request payloads, tokens, file contents, or original project files are saved.
    """

    def __init__(self, directory: Path, *, create: bool = False):
        try:
            if not isinstance(directory, Path) or not directory.is_absolute() or type(create) is not bool:
                raise ValueError()
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & REPARSE):
                raise ValueError()
            self.path = directory / "read-replay.sqlite3"
            if create:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
                os.close(fd)
            self._check_file()
            with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2)) as db:
                db.execute("PRAGMA journal_mode=DELETE")
                db.execute("PRAGMA synchronous=FULL")
                if create:
                    db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    db.execute("PRAGMA user_version=1")
                    db.execute("CREATE TABLE claimed (id BLOB PRIMARY KEY) WITHOUT ROWID")
                if (db.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,)
                    or db.execute("PRAGMA user_version").fetchone() != (1,)
                    or db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",)
                    or db.execute("SELECT name,type FROM sqlite_master").fetchall() != [("claimed", "table")]
                    or db.execute("PRAGMA table_info(claimed)").fetchall() != [(0, "id", "BLOB", 1, None, 1)]):
                    raise ValueError()
                db.commit()
            self._check_file()
        except Exception:
            raise ReplayDenied("personal_replay_denied") from None

    def _check_file(self) -> None:
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & REPARSE or info.st_size > MAX_BYTES):
            raise ReplayDenied("personal_replay_denied")

    def claim(self, request_id: str) -> bool:
        try:
            if type(request_id) is not str or not 1 <= len(request_id) <= 128:
                raise ValueError()
            digest = hashlib.sha256(request_id.encode("utf-8")).digest()
            self._check_file()
            with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2, isolation_level=None)) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM claimed WHERE id=?", (digest,)).fetchone():
                    db.execute("ROLLBACK")
                    return False
                if db.execute("SELECT COUNT(*) FROM claimed").fetchone()[0] >= MAX_RECORDS:
                    raise ValueError()
                db.execute("INSERT INTO claimed(id) VALUES(?)", (digest,))
                db.execute("COMMIT")
            self._check_file()
            return True
        except Exception:
            raise ReplayDenied("personal_replay_denied") from None
