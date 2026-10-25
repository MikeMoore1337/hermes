#!/usr/bin/env python3
"""#272 read-only Codex session source preflight, run as hermes-codex.

Reads directory entries and inode metadata only. Never opens rollout contents,
SQLite, auth.json, or a Codex process; never creates any file or directory.
A successful scan is NOT authorization to start a new analytics service.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import stat

from control_center.codex_analytics import MAX_FILE_BYTES, SESSION

HOME = Path("/var/lib/hermes-codex-usage/auth")
USERNAME = "hermes-codex"
MAX_FILES = 3000
MAX_ENTRIES_PER_DIR = 3500
YEAR = re.compile(r"\d{4}\Z")
MONTH = re.compile(r"(?:0[1-9]|1[0-2])\Z")
DAY = re.compile(r"(?:0[1-9]|[12]\d|3[01])\Z")


class PreflightHold(Exception):
    """The message is a constant safe reason code, never an OS exception."""


def _directory(path: Path, *, missing_reason="SOURCE_DIRECTORY_UNAVAILABLE") -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise PreflightHold(missing_reason) from None
    except OSError:
        raise PreflightHold("SOURCE_DIRECTORY_UNAVAILABLE") from None
    if not stat.S_ISDIR(info.st_mode):
        raise PreflightHold("SOURCE_DIRECTORY_NOT_REAL")


def _entries(path: Path):
    """Enumerate at most the agreed bound, without returning names to caller logs."""
    try:
        with os.scandir(path) as stream:
            entries = []
            for entry in stream:
                entries.append(entry)
                if len(entries) > MAX_ENTRIES_PER_DIR:
                    raise PreflightHold("SOURCE_ENTRY_LIMIT")
            return entries
    except OSError:
        raise PreflightHold("SOURCE_DIRECTORY_DENIED") from None


def inspect_source(home: Path, *, expected_uid: int) -> dict[str, int]:
    """Perform non-content source inventory under the intended collector uid.

    The POSIX access check runs as the actual collector; it cannot replace an
    installed systemd sandbox/ACL check and cannot establish the JSONL schema.
    """
    if os.geteuid() != expected_uid:
        raise PreflightHold("COLLECTOR_IDENTITY_MISMATCH")
    _directory(home)
    sessions = home / "sessions"
    _directory(sessions, missing_reason="SESSIONS_DIRECTORY_MISSING")
    if not os.access(sessions, os.R_OK | os.X_OK):
        raise PreflightHold("SESSIONS_NOT_READABLE")
    files = 0
    total_bytes = 0
    for year in _entries(sessions):
        if not YEAR.fullmatch(year.name):
            continue
        _directory(Path(year.path))
        for month in _entries(Path(year.path)):
            if not MONTH.fullmatch(month.name):
                continue
            _directory(Path(month.path))
            for day in _entries(Path(month.path)):
                if not DAY.fullmatch(day.name):
                    continue
                _directory(Path(day.path))
                for candidate in _entries(Path(day.path)):
                    if not candidate.name.startswith("rollout-"):
                        continue
                    if SESSION.search(candidate.name) is None:
                        raise PreflightHold("ROLLOUT_NAME_UNRECOGNIZED")
                    try:
                        info = candidate.stat(follow_symlinks=False)
                    except OSError:
                        raise PreflightHold("ROLLOUT_METADATA_DENIED") from None
                    if not stat.S_ISREG(info.st_mode):
                        raise PreflightHold("ROLLOUT_NOT_REGULAR_FILE")
                    if info.st_uid != expected_uid:
                        raise PreflightHold("ROLLOUT_OWNER_MISMATCH")
                    if info.st_size > MAX_FILE_BYTES or info.st_size < 0:
                        raise PreflightHold("ROLLOUT_SIZE_LIMIT")
                    if not os.access(candidate.path, os.R_OK):
                        raise PreflightHold("ROLLOUT_NOT_READABLE")
                    files += 1
                    total_bytes += info.st_size
                    if files > MAX_FILES:
                        raise PreflightHold("ROLLOUT_COUNT_LIMIT")
    if files == 0:
        raise PreflightHold("NO_ROLLOUT_FILES")
    return {"rollout_files": files, "total_bytes": total_bytes}


def main() -> int:
    try:
        uid = pwd.getpwnam(USERNAME).pw_uid
        snapshot = inspect_source(HOME, expected_uid=uid)
    except KeyError:
        print("H272_READONLY_PREFLIGHT=HOLD_COLLECTOR_USER_ABSENT")
        return 2
    except PreflightHold as error:
        print("H272_READONLY_PREFLIGHT=HOLD_" + str(error))
        return 2
    finally:
        print("SESSION_CONTENT_READ=NO")
        print("SESSION_SCHEMA=NOT_VERIFIED")
        print("CODEX_CLI_VERSION=NOT_VERIFIED")
        print("ANALYTICS_TIMER_ACTIVATION=HOLD_SEPARATE_OWNER_GATE")
        print("CHANGES_PERFORMED=NO")
        print("MODEL_CALLS_ADDED=0")
    print("ROLLOUT_FILES=" + str(snapshot["rollout_files"]))
    print("ROLLOUT_BYTES=" + str(snapshot["total_bytes"]))
    print("H272_READONLY_PREFLIGHT=METADATA_PASS_RUNTIME_NOT_APPROVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
