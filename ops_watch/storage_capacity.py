"""Manual read-only capacity diagnostic for Ops Watch SQLite.

Only filesystem metadata is inspected. No SQL, updates, secrets or Telegram.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

from .state_store import DATABASE

DIRECTORY = Path("/var/lib/hermes-agent/ops-watch")
MAX_DB_BYTES = 128 * 1024 * 1024
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024


class StorageAuditDenied(ValueError):
    """Untrusted metadata cannot prove healthy storage."""


def inspect_capacity(directory: Path) -> dict[str, Any]:
    """Inspect only ownership, size and capacity; never open the DB."""
    if not isinstance(directory, Path):
        raise StorageAuditDenied("invalid_directory")
    try:
        root = directory.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(root.st_mode)
                or stat.S_IMODE(root.st_mode) != 0o700
                or root.st_uid != os.geteuid()):
            raise StorageAuditDenied("unsafe_directory")
        db = (directory / DATABASE).stat(follow_symlinks=False)
        if (not stat.S_ISREG(db.st_mode)
                or stat.S_IMODE(db.st_mode) != 0o600
                or db.st_uid != os.geteuid()
                or db.st_nlink != 1 or db.st_size < 0):
            raise StorageAuditDenied("unsafe_database")
        fs = os.statvfs(directory)
    except OSError as exc:
        raise StorageAuditDenied("storage_metadata_unavailable") from exc

    if (fs.f_frsize <= 0 or fs.f_blocks <= 0
            or fs.f_bavail < 0 or fs.f_bavail > fs.f_blocks):
        raise StorageAuditDenied("invalid_filesystem_metrics")
    total_bytes = fs.f_frsize * fs.f_blocks
    free_bytes = fs.f_frsize * fs.f_bavail
    free_limit = max(MIN_FREE_BYTES, total_bytes // 10)
    reasons: list[str] = []
    if db.st_size >= MAX_DB_BYTES:
        reasons.append("sqlite_history_large")
    if free_bytes <= free_limit:
        reasons.append("filesystem_space_low")
    return {
        "status": "REVIEW" if reasons else "OK",
        "reasons": reasons,
        "database_bytes": db.st_size,
        "filesystem_available_bytes": free_bytes,
        "filesystem_total_bytes": total_bytes,
        "database_review_threshold_bytes": MAX_DB_BYTES,
        "filesystem_review_threshold_bytes": free_limit,
        "remediation_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manual read-only Ops Watch capacity check")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = inspect_capacity(DIRECTORY)
    except StorageAuditDenied:
        print(json.dumps({"status": "UNKNOWN", "reason": "storage_evidence_unavailable",
                          "remediation_performed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "REVIEW" else 0


if __name__ == "__main__":
    raise SystemExit(main())
