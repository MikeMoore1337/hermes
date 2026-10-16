"""Read-only retention planning for Ops Watch's canonical SQLite ledger.

No message text, chat ID, lease token or raw database row leaves this module.
Never delete, vacuum, checkpoint, rotate, back up or archive data automatically.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

from .core import InputError
from .delivery_contract import stats
from .state_store import DATABASE

SCHEMA = "hermes-ops-retention-audit-v1"
DEFAULT_REVIEW_ACKS = 10_000
DEFAULT_REVIEW_BYTES = 32 * 1024 * 1024
TARGET = Path("/var/lib/hermes-agent/ops-watch")


def assess(
    directory: Path, *, review_after_acks: int = DEFAULT_REVIEW_ACKS,
    review_after_bytes: int = DEFAULT_REVIEW_BYTES,
) -> dict[str, Any]:
    """Compute bounded aggregate only; even an ACK is never deleted here."""
    if (
        type(review_after_acks) is not int or not 1 <= review_after_acks <= 1_000_000
        or type(review_after_bytes) is not int
        or not 4096 <= review_after_bytes <= 1_073_741_824
    ):
        raise InputError("retention_policy_invalid")
    # stats() enforces regular file, no symlinks/hardlinks, 0600 and
    # current OS identity. It opens SQLite mode=ro and never runs DDL.
    totals = stats(directory)
    path = directory / DATABASE
    if path.is_symlink():
        raise InputError("unsafe_outbox_db")
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.geteuid()
    ):
        raise InputError("unsafe_outbox_db")
    bytes_used = info.st_size
    if bytes_used < 0:
        raise InputError("retention_storage_invalid")
    review = (
        totals["acknowledged"] >= review_after_acks
        or bytes_used >= review_after_bytes
    )
    return {
        "schema": SCHEMA,
        "status": "MANUAL_ARCHIVE_PLAN_REQUIRED" if review else "MONITOR_ONLY",
        "source": "CANONICAL_LOCAL_SQLITE_READ_ONLY",
        "event_counts": totals,
        "sqlite_file_bytes": bytes_used,
        "thresholds": {
            "acknowledged_events": review_after_acks,
            "sqlite_file_bytes": review_after_bytes,
        },
        "archive_candidate_scope": "ACKNOWLEDGED_ONLY",
        "outstanding_preservation_required": totals["unacknowledged"] > 0,
        "backup_verified": False,
        "archive_written": False,
        "events_deleted": False,
        "sqlite_modified": False,
        "telegram_sent": False,
        "production_retention_approved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ops Watch aggregate-only retention audit")
    parser.add_argument("--inspect", action="store_true",
                        help="Read bounded aggregates from the fixed Ops Watch directory")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if not args.inspect:
        print(json.dumps({"status": "NOT_EXECUTED", "events_deleted": False}))
        return 0
    try:
        result = assess(TARGET)
    except (InputError, OSError, ValueError):
        print(json.dumps({"status": "REJECTED", "reason": "storage_unavailable"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
