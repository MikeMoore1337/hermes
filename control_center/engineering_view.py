"""Independent root-only verifier of Engineering Control's sanitized QA feed.

Control Center deployment intentionally does not ship qa_advisor code, so the
schema is validated again at its existing privileged snapshot boundary.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import stat

FILE = Path("/var/lib/hermes-qa-watch/engineering-inbox.json")
SCHEMA = "hermes-engineering-inbox-v1"
MAX_BYTES = 4096
MAX_AGE = timedelta(minutes=45)
SKEW = timedelta(minutes=2)
KINDS = {
    "release_guard": frozenset({"BLOCKED", "INCONCLUSIVE", "READY_FOR_OWNER_REVIEW"}),
    "merge_control": frozenset({"REVIEW_REQUIRED", "INCONCLUSIVE", "NO_OVERLAP_IN_SUPPLIED_WINDOW"}),
    "deppilot": frozenset({"REVIEW_REQUIRED", "INCONCLUSIVE", "NO_CHANGES_IN_SUPPLIED_CANDIDATES"}),
    "opensource_radar": frozenset({"PILOT_REVIEW", "NEEDS_REVIEW", "HOLD_FOR_REVIEW", "REJECT_RECOMMENDED"}),
}


class EngineeringViewRefused(ValueError):
    """Constant diagnostic codes only."""


def _utc(value):
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise EngineeringViewRefused("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EngineeringViewRefused("timestamp_invalid") from None
    if parsed.utcoffset() != timedelta(0):
        raise EngineeringViewRefused("timestamp_invalid")
    return parsed.astimezone(UTC)


def validate(value):
    if type(value) is not dict or set(value) != {
        "schema", "observed_at", "scope", "owner_approval",
        "execution_authorized", "sources",
    }:
        raise EngineeringViewRefused("shape_invalid")
    if (value["schema"] != SCHEMA
            or value["scope"] != "SANITIZED_READONLY_ENGINEERING"
            or value["owner_approval"] != "NOT_GRANTED"
            or value["execution_authorized"] is not False
            or type(value["sources"]) is not dict
            or set(value["sources"]) != set(KINDS)):
        raise EngineeringViewRefused("scope_invalid")
    observed = _utc(value["observed_at"])
    for key, row in value["sources"].items():
        if type(row) is not dict or set(row) != {"status", "checked_at", "reason_count"}:
            raise EngineeringViewRefused("row_invalid")
        if (type(row["status"]) is not str
                or row["status"] not in KINDS[key] | {"NOT_AVAILABLE"}
                or type(row["reason_count"]) is not int
                or not 0 <= row["reason_count"] <= 50):
            raise EngineeringViewRefused("row_invalid")
        if row["status"] == "NOT_AVAILABLE":
            if row["checked_at"] is not None or row["reason_count"] != 0:
                raise EngineeringViewRefused("row_invalid")
        else:
            at = _utc(row["checked_at"])
            if at > observed + SKEW or observed - at > MAX_AGE:
                raise EngineeringViewRefused("row_time_invalid")
    return value


def load(path: Path = FILE):
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise EngineeringViewRefused("directory_unsafe")
    parent_info = parent.stat()
    if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise EngineeringViewRefused("directory_unsafe")
    if path.is_symlink():
        raise EngineeringViewRefused("file_unsafe")
    if not path.exists():
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or not 2 <= info.st_size <= MAX_BYTES):
                raise EngineeringViewRefused("file_unsafe")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise EngineeringViewRefused("file_unsafe")
        return validate(json.loads(raw))
    except EngineeringViewRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise EngineeringViewRefused("feed_unavailable") from None


def fresh(value, *, now: datetime):
    try:
        if type(now) is not datetime or now.tzinfo is None:
            return False
        data = validate(value)
        clock = now.astimezone(UTC)
        observed = _utc(data["observed_at"])
        if not -SKEW <= clock - observed <= MAX_AGE:
            return False
        return all(
            item["checked_at"] is None
            or -SKEW <= clock - _utc(item["checked_at"]) <= MAX_AGE
            for item in data["sources"].values()
        )
    except (EngineeringViewRefused, ValueError, AttributeError, TypeError):
        return False
