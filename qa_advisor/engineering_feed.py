"""Engineering Control: explicit, sanitized handoff into existing QA snapshot.

One opt-in operator action writes only a fixed status envelope, never source
PR text, lockfiles, private URLs, dependencies, tokens or action approvals.
No timer, network client or second source-of-truth database is introduced.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from qa_advisor.no_follow import open_nofollow
from qa_advisor.signal_store import DIR, _dir

SCHEMA = "hermes-engineering-inbox-v1"
FILE = "engineering-inbox.json"
MAX_BYTES = 4096
MAX_INPUT = 32768
MAX_AGE = timedelta(minutes=45)
SKEW = timedelta(minutes=2)
KINDS = {
    "release_guard": ("hermes-releaseguard-precheck-v1", frozenset({
        "BLOCKED", "INCONCLUSIVE", "READY_FOR_OWNER_REVIEW",
    })),
    "merge_control": ("hermes-mergecontrol-review-v1", frozenset({
        "REVIEW_REQUIRED", "INCONCLUSIVE", "NO_OVERLAP_IN_SUPPLIED_WINDOW",
    })),
    "deppilot": ("hermes-deppilot-plan-v1", frozenset({
        "REVIEW_REQUIRED", "INCONCLUSIVE", "NO_CHANGES_IN_SUPPLIED_CANDIDATES",
    })),
    "opensource_radar": ("hermes-ossradar-review-v1", frozenset({
        "PILOT_REVIEW", "NEEDS_REVIEW", "HOLD_FOR_REVIEW", "REJECT_RECOMMENDED",
    })),
}


class EngineeringFeedRefused(ValueError):
    """Fixed non-sensitive refusal codes."""


def _utc(value: Any) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise EngineeringFeedRefused("timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EngineeringFeedRefused("timestamp_invalid") from None
    if stamp.utcoffset() != timedelta(0):
        raise EngineeringFeedRefused("timestamp_invalid")
    return stamp.astimezone(UTC)


def _now(value: datetime | None) -> datetime:
    stamp = value if value is not None else datetime.now(UTC)
    if type(stamp) is not datetime or stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise EngineeringFeedRefused("clock_invalid")
    return stamp


def _row(key: str, report: Any, *, now: datetime) -> dict:
    if report is None:
        return {"status": "NOT_AVAILABLE", "checked_at": None, "reason_count": 0}
    if type(report) is not dict:
        raise EngineeringFeedRefused("report_invalid")
    schema, allowed = KINDS[key]
    if report.get("schema") != schema or type(report.get("status")) is not str or report["status"] not in allowed:
        raise EngineeringFeedRefused("report_invalid")
    if report.get("recommendation_only") is not True:
        raise EngineeringFeedRefused("report_authority_invalid")
    if key in ("release_guard", "merge_control", "opensource_radar"):
        if report.get("owner_approval") != "NOT_GRANTED":
            raise EngineeringFeedRefused("report_authority_invalid")
        if report.get("execution_authorized") is not False and key != "opensource_radar":
            raise EngineeringFeedRefused("report_authority_invalid")
        if key == "opensource_radar" and report.get("install_authorized") is not False:
            raise EngineeringFeedRefused("report_authority_invalid")
        if key == "release_guard" and report.get("deploy_authorized") is not False:
            raise EngineeringFeedRefused("report_authority_invalid")
        if key == "merge_control" and report.get("merge_authorized") is not False:
            raise EngineeringFeedRefused("report_authority_invalid")
    elif report.get("changes_written") is not False or report.get("production_authorized") is not False:
        raise EngineeringFeedRefused("report_authority_invalid")
    stamp = _utc(report.get("checked_at"))
    if now - stamp > MAX_AGE or stamp > now + SKEW:
        raise EngineeringFeedRefused("report_stale_or_future")
    reasons = report.get("reasons")
    if type(reasons) is not list or len(reasons) > 50 or any(type(r) is not str for r in reasons):
        raise EngineeringFeedRefused("report_reasons_invalid")
    # Never persist reason strings, URLs, SHA, paths, or untrusted metadata.
    return {"status": report["status"], "checked_at": stamp.isoformat().replace("+00:00", "Z"),
            "reason_count": len(reasons)}


def build(reports: Any, *, now: datetime | None = None) -> dict:
    instant = _now(now)
    if (type(reports) is not dict or not reports
            or not set(reports).issubset(KINDS)):
        raise EngineeringFeedRefused("report_map_invalid")
    result = {
        "schema": SCHEMA,
        "observed_at": instant.isoformat().replace("+00:00", "Z"),
        "scope": "SANITIZED_READONLY_ENGINEERING",
        "owner_approval": "NOT_GRANTED",
        "execution_authorized": False,
        "sources": {
            key: _row(key, reports.get(key), now=instant) for key in KINDS
        },
    }
    return validate(result)


def validate(value: Any) -> dict:
    if type(value) is not dict or set(value) != {
        "schema", "observed_at", "scope", "owner_approval",
        "execution_authorized", "sources",
    }:
        raise EngineeringFeedRefused("feed_shape_invalid")
    if (value["schema"] != SCHEMA
            or value["scope"] != "SANITIZED_READONLY_ENGINEERING"
            or value["owner_approval"] != "NOT_GRANTED"
            or value["execution_authorized"] is not False
            or type(value["sources"]) is not dict
            or set(value["sources"]) != set(KINDS)):
        raise EngineeringFeedRefused("feed_scope_invalid")
    observed = _utc(value["observed_at"])
    for key, item in value["sources"].items():
        if type(item) is not dict or set(item) != {"status", "checked_at", "reason_count"}:
            raise EngineeringFeedRefused("feed_entry_invalid")
        status = item["status"]
        if (type(status) is not str
                or status not in KINDS[key][1] | {"NOT_AVAILABLE"}
                or type(item["reason_count"]) is not int
                or not 0 <= item["reason_count"] <= 50):
            raise EngineeringFeedRefused("feed_entry_invalid")
        if status == "NOT_AVAILABLE":
            if item["checked_at"] is not None or item["reason_count"] != 0:
                raise EngineeringFeedRefused("feed_entry_invalid")
        else:
            checked = _utc(item["checked_at"])
            if checked > observed + SKEW or observed - checked > MAX_AGE:
                raise EngineeringFeedRefused("feed_entry_invalid")
    return value


def save(value: dict, *, directory: Path = DIR) -> str:
    valid = validate(value)
    _dir(directory)
    body = (json.dumps(valid, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")
    if len(body) > MAX_BYTES:
        raise EngineeringFeedRefused("feed_oversized")
    fd, filename = tempfile.mkstemp(prefix=".engineering-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, directory / FILE)
    finally:
        Path(filename).unlink(missing_ok=True)
    return "STORED_SANITIZED_ENGINEERING"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit report projection; no API or model calls")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args(argv)
    if args.input is None and not args.save:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        if args.input is None:
            raise EngineeringFeedRefused("input_required")
        fd = open_nofollow(args.input)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 2 <= info.st_size <= MAX_INPUT:
                raise EngineeringFeedRefused("input_unsafe")
            raw = os.read(fd, MAX_INPUT + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_INPUT:
            raise EngineeringFeedRefused("input_unsafe")
        data = json.loads(raw)
        result = build(data)
        if args.save:
            save(result)
    except EngineeringFeedRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2
    except (OSError, ValueError, UnicodeError, RecursionError):
        print(json.dumps({"status": "REFUSED", "reason": "input_unavailable_or_invalid"}))
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
