"""#272: inspect event *shapes* of one already-delivered, SHA256-bound Codex artifact.

Never logs event bodies, type values outside a fixed whitelist, item text, IDs,
paths, model payloads, authentication, or tool arguments. Never calls Codex.
The output is only a diagnostic; it cannot establish actual token usage.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from scripts.h271_post_canary_readonly import verify_artifact
from scripts.h272_exec_usage_readonly import (
    ARTIFACTS, DB, MAX_ARTIFACT, UsageHold, _job,
)

# Only fixed counters are emitted, not arbitrary untrusted strings.
EVENT_TYPES = (
    "thread.started", "turn.started", "turn.completed", "turn.failed",
    "item.started", "item.updated", "item.completed", "error",
)
ITEM_TYPES = (
    "agent_message", "reasoning", "command_execution", "file_change",
    "mcp_tool_call", "web_search",
)
MAX_EVENTS = 128


def _read_bound_artifact(db: Path, artifacts: Path) -> bytes:
    row = _job(db)
    jid, ref = row["job_id"], row["result_ref"]
    try:
        verify_artifact(jid, ref, artifacts)
    except (ValueError, OSError, AttributeError, TypeError):
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED") from None
    match = re.fullmatch(
        r"artifact:[a-zA-Z0-9-]{1,64}:([a-f0-9]{64})", ref
    )
    if match is None:
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED")
    path = artifacts / (jid + "-" + match.group(1) + ".jsonl")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 <= info.st_size <= MAX_ARTIFACT):
                raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_ARTIFACT + 1)
        finally:
            os.close(fd)
    except OSError:
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED") from None
    if (len(raw) > MAX_ARTIFACT
            or hashlib.sha256(raw).hexdigest() != match.group(1)):
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED")
    return raw


def classify(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_ARTIFACT:
        raise UsageHold("ARTIFACT_TOO_LARGE")
    event_counts = {key: 0 for key in EVENT_TYPES}
    item_counts = {key: 0 for key in ITEM_TYPES}
    other_events, other_items, with_usage = 0, 0, 0
    last = "NONE"
    record_count = 0
    for record in raw.splitlines():
        record_count += 1
        if record_count > MAX_EVENTS:
            raise UsageHold("EVENT_COUNT_LIMIT")
        try:
            entry = json.loads(record)
        except (ValueError, UnicodeDecodeError):
            raise UsageHold("EVENT_JSON_INVALID") from None
        if type(entry) is not dict:
            raise UsageHold("EVENT_JSON_INVALID")
        kind = entry.get("type")
        # Unknown event labels, even malicious strings, are never reflected.
        if type(kind) is not str or kind not in event_counts:
            last = "OTHER"
            other_events += 1
            continue
        event_counts[kind] += 1
        last = kind
        if kind == "turn.completed" and type(entry.get("usage")) is dict:
            with_usage += 1
        if kind == "item.completed":
            item = entry.get("item")
            item_type = item.get("type") if type(item) is dict else None
            if type(item_type) is str and item_type in item_counts:
                item_counts[item_type] += 1
            else:
                other_items += 1
    if record_count == 0:
        result = "EMPTY"
    elif event_counts["turn.completed"] == 0:
        result = "NO_TURN_COMPLETED_EVENT"
    elif with_usage == 0:
        result = "TURN_COMPLETED_NO_USAGE_MAP"
    else:
        result = "TURN_COMPLETED_USAGE_MAP_PRESENT_UNVERIFIED"
    return {
        "classification": result,
        "artifact_bytes": len(raw),
        "records": record_count,
        "events": event_counts,
        "other_events": other_events,
        "items": item_counts,
        "other_completed_items": other_items,
        "completed_usage_maps": with_usage,
        "last_event_class": last,
    }


def read_shape(*, db: Path = DB, artifacts: Path = ARTIFACTS) -> dict[str, object]:
    return classify(_read_bound_artifact(db, artifacts))


def main() -> int:
    if os.geteuid() != 0 or os.uname().nodename.split(".")[0] != "vps1777112993":
        print("H272_ARTIFACT_SHAPE=HOLD_OWNER_HOST_REQUIRED")
        return 2
    try:
        result = read_shape()
    except UsageHold as exc:
        print("H272_ARTIFACT_SHAPE=HOLD_" + str(exc))
        return 2
    finally:
        print("RAW_CONTENT_PRINTED=NO")
        print("SESSION_CONTENT_READ=NO")
        print("CREDENTIALS_READ=NO")
        print("JOB_IDENTIFIERS_PRINTED=NO")
        print("SCHEDULER_MUTATION=NO")
        print("MODEL_CALLS_ADDED=0")
        print("ANALYTICS_TIMER_ACTIVATION=HOLD_SEPARATE_OWNER_GATE")
    print("H272_ARTIFACT_SHAPE=METADATA_PASS")
    print("CLASSIFICATION=" + str(result["classification"]))
    print("ARTIFACT_BYTES=" + str(result["artifact_bytes"]))
    print("EVENT_RECORDS=" + str(result["records"]))
    for kind, count in result["events"].items():
        print("EVENT_" + kind.replace(".", "_").upper() + "=" + str(count))
    print("EVENT_OTHER=" + str(result["other_events"]))
    for kind, count in result["items"].items():
        print("ITEM_" + kind.upper() + "=" + str(count))
    print("ITEM_OTHER_COMPLETED=" + str(result["other_completed_items"]))
    print("COMPLETED_USAGE_MAPS=" + str(result["completed_usage_maps"]))
    print("LAST_EVENT_CLASS=" + str(result["last_event_class"]).replace(".", "_").upper())
    print("ACTUAL_TOKEN_USAGE=NOT_VERIFIED")
    print("ACTUAL_SPEND_USD=UNKNOWN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
