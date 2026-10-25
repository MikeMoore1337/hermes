"""#272: bounded, read-only metadata proof from a previously approved Codex canary.

Source is #271's successful, delivered, SHA-256-bound codex exec --json
artifact. Never launches Codex, reads auth/session files, mutates SQLite,
or exports prompts, item text, tool arguments, or an opaque identifier.
One turn is required: upstream has reported cumulative usage on resumed turns,
so multiple turn.completed values must NOT be summed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from scripts.h271_post_canary_readonly import verify_artifact

DB = Path("/var/lib/hermes-codex-scheduler/jobs.sqlite3")
ARTIFACTS = Path("/var/lib/hermes-codex-scheduler/artifacts")
MAX_ARTIFACT = 8192
MAX_TOKENS = 10**12
SAFE_MODEL = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class UsageHold(ValueError):
    """Safe code only. Never interpolate private file contents."""


def _job(db: Path):
    if db.is_symlink() or db.parent.is_symlink() or not db.is_file():
        raise UsageHold("SCHEDULER_DATABASE_UNAVAILABLE")
    try:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=2) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            row = conn.execute(
                """SELECT job_id,status,attempt_count,invocation_state,
                          last_error_code,result_ref,delivered,model,started,finished
                   FROM jobs WHERE status='succeeded' AND delivered IS NOT NULL
                   ORDER BY finished DESC LIMIT 1"""
            ).fetchone()
    except (OSError, sqlite3.Error):
        raise UsageHold("SCHEDULER_DATABASE_UNAVAILABLE") from None
    if row is None:
        raise UsageHold("NO_DELIVERED_SUCCESS")
    if (row["status"] != "succeeded" or row["attempt_count"] != 1
            or row["invocation_state"] != "finished" or row["last_error_code"] is not None
            or row["delivered"] is None):
        raise UsageHold("SUCCESS_INVARIANT_FAILED")
    return row


def _count(value):
    if type(value) is not int or not 0 <= value <= MAX_TOKENS:
        raise UsageHold("USAGE_FIELDS_INVALID")
    return value


def _read_usage(path: Path):
    try:
        if path.is_symlink() or not path.is_file():
            raise UsageHold("ARTIFACT_UNAVAILABLE")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_ARTIFACT:
            raise UsageHold("ARTIFACT_UNAVAILABLE")
        raw = path.read_bytes()
    except OSError:
        raise UsageHold("ARTIFACT_UNAVAILABLE") from None
    if len(raw) > MAX_ARTIFACT:
        raise UsageHold("ARTIFACT_UNAVAILABLE")
    found = []
    failed = False
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            raise UsageHold("EVENT_JSON_INVALID") from None
        if type(event) is not dict:
            raise UsageHold("EVENT_JSON_INVALID")
        kind = event.get("type")
        if kind in ("error", "turn.failed"):
            failed = True
        if kind == "item.completed" and type(event.get("item")) is dict:
            if event["item"].get("type") == "error":
                failed = True
        if kind == "turn.completed":
            found.append(event.get("usage"))
    if failed:
        raise UsageHold("STREAM_HAS_ERROR")
    if not found:
        raise UsageHold("NO_COMPLETED_TURN_USAGE")
    if len(found) != 1:
        raise UsageHold("MULTI_TURN_USAGE_AMBIGUOUS")
    values = found[0]
    if type(values) is not dict:
        raise UsageHold("USAGE_FIELDS_INVALID")
    inp = _count(values.get("input_tokens"))
    cached = _count(values.get("cached_input_tokens"))
    out = _count(values.get("output_tokens"))
    if cached > inp:
        raise UsageHold("USAGE_FIELDS_INVALID")
    reasoning = values.get("reasoning_output_tokens")
    if reasoning is not None:
        reasoning = _count(reasoning)
        if reasoning > out:
            raise UsageHold("USAGE_FIELDS_INVALID")
    return {"input": inp, "cached_input": cached, "output": out,
            "reasoning_output": reasoning}


def read_one(*, db: Path = DB, artifacts: Path = ARTIFACTS) -> dict:
    """Return only non-sensitive metadata from a SHA-verified result."""
    row = _job(db)
    job_id = row["job_id"]
    result_ref = row["result_ref"]
    try:
        verify_artifact(job_id, result_ref, artifacts)
    except (ValueError, OSError, TypeError, AttributeError):
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED") from None
    # verify_artifact validates exact bound job_id/hash and file mode.
    match = re.fullmatch(
        r"artifact:[a-zA-Z0-9-]{1,64}:([a-f0-9]{64})", result_ref
    )
    if match is None:
        raise UsageHold("ARTIFACT_INTEGRITY_UNVERIFIED")
    target = artifacts / (job_id + "-" + match.group(1) + ".jsonl")
    usage = _read_usage(target)
    model = row["model"]
    if type(model) is not str or SAFE_MODEL.fullmatch(model) is None:
        model = None
    return {"quality": "cli_reported_not_provider_verified", "model": model,
            "usage": usage, "actual_spend_usd": None,
            "source": "sha256_verified_codex_exec_artifact",
            "turns_observed": 1}


def main() -> int:
    if os.geteuid() != 0 or os.uname().nodename.split(".")[0] != "vps1777112993":
        print("H272_EXEC_USAGE=HOLD_OWNER_HOST_REQUIRED")
        return 2
    try:
        data = read_one()
    except UsageHold as exc:
        print("H272_EXEC_USAGE=HOLD_" + str(exc))
        return 2
    finally:
        print("SESSION_CONTENT_READ=NO")
        print("CREDENTIALS_READ=NO")
        print("SCHEDULER_MUTATION=NO")
        print("MODEL_CALLS_ADDED=0")
        print("ANALYTICS_TIMER_ACTIVATION=HOLD_SEPARATE_OWNER_GATE")
    print("H272_EXEC_USAGE=METADATA_PASS")
    print("PROVENANCE=SHA256_BOUND_DELIVERED_JOB")
    print("USAGE_QUALITY=CLI_REPORTED_NOT_PROVIDER_VERIFIED")
    print("MODEL=" + (data["model"] or "UNKNOWN"))
    for name, value in data["usage"].items():
        print(name.upper() + "_TOKENS=" + (str(value) if value is not None else "UNKNOWN"))
    print("ACTUAL_SPEND_USD=UNKNOWN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
