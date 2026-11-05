"""Offline, fail-closed ReleaseGuard precheck for sanitized GitHub evidence.

This is NOT an authenticated GitHub collector or permission to merge/deploy.
Only a trusted caller can independently establish the truth of the input.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA = "hermes-releaseguard-evidence-v1"
REPORT_SCHEMA = "hermes-releaseguard-precheck-v1"
REPOSITORIES = {
    "MikeMoore1337/hermes": {"PR": "main", "RELEASE": "main"},
    "MikeMoore1337/ai-development-toolkit": {"PR": "main", "RELEASE": "main"},
    "MikeMoore1337/your-fitness-coach": {"PR": "dev", "RELEASE": "master"},
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
CONCLUSIONS = frozenset({
    "success", "failure", "cancelled", "timed_out", "neutral",
    "skipped", "action_required", "startup_failure",
})
STATES = frozenset({"queued", "in_progress", "completed"})
MAX_CHECKS = 24
MAX_REQUIRED = 16
MAX_BYTES = 32768
MAX_AGE = timedelta(minutes=45)
FUTURE_SKEW = timedelta(minutes=2)


class ReleaseEvidenceRefused(ValueError):
    """Fixed error codes only; never echo supplied evidence."""


def _shape(value: Any, keys: set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ReleaseEvidenceRefused(code)
    return value


def _sha(value: Any, code: str) -> str:
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise ReleaseEvidenceRefused(code)
    return value


def _id(value: Any, code: str) -> int:
    if type(value) is not int or not 1 <= value <= 10**18:
        raise ReleaseEvidenceRefused(code)
    return value


def _utc(value: Any) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise ReleaseEvidenceRefused("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ReleaseEvidenceRefused("timestamp_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ReleaseEvidenceRefused("timestamp_invalid")
    return parsed.astimezone(UTC)


def _check(raw: Any) -> dict:
    row = _shape(raw, {"workflow_id", "run_id", "head_sha", "status", "conclusion"}, "check_shape_invalid")
    _id(row["workflow_id"], "workflow_invalid")
    _id(row["run_id"], "run_invalid")
    _sha(row["head_sha"], "check_sha_invalid")
    state, conclusion = row["status"], row["conclusion"]
    if (type(state) is not str or state not in STATES
            or (state == "completed" and (type(conclusion) is not str
                                           or conclusion not in CONCLUSIONS))
            or (state != "completed" and conclusion is not None)):
        raise ReleaseEvidenceRefused("check_state_invalid")
    return row


def _validate(raw: Any) -> tuple[dict, datetime]:
    data = _shape(raw, {
        "schema", "repo", "stage", "branch", "candidate_sha",
        "observed_head_sha", "observed_at", "required_workflows",
        "checks", "review", "mergeability", "draft",
    }, "evidence_shape_invalid")
    if data["schema"] != SCHEMA or type(data["repo"]) is not str or data["repo"] not in REPOSITORIES:
        raise ReleaseEvidenceRefused("evidence_scope_invalid")
    if (type(data["stage"]) is not str or data["stage"] not in ("PR", "RELEASE")
            or type(data["branch"]) is not str
            or data["branch"] != REPOSITORIES[data["repo"]][data["stage"]]):
        raise ReleaseEvidenceRefused("branch_scope_invalid")
    _sha(data["candidate_sha"], "candidate_sha_invalid")
    if data["observed_head_sha"] is not None:
        _sha(data["observed_head_sha"], "branch_sha_invalid")
    observed = _utc(data["observed_at"])
    required = data["required_workflows"]
    if (type(required) is not list or not 1 <= len(required) <= MAX_REQUIRED
            or any(type(w) is not int or not 1 <= w <= 10**18 for w in required)
            or len(set(required)) != len(required)):
        raise ReleaseEvidenceRefused("required_workflows_invalid")
    rows = data["checks"]
    if type(rows) is not list or len(rows) > MAX_CHECKS:
        raise ReleaseEvidenceRefused("checks_invalid")
    checks = [_check(row) for row in rows]
    if len({r["workflow_id"] for r in checks}) != len(checks):
        raise ReleaseEvidenceRefused("duplicate_workflow_invalid")
    review = _shape(data["review"], {"state", "head_sha"}, "review_shape_invalid")
    if type(review["state"]) is not str or review["state"] not in {
        "approved", "changes_requested", "pending", "unknown", "not_applicable",
    }:
        raise ReleaseEvidenceRefused("review_state_invalid")
    if review["head_sha"] is not None:
        _sha(review["head_sha"], "review_sha_invalid")
    if type(data["mergeability"]) is not str or data["mergeability"] not in {
        "clean", "dirty", "unknown", "not_applicable",
    }:
        raise ReleaseEvidenceRefused("mergeability_invalid")
    if data["stage"] == "PR":
        if type(data["draft"]) is not bool or review["state"] == "not_applicable" or data["mergeability"] == "not_applicable":
            raise ReleaseEvidenceRefused("pr_evidence_invalid")
    elif (data["draft"] is not None or review != {"state": "not_applicable", "head_sha": None}
          or data["mergeability"] != "not_applicable"):
        raise ReleaseEvidenceRefused("release_evidence_invalid")
    return data, observed


def evaluate(raw: Any, *, now: datetime | None = None) -> dict:
    """Assess bounded supplied evidence. Passing never proves authenticity or owner GO."""
    data, observed = _validate(raw)
    checked = now if now is not None else datetime.now(UTC)
    if type(checked) is not datetime or checked.tzinfo is None or checked.utcoffset() != timedelta(0):
        raise ReleaseEvidenceRefused("clock_invalid")
    checked = checked.astimezone(UTC)
    blocked: set[str] = set()
    inconclusive: set[str] = set()
    if observed > checked + FUTURE_SKEW:
        inconclusive.add("future_evidence")
    if checked - observed > MAX_AGE:
        inconclusive.add("stale_evidence")
    candidate = data["candidate_sha"]
    if data["observed_head_sha"] is None:
        inconclusive.add("branch_head_unknown")
    elif data["observed_head_sha"] != candidate:
        inconclusive.add("branch_sha_mismatch")
    checks = {r["workflow_id"]: r for r in data["checks"]}
    for workflow in data["required_workflows"]:
        row = checks.get(workflow)
        if row is None:
            inconclusive.add("required_check_missing")
        elif row["head_sha"] != candidate:
            inconclusive.add("check_sha_mismatch")
        elif row["status"] != "completed":
            inconclusive.add("required_check_pending")
        elif row["conclusion"] in ("failure", "startup_failure", "timed_out", "action_required"):
            blocked.add("required_check_failed")
        elif row["conclusion"] != "success":
            inconclusive.add("required_check_not_proving")
    if data["stage"] == "PR":
        if data["draft"]:
            blocked.add("draft_pr")
        if data["mergeability"] == "dirty":
            blocked.add("merge_conflict")
        elif data["mergeability"] == "unknown":
            inconclusive.add("mergeability_unknown")
        review = data["review"]
        if review["state"] == "changes_requested":
            blocked.add("changes_requested")
        elif review["state"] == "pending":
            blocked.add("review_pending")
        elif review["state"] != "approved":
            inconclusive.add("review_unknown")
        if review["head_sha"] != candidate:
            inconclusive.add("review_sha_not_verified")
    if data["stage"] == "RELEASE" and data["repo"] == "MikeMoore1337/your-fitness-coach":
        inconclusive.add("yfc_dev_to_master_gate_not_verified")
    status = "BLOCKED" if blocked else "INCONCLUSIVE" if inconclusive else "READY_FOR_OWNER_REVIEW"
    # URLs are constructed solely from allowlisted repository and integer IDs.
    urls = [
        f"https://github.com/{data['repo']}/actions/runs/{checks[w]['run_id']}"
        for w in data["required_workflows"] if w in checks
    ]
    return {
        "schema": REPORT_SCHEMA,
        "status": status,
        "repo": data["repo"],
        "stage": data["stage"],
        "branch": data["branch"],
        "candidate_sha": candidate,
        "checked_at": checked.isoformat().replace("+00:00", "Z"),
        "reasons": sorted(blocked | inconclusive),
        "required_count": len(data["required_workflows"]),
        "observed_count": len(checks),
        "evidence_urls": urls,
        "evidence_verified": False,
        "required_workflow_policy_verified": False,
        "production_evidence": "NOT_VERIFIED",
        "owner_approval": "NOT_GRANTED",
        "execution_authorized": False,
        "deploy_authorized": False,
        "recommendation_only": True,
    }


def _read_file(path: Path) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES or info.st_size < 2:
                raise ReleaseEvidenceRefused("file_invalid")
            body = os.read(fd, MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(body) > MAX_BYTES:
            raise ReleaseEvidenceRefused("file_invalid")
        return json.loads(body)
    except ReleaseEvidenceRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise ReleaseEvidenceRefused("file_unavailable_or_invalid") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline ReleaseGuard precheck; no GitHub access or write effects")
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    if args.input is None:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        report = evaluate(_read_file(args.input))
    except ReleaseEvidenceRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "READY_FOR_OWNER_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
