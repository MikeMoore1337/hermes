"""Offline MergeControl v1: bounded overlap and dependency risk signals.

No GitHub fetches, git commands, agent scheduling, rebase or merge operations.
An overlap is not a proven merge conflict; input is not independently verified.
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

SCHEMA = "hermes-mergecontrol-evidence-v1"
REPORT_SCHEMA = "hermes-mergecontrol-review-v1"
REPOS = {
    "MikeMoore1337/hermes": frozenset({"main"}),
    "MikeMoore1337/ai-development-toolkit": frozenset({"main"}),
    "MikeMoore1337/your-fitness-coach": frozenset({"dev", "master"}),
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
PATH = re.compile(r"[A-Za-z0-9._/@+\-]{1,180}\Z")
STATUSES = frozenset({"added", "modified", "removed", "renamed"})
MAX_PRS = 24
MAX_FILES = 120
MAX_BYTES = 65536
MAX_AGE = timedelta(minutes=45)
MAX_SKEW = timedelta(minutes=2)


class MergeEvidenceRefused(ValueError):
    """Fixed error codes; never echo source text, branch/path or token."""


def _shape(value: Any, keys: set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise MergeEvidenceRefused(code)
    return value


def _id(value: Any, code: str) -> int:
    if type(value) is not int or not 1 <= value <= 10**18:
        raise MergeEvidenceRefused(code)
    return value


def _sha(value: Any, code: str) -> str:
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise MergeEvidenceRefused(code)
    return value


def _path(value: Any) -> str:
    if (type(value) is not str or PATH.fullmatch(value) is None
            or value.startswith(("/", "./", ".git/"))
            or any(segment in ("", ".", "..") for segment in value.split("/"))):
        raise MergeEvidenceRefused("path_invalid")
    return value


def _time(value: Any) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise MergeEvidenceRefused("observed_at_invalid")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise MergeEvidenceRefused("observed_at_invalid") from None
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise MergeEvidenceRefused("observed_at_invalid")
    return dt.astimezone(UTC)


def _file(value: Any) -> tuple[dict, set[str]]:
    row = _shape(value, {"path", "previous_path", "status"}, "file_shape_invalid")
    path = _path(row["path"])
    if type(row["status"]) is not str or row["status"] not in STATUSES:
        raise MergeEvidenceRefused("file_status_invalid")
    previous = row["previous_path"]
    if row["status"] == "renamed":
        previous = _path(previous)
        if previous == path:
            raise MergeEvidenceRefused("rename_invalid")
    elif previous is not None:
        raise MergeEvidenceRefused("previous_path_unexpected")
    return row, {path, previous} if previous is not None else {path}


def _pr(raw: Any, repo: str) -> tuple[dict, set[str]]:
    row = _shape(raw, {
        "number", "head_sha", "base_sha", "base_branch",
        "draft", "mergeable", "files_complete", "files", "depends_on",
    }, "pr_shape_invalid")
    _id(row["number"], "pr_number_invalid")
    _sha(row["head_sha"], "head_sha_invalid")
    _sha(row["base_sha"], "base_sha_invalid")
    if (type(row["base_branch"]) is not str or row["base_branch"] not in REPOS[repo]
            or type(row["draft"]) is not bool
            or type(row["files_complete"]) is not bool
            or type(row["mergeable"]) is not str
            or row["mergeable"] not in ("clean", "dirty", "unknown")):
        raise MergeEvidenceRefused("pr_state_invalid")
    files = row["files"]
    if type(files) is not list or len(files) > MAX_FILES:
        raise MergeEvidenceRefused("files_window_invalid")
    affected: set[str] = set()
    original: set[str] = set()
    for f in files:
        item, paths = _file(f)
        if item["path"] in original:
            raise MergeEvidenceRefused("file_duplicate")
        original.add(item["path"])
        affected.update(paths)
    deps = row["depends_on"]
    if (type(deps) is not list or len(deps) > MAX_PRS
            or any(type(d) is not int or not 1 <= d <= 10**18 for d in deps)
            or len(set(deps)) != len(deps) or row["number"] in deps):
        raise MergeEvidenceRefused("dependencies_invalid")
    return row, affected


def _order(items: dict[int, dict]) -> list[int]:
    remaining = {number: set(row["depends_on"]) for number, row in items.items()}
    ordered: list[int] = []
    while remaining:
        ready = sorted(number for number, deps in remaining.items() if not deps)
        if not ready:
            return []
        number = ready[0]
        ordered.append(number)
        remaining.pop(number)
        for deps in remaining.values():
            deps.discard(number)
    return ordered


def review(raw: Any, *, now: datetime | None = None) -> dict:
    data = _shape(raw, {"schema", "repo", "observed_at", "window_complete", "prs"},
                  "evidence_shape_invalid")
    if (data["schema"] != SCHEMA or type(data["repo"]) is not str
            or data["repo"] not in REPOS or type(data["window_complete"]) is not bool):
        raise MergeEvidenceRefused("evidence_scope_invalid")
    observed = _time(data["observed_at"])
    checked = now if now is not None else datetime.now(UTC)
    if type(checked) is not datetime or checked.tzinfo is None or checked.utcoffset() != timedelta(0):
        raise MergeEvidenceRefused("clock_invalid")
    checked = checked.astimezone(UTC)
    raw_prs = data["prs"]
    if type(raw_prs) is not list or len(raw_prs) > MAX_PRS:
        raise MergeEvidenceRefused("prs_window_invalid")
    prs: dict[int, dict] = {}
    paths: dict[int, set[str]] = {}
    for raw_pr in raw_prs:
        row, affected = _pr(raw_pr, data["repo"])
        number = row["number"]
        if number in prs:
            raise MergeEvidenceRefused("duplicate_pr")
        prs[number] = row
        paths[number] = affected
    reasons: set[str] = set()
    review_signals: set[str] = set()
    if not data["window_complete"]:
        reasons.add("pr_window_incomplete")
    if observed > checked + MAX_SKEW:
        reasons.add("future_evidence")
    if checked - observed > MAX_AGE:
        reasons.add("stale_evidence")
    if any(not row["files_complete"] for row in prs.values()):
        reasons.add("files_window_incomplete")
    if any(row["mergeable"] == "unknown" for row in prs.values()):
        reasons.add("mergeability_unknown")
    if any(row["mergeable"] == "dirty" for row in prs.values()):
        review_signals.add("github_dirty_reported_input_only")
    if any(row["draft"] for row in prs.values()):
        review_signals.add("draft_pr_in_window")
    if any(any(dep not in prs for dep in row["depends_on"]) for row in prs.values()):
        reasons.add("dependency_outside_window")
    if len({(row["base_branch"], row["base_sha"]) for row in prs.values()}) > 1:
        reasons.add("multiple_base_refs")
    order = _order(prs) if "dependency_outside_window" not in reasons else []
    if prs and not order and "dependency_outside_window" not in reasons:
        review_signals.add("dependency_cycle_or_incomplete")
    overlaps: list[dict] = []
    numbers = sorted(prs)
    for i, one in enumerate(numbers):
        for other in numbers[i + 1:]:
            shared = sorted(paths[one] & paths[other])
            if shared:
                # Even identical paths may merge cleanly. A rename/delete only
                # broadens the path set; do not infer textual conflicts.
                overlaps.append({
                    "prs": [one, other],
                    "paths": shared[:MAX_FILES],
                    "classification": "POTENTIAL_OVERLAP_NOT_PROVEN_CONFLICT",
                    "same_base_branch": prs[one]["base_branch"] == prs[other]["base_branch"],
                })
    if overlaps:
        review_signals.add("overlapping_paths")
    status = (
        "REVIEW_REQUIRED" if review_signals
        else "INCONCLUSIVE" if reasons
        else "NO_OVERLAP_IN_SUPPLIED_WINDOW"
    )
    return {
        "schema": REPORT_SCHEMA,
        "status": status, "repo": data["repo"],
        "checked_at": checked.isoformat().replace("+00:00", "Z"),
        "reasons": sorted(reasons | review_signals),
        "prs_seen": len(prs),
        "overlaps": overlaps,
        "suggested_order": order,
        "pr_urls": [f"https://github.com/{data['repo']}/pull/{n}" for n in numbers],
        "evidence_verified": False,
        "dependency_claims_verified": False,
        "window_exhaustive_verified": False,
        "owner_approval": "NOT_GRANTED",
        "merge_authorized": False,
        "execution_authorized": False,
        "recommendation_only": True,
    }


def _load(path: Path) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 2 <= info.st_size <= MAX_BYTES:
                raise MergeEvidenceRefused("file_invalid")
            body = os.read(fd, MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(body) > MAX_BYTES:
            raise MergeEvidenceRefused("file_invalid")
        return json.loads(body)
    except MergeEvidenceRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise MergeEvidenceRefused("file_unavailable_or_invalid") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline MergeControl review; no GitHub or git writes")
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    if args.input is None:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = review(_load(args.input))
    except MergeEvidenceRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "NO_OVERLAP_IN_SUPPLIED_WINDOW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
