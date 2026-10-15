"""Hermes H-04: one-shot main-branch CI outcome, without alert delivery.

Private, read-only, exactly one allowlisted GET. Never infer recovery from
missing/queued/cancelled evidence. No local persistence, Telegram or retries.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from qa_advisor.core import InvalidEvidence, parse_run
from qa_advisor.github_public import (
    GithubPublicError, PRIVATE_REPO, TOKEN_FILE, public_runs,
)

ALLOWLISTED_WORKFLOWS = frozenset()  # Empty until the exact required CI workflow_id is independently verified.
MAX_RUNS = 3


class SnapshotRefused(ValueError):
    """Fixed diagnostic code only."""


def decide(runs: object, *, trusted_workflow_ids: frozenset[str]) -> dict[str, object]:
    """Produce only bounded facts; skip unrelated workflows; no false recovery."""
    if (type(trusted_workflow_ids) is not frozenset
            or not trusted_workflow_ids
            or any(type(v) is not str or not v.startswith("workflow-")
                   or not v[9:].isdigit() for v in trusted_workflow_ids)):
        raise SnapshotRefused("workflow_allowlist_not_verified")
    if type(runs) is not list or len(runs) > MAX_RUNS:
        raise SnapshotRefused("ci_window_invalid")
    try:
        validated = [parse_run(run) for run in runs]
    except InvalidEvidence:
        raise SnapshotRefused("ci_evidence_invalid") from None
    selected = [r for r in validated if (
        r["repo"] == PRIVATE_REPO and r["workflow"] in trusted_workflow_ids
    )]
    if not selected:
        return {"status": "UNKNOWN", "reason": "required_workflow_absent",
                "observed_runs": len(validated), "verified_recovery": False}
    latest = max(selected, key=lambda r: r["run_id"])
    if latest["status"] != "completed":
        state, reason = "RUNNING", "newest_required_run_not_completed"
    elif latest["conclusion"] == "success":
        state, reason = "SUCCESS", "newest_required_run_success"
    elif latest["conclusion"] in ("failure", "startup_failure", "timed_out"):
        state, reason = "FAILURE", "newest_required_run_failed"
    else:
        state, reason = "UNKNOWN", "non_proving_conclusion"
    return {
        "status": state, "reason": reason,
        "repo": PRIVATE_REPO,
        "run_id": latest["run_id"], "head_sha": latest["head_sha"],
        "observed_runs": len(validated),
        "verified_recovery": state == "SUCCESS",
        "no_automatic_retry": True,
        "no_actions": True,
    }


def inspect_once(
    *,
    workflow_ids: frozenset[str] = ALLOWLISTED_WORKFLOWS,
    token_file: Path = TOKEN_FILE,
    reader: Callable[..., list[dict[str, Any]]] = public_runs,
) -> dict[str, object]:
    if not workflow_ids:
        raise SnapshotRefused("workflow_allowlist_not_verified")
    rows = reader(PRIVATE_REPO, branch="main", token_file=token_file)
    return decide(rows, trusted_workflow_ids=workflow_ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One GET; read-only Hermes main CI")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = inspect_once()
    except (SnapshotRefused, GithubPublicError):
        print(json.dumps({"status": "UNKNOWN", "reason": "ci_observation_unavailable"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] != "UNKNOWN" else 2


if __name__ == "__main__":
    raise SystemExit(main())
