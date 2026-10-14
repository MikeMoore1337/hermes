"""Hermes QA Advisor: deterministic, offline CI metadata analysis.

Never fetch CI logs, send requests, run jobs or mutate GitHub.
Failure labels are hypotheses, not root-cause determinations.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

ALLOWED_REPOS = frozenset({
    "MikeMoore1337/hermes",
    "MikeMoore1337/your-fitness-coach",
})
CONCLUSIONS = frozenset({
    "success", "failure", "cancelled", "timed_out", "neutral",
    "skipped", "action_required", "startup_failure",
})
RUN_STATUS = frozenset({"queued", "in_progress", "completed"})
JOB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,90}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_RUNS = 200
MAX_JOBS = 60


class InvalidEvidence(ValueError):
    """Never include untrusted evidence or token strings in the reason."""


def bounded(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise InvalidEvidence(label + "_invalid")
    if any(ord(c) < 32 for c in value):
        raise InvalidEvidence(label + "_invalid")
    return value


def parse_job(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != {"name", "conclusion"}:
        raise InvalidEvidence("job_schema_invalid")
    name = bounded(obj["name"], "job_name", 91)
    if not JOB_NAME.fullmatch(name):
        raise InvalidEvidence("job_name_invalid")
    conclusion = obj["conclusion"]
    if conclusion is not None and (
        not isinstance(conclusion, str) or conclusion not in CONCLUSIONS
    ):
        raise InvalidEvidence("job_conclusion_invalid")
    return {"name": name, "conclusion": conclusion}


def parse_run(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != {
        "repo", "workflow", "run_id", "head_sha", "status", "conclusion", "jobs"
    }:
        raise InvalidEvidence("run_schema_invalid")
    repo = bounded(obj["repo"], "repo", 100)
    if repo not in ALLOWED_REPOS:
        raise InvalidEvidence("repository_not_allowlisted")
    workflow = bounded(obj["workflow"], "workflow", 91)
    if not JOB_NAME.fullmatch(workflow):
        raise InvalidEvidence("workflow_invalid")
    run_id = obj["run_id"]
    if type(run_id) is not int or not 1 <= run_id <= 10**18:
        raise InvalidEvidence("run_id_invalid")
    sha = obj["head_sha"]
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise InvalidEvidence("head_sha_invalid")
    status = obj["status"]
    conclusion = obj["conclusion"]
    if (not isinstance(status, str) or status not in RUN_STATUS
            or (status == "completed" and (
                not isinstance(conclusion, str) or conclusion not in CONCLUSIONS
            )) or (status != "completed" and conclusion is not None)):
        raise InvalidEvidence("run_state_invalid")
    jobs = obj["jobs"]
    if not isinstance(jobs, list) or len(jobs) > MAX_JOBS:
        raise InvalidEvidence("jobs_invalid")
    clean_jobs = [parse_job(job) for job in jobs]
    if len({job["name"] for job in clean_jobs}) != len(clean_jobs):
        raise InvalidEvidence("duplicate_job_names")
    return {
        "repo": repo, "workflow": workflow, "run_id": run_id,
        "head_sha": sha, "status": status, "conclusion": conclusion,
        "jobs": clean_jobs,
    }


def category(run: dict[str, Any]) -> str:
    """Return a bounded *diagnostic hypothesis*, not invented root cause."""
    if run["status"] != "completed":
        return "pending_no_diagnosis"
    if run["conclusion"] == "success":
        return "healthy"
    if run["conclusion"] == "cancelled":
        return "cancelled_unknown_reason"
    if run["conclusion"] == "timed_out":
        return "timeout_investigation"
    if run["conclusion"] == "action_required":
        return "manual_approval_required"
    if run["conclusion"] == "startup_failure":
        return "runner_startup_investigation"
    if run["conclusion"] in ("neutral", "skipped"):
        return "no_evidence"
    # Failure could be infra, test or tool issue. Job metadata cannot prove
    # root cause, so do not guess based on name alone.
    return "failure_unknown_root_cause"


def analyze(raw: Any) -> dict[str, Any]:
    """Expose only vetted repo/run IDs, classifications and safe action hints."""
    if not isinstance(raw, list) or len(raw) > MAX_RUNS:
        raise InvalidEvidence("batch_invalid")
    parsed = [parse_run(obj) for obj in raw]
    identifiers = [(r["repo"], r["run_id"]) for r in parsed]
    if len(identifiers) != len(set(identifiers)):
        raise InvalidEvidence("duplicate_run_id")
    cohorts: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for run in parsed:
        if run["status"] == "completed":
            cohorts[(run["repo"], run["workflow"], run["head_sha"])].add(
                run["conclusion"]
            )
    findings = []
    for run in parsed:
        label = category(run)
        if label in ("healthy", "pending_no_diagnosis", "no_evidence"):
            continue
        failed_names = sorted(
            job["name"] for job in run["jobs"] if job["conclusion"] == "failure"
        )
        cross_runs = cohorts[(run["repo"], run["workflow"], run["head_sha"])]
        flaky_candidate = (label == "failure_unknown_root_cause"
                           and "failure" in cross_runs and "success" in cross_runs)
        findings.append({
            "repo": run["repo"], "run_id": run["run_id"],
            "workflow": run["workflow"], "head_sha": run["head_sha"],
            "classification": label,
            "repeatability_signal": (
                "same_commit_success_and_failure_check_environment"
                if flaky_candidate else "unknown"
            ),
            "failed_job_names": failed_names,
            "suggested_action": (
                "compare_attempt_environments_and_sanitized_logs" if flaky_candidate
                else "inspect_sanitized_logs_manually"
            ),
        })
    findings.sort(key=lambda x: (x["repo"], x["run_id"]))
    return {"status": "NO_DATA" if not raw else "REVIEW_REQUIRED" if findings else
            "NO_INCIDENT_EVIDENCE", "findings": findings, "observed_runs": len(parsed)}
