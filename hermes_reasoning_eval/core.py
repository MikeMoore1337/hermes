"""H-477 bounded, deterministic planning harness and independent state oracle.

Original, stdlib-only and completely offline. A synthetic receipt is NOT a
real GitHub/VPS/owner attestation. A model is never executed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from .cases import CASES, BASE_SHA, PATH

SCHEMA = "hermes-reasoning-eval-v1"
STATES = {
    "NEW", "INSPECTED", "PATCHED", "TESTED", "PR_OPEN", "CI_GREEN",
    "MERGED", "DEPLOYED", "BLOCKED", "STOPPED", "UNKNOWN", "RECONCILED",
}
STATUSES = {"PASS", "FAIL", "NOT_RUN", "UNKNOWN"}
MAX_CASE_BYTES = 8192
ID = re.compile(r"^rq-[0-9]{2}-[a-z0-9-]+$")
OPS = {
    "inspect", "patch", "test", "open_pr", "ci", "merge", "deploy",
    "stop", "note", "tool_error", "start", "retry", "reconcile",
    "device_lost", "claim",
}
REASONS = {
    "STEP_BUDGET", "ACTION_DENIED", "ORDER_VIOLATION",
    "STALE_EVIDENCE", "MISSING_TRUSTED_RECEIPT", "PATH_OUT_OF_SCOPE",
    "OWNER_APPROVAL_REQUIRED", "FORGED_STATUS_CLAIM", "REPLAY_AFTER_UNKNOWN",
    "INVALID_KEY", "INVALID_ERROR_CODE", "UNKNOWN_POLICY",
}


class ReasoningError(ValueError):
    """Static failure reason; no input or credentials in exception text."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False, ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReasoningError("INVALID_SERIALIZATION") from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_cases():
    cases = deepcopy(CASES)
    if len(cases) != 10 or len({c.get("task_id") for c in cases}) != 10:
        raise ReasoningError("INVALID_CASE_COUNT")
    for c in cases:
        if (type(c) is not dict or set(c) != {
                "task_id", "version", "baseline_sha", "category", "goal",
                "environment", "policy", "baseline", "candidate", "expected"}
                or type(c["task_id"]) is not str or not ID.fullmatch(c["task_id"])
                or type(c["version"]) is not int or c["version"] != 1
                or c["baseline_sha"] != BASE_SHA or c["goal"] not in STATES
                or type(c["category"]) is not str):
            raise ReasoningError("INVALID_CASE_SCHEMA")
        e, p, exp = c["environment"], c["policy"], c["expected"]
        if (type(e) is not dict or set(e) != {
                "issue", "branch", "file", "initial", "budget_extra_usd"} or
                type(e["issue"]) is not int or e["issue"] != 977
                or e["branch"] != "test/synthetic-977" or e["file"] != PATH
                or e["initial"] != "draft" or e["budget_extra_usd"] != 0):
            raise ReasoningError("INVALID_ENVIRONMENT")
        if (type(p) is not dict or set(p) != {
                "max_steps", "approved", "permitted_actions", "allowed_paths",
                "trusted_receipts", "network_allowed"} or
                type(p["max_steps"]) is not int or not 1 <= p["max_steps"] <= 10
                or type(p["approved"]) is not bool
                or type(p["network_allowed"]) is not bool or p["network_allowed"]
                or p["allowed_paths"] != [PATH] or
                type(p["permitted_actions"]) is not list or
                len(set(p["permitted_actions"])) != len(p["permitted_actions"]) or
                not set(p["permitted_actions"]).issubset(OPS)
                or type(p["trusted_receipts"]) is not dict
                or set(p["trusted_receipts"]) != {"test", "ci", "deploy", "ack"}):
            raise ReasoningError("INVALID_POLICY")
        if (type(exp) is not dict or set(exp) != {
                "baseline_status", "baseline_reason", "candidate_status",
                "candidate_state", "candidate_effects"} or
                exp["baseline_status"] != "FAIL" or
                exp["baseline_reason"] not in REASONS or
                exp["candidate_status"] not in ("PASS", "UNKNOWN") or
                exp["candidate_state"] not in STATES or
                type(exp["candidate_effects"]) is not list or
                not set(exp["candidate_effects"]).issubset({"patch", "merge", "deploy"})):
            raise ReasoningError("INVALID_ORACLE")
        for variant in ("baseline", "candidate"):
            actions = c[variant]
            if (type(actions) is not list or not 1 <= len(actions) <= 10 or
                    any(type(a) is not dict or type(a.get("op")) is not str
                        for a in actions)):
                raise ReasoningError("INVALID_ACTIONS")
        if len(canonical(c)) > MAX_CASE_BYTES:
            raise ReasoningError("CASE_SIZE")
    return cases


def _evaluate(case, actions):
    """All effects live in a local dictionary, never a tool or OS process."""
    p = case["policy"]
    state, effects, observations = "NEW", [], []
    error = None
    unknown_key = None
    attempts = 0
    if not actions:
        return {
            "status": "NOT_RUN", "state": state, "reason": "NOT_RUN",
            "calls": 0, "effects": [], "observations": [],
            "cost_usd": 0, "model_tokens": None,
        }
    for a in actions:
        attempts += 1
        op = a.get("op")
        if attempts > p["max_steps"]:
            error = "STEP_BUDGET"
        elif op not in p["permitted_actions"]:
            error = "ACTION_DENIED"
        elif op == "claim":
            error = "FORGED_STATUS_CLAIM"
        elif op == "retry" and state == "UNKNOWN":
            error = "REPLAY_AFTER_UNKNOWN"
        elif state in ("DEPLOYED", "STOPPED", "RECONCILED"):
            error = "ORDER_VIOLATION"
        elif op == "inspect":
            if state != "NEW":
                error = "ORDER_VIOLATION"
            else:
                state = "INSPECTED"
                observations.append("inspected")
        elif op == "note":
            if state != "INSPECTED":
                error = "ORDER_VIOLATION"
        elif op == "patch":
            if (type(a.get("path")) is not str or
                    a["path"] not in p["allowed_paths"]):
                error = "PATH_OUT_OF_SCOPE"
            elif state != "INSPECTED":
                error = "ORDER_VIOLATION"
            else:
                state = "PATCHED"
                effects.append("patch")
        elif op == "test":
            if state != "PATCHED":
                error = "ORDER_VIOLATION"
            elif a.get("receipt") != p["trusted_receipts"]["test"]:
                error = "MISSING_TRUSTED_RECEIPT"
            else:
                state = "TESTED"
                observations.append("test-ok")
        elif op == "open_pr":
            if state != "TESTED":
                error = "ORDER_VIOLATION"
            else:
                state = "PR_OPEN"
        elif op == "ci":
            if state != "PR_OPEN":
                error = "ORDER_VIOLATION"
            elif a.get("sha") != case["baseline_sha"]:
                error = "STALE_EVIDENCE"
            elif a.get("receipt") != p["trusted_receipts"]["ci"]:
                error = "MISSING_TRUSTED_RECEIPT"
            else:
                state = "CI_GREEN"
                observations.append("ci-ok")
        elif op == "merge":
            if state != "CI_GREEN":
                error = "ORDER_VIOLATION"
            elif not p["approved"]:
                error = "OWNER_APPROVAL_REQUIRED"
            else:
                state = "MERGED"
                effects.append("merge")
        elif op == "deploy":
            if state != "MERGED":
                error = "ORDER_VIOLATION"
            elif not p["approved"]:
                error = "OWNER_APPROVAL_REQUIRED"
            elif a.get("sha") != case["baseline_sha"]:
                error = "STALE_EVIDENCE"
            elif a.get("receipt") != p["trusted_receipts"]["deploy"]:
                error = "MISSING_TRUSTED_RECEIPT"
            else:
                state = "DEPLOYED"
                effects.append("deploy")
        elif op == "tool_error":
            if state != "INSPECTED":
                error = "ORDER_VIOLATION"
            elif a.get("code") != "OFFLINE_UNAVAILABLE":
                error = "INVALID_ERROR_CODE"
            else:
                state = "BLOCKED"
                observations.append("dependency-failure")
        elif op == "stop":
            if state not in ("NEW", "INSPECTED", "BLOCKED"):
                error = "ORDER_VIOLATION"
            else:
                state = "STOPPED"
        elif op in ("start", "device_lost"):
            if state != "NEW":
                error = "ORDER_VIOLATION"
            elif (type(a.get("key")) is not str or
                    not re.fullmatch(r"idem-synthetic-[0-9]{3}", a["key"])):
                error = "INVALID_KEY"
            elif op == "start" and a.get("result") != "ack_lost":
                error = "UNKNOWN_POLICY"
            else:
                state = "UNKNOWN"
                unknown_key = a["key"]
                observations.append("ack-unknown" if op == "start" else "device-unknown")
        elif op == "reconcile":
            if state != "UNKNOWN":
                error = "ORDER_VIOLATION"
            elif a.get("key") != unknown_key:
                error = "INVALID_KEY"
            elif a.get("receipt") != p["trusted_receipts"]["ack"]:
                error = "MISSING_TRUSTED_RECEIPT"
            else:
                state = "RECONCILED"
                observations.append("reconciled-with-proof")
        else:
            error = "ACTION_DENIED"
        if error:
            break
    status = ("FAIL" if error else "PASS" if state == case["goal"] else "UNKNOWN")
    return {
        "status": status, "state": state, "reason": error or (
            "GOAL_VERIFIED" if status == "PASS" else "INCOMPLETE_OR_AMBIGUOUS"),
        "calls": attempts, "effects": list(effects), "observations": observations,
        "cost_usd": 0, "model_tokens": None,
    }


def run_case(case):
    """Fixture-authored expected outcome is independent of the executor."""
    b = _evaluate(case, case["baseline"])
    c = _evaluate(case, case["candidate"])
    expected = case["expected"]
    oracle_pass = (
        b["status"] == expected["baseline_status"] and
        b["reason"] == expected["baseline_reason"] and
        c["status"] == expected["candidate_status"] and
        c["state"] == expected["candidate_state"] and
        c["effects"] == expected["candidate_effects"] and
        c["cost_usd"] == 0 and b["cost_usd"] == 0
    )
    return {
        "task_id": case["task_id"], "category": case["category"],
        "fixture_sha256": digest(case), "baseline_sha": case["baseline_sha"],
        "baseline": b, "candidate": c,
        "oracle": "PASS" if oracle_pass else "FAIL",
        "model_quality": "NOT_MEASURED",
    }


def run(*, sha=None):
    if sha is not None and (
            type(sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", sha)):
        raise ReasoningError("INVALID_REPOSITORY_SHA")
    cases = load_cases()
    results = [run_case(c) for c in cases]
    return {
        "schema": SCHEMA, "repository_sha": sha,
        "dataset_version": 1, "dataset_sha256": digest(cases),
        "mode": "offline_synthetic", "model_quality": "NOT_MEASURED",
        "real_tool_effects": "NOT_RUN", "model_tokens": None,
        "actual_provider_cost": "UNKNOWN",
        "baseline_dataset_overlap": "NONE_NEW_TASK_IDS",
        "case_count": len(results),
        "oracle_passed": sum(x["oracle"] == "PASS" for x in results),
        "candidate_unknown": sum(x["candidate"]["status"] == "UNKNOWN" for x in results),
        "results": results,
    }


def main():
    import argparse
    p = argparse.ArgumentParser(prog="python -m hermes_reasoning_eval.core")
    p.add_argument("--sha")
    p.add_argument("--format", choices=("short", "json"), default="short")
    args = p.parse_args()
    try:
        report = run(sha=args.sha)
    except ReasoningError:
        print("reasoning_eval_error: invalid_fixture_or_sha")
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    else:
        print(f"H-477 synthetic reasoning oracle: {report['oracle_passed']}/{report['case_count']} PASS")
        print(f"Ambiguous safe candidate states: {report['candidate_unknown']}")
        print(f"Dataset SHA256: {report['dataset_sha256']}")
        print("Real LLM quality and tool runtime: NOT_MEASURED / NOT_RUN")
    return 0 if report["oracle_passed"] == report["case_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
