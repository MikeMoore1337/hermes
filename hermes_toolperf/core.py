"""Deterministic in-memory tool-use comparison for Hermes #463.

No network, subprocess, model inference, host file writes, or device access.
This evaluator measures the synthetic tool scripts, NOT live Hermes or LLM performance.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
import re
import time

from .cases import CASES, VERSION

SCHEMA = "hermes-toolperf-v1"
OPERATIONS = {"read", "list", "patch", "write", "check", "env", "run", "claim"}
FIELDS = {
    "task_id", "version", "category", "initial_files", "expected_files",
    "allowed_writes", "required_reads", "required_checks", "call_budget",
    "output_budget", "baseline", "candidate",
}


class ToolperfError(ValueError):
    """A corrupt or incompatible benchmark fixture."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def fixture_sha256(case):
    return hashlib.sha256(canonical(case)).hexdigest()


def _safe_path(path):
    if not isinstance(path, str) or not path or len(path) > 160 or "\\" in path:
        return False
    p = PurePosixPath(path)
    return (not p.is_absolute() and all(x not in ("", ".", "..") for x in
                                         path.split("/")) and ":" not in path)


def load_cases():
    cases = deepcopy(CASES)
    if len(cases) != 9 or len({x.get("task_id") for x in cases}) != 9:
        raise ToolperfError("fixture_count_or_duplicate")
    for c in cases:
        if set(c) != FIELDS or c["version"] != VERSION or not re.fullmatch(
                r"tp-[0-9]{2}-[a-z0-9-]+", c["task_id"]):
            raise ToolperfError("fixture_schema")
        if (not isinstance(c["category"], str) or
                type(c["call_budget"]) is not int or
                not 1 <= c["call_budget"] <= 8 or
                c["output_budget"] != 128):
            raise ToolperfError("fixture_limits")
        for field in ("initial_files", "expected_files"):
            files = c[field]
            if not isinstance(files, dict) or len(files) > 8 or any(
                    not _safe_path(p) or not isinstance(v, str) or
                    len(v.encode("utf-8")) > 4096 for p, v in files.items()):
                raise ToolperfError("fixture_files")
        if not isinstance(c["allowed_writes"], list) or any(
                not _safe_path(p) for p in c["allowed_writes"]):
            raise ToolperfError("fixture_writes")
        if not isinstance(c["required_reads"], dict) or any(
                not _safe_path(p) or not isinstance(offsets, list) or
                not offsets or any(type(o) is not int or o < 0
                                   for o in offsets)
                for p, offsets in c["required_reads"].items()):
            raise ToolperfError("fixture_reads")
        if not isinstance(c["required_checks"], list) or not all(
                x in ("env-ok", "check-ok") for x in c["required_checks"]):
            raise ToolperfError("fixture_checks")
        for variant in ("baseline", "candidate"):
            actions = c[variant]
            if not isinstance(actions, list) or not 1 <= len(actions) <= 8:
                raise ToolperfError("fixture_actions")
            if any(not isinstance(a, dict) or a.get("op") not in OPERATIONS
                   for a in actions):
                raise ToolperfError("fixture_operations")
    return cases


def _evaluate(case, actions):
    """An independent state oracle; executor claims never count as evidence."""
    started = time.perf_counter_ns()
    files = dict(case["initial_files"])
    events = []
    receipts = set()
    reads = set()
    errors = []
    output_bytes = 0
    claimed_success = False
    retries = 0
    for action in actions:
        op = action["op"]
        if action.get("retry") is True:
            retries += 1
        reason = None
        path = action.get("path")
        if op in ("read", "patch", "write", "check") and not _safe_path(path):
            reason = "INVALID_PATH"
        elif op == "claim":
            # An untrusted model response is never a receipt or a side effect.
            claimed_success = action.get("success") is True
        elif op == "run":
            # Never execute arbitrary inline code or call subprocess.
            reason = "INLINE_SCRIPT_DENIED"
        elif op == "list":
            visible = sorted(p for p in files if action.get("hidden") is True or
                             not any(part.startswith(".") for part in p.split("/")))
            size = len("\n".join(visible).encode("utf-8"))
            if output_bytes + size > case["output_budget"]:
                reason = "OUTPUT_LIMIT"
            else:
                output_bytes += size
        elif op == "read":
            offset = action.get("offset", 0)
            limit = action.get("limit", 128)
            if path not in files:
                reason = "NOT_FOUND"
            elif (type(offset) is not int or type(limit) is not int or
                  offset < 0 or limit < 1 or offset >= len(files[path])):
                reason = "INVALID_READ_RANGE"
            else:
                part = files[path][offset:offset + limit]
                size = len(part.encode("utf-8"))
                if size > case["output_budget"] or output_bytes + size > case["output_budget"]:
                    reason = "OUTPUT_LIMIT"
                else:
                    output_bytes += size
                    reads.add((path, offset))
        elif op in ("patch", "write"):
            if path not in case["allowed_writes"]:
                reason = "PATH_OUT_OF_SCOPE"
            elif op == "patch":
                old, new = action.get("old"), action.get("new")
                if path not in files or not isinstance(old, str) or not old or not isinstance(new, str):
                    reason = "INVALID_PATCH"
                elif files[path].count(old) != 1:
                    reason = ("AMBIGUOUS_PATCH" if files[path].count(old) > 1
                              else "PATCH_MISMATCH")
                elif len(files[path].replace(old, new, 1).encode("utf-8")) > 4096:
                    reason = "FILE_LIMIT"
                else:
                    files[path] = files[path].replace(old, new, 1)
            else:
                data = action.get("content")
                if not isinstance(data, str) or len(data.encode("utf-8")) > 4096:
                    reason = "FILE_LIMIT"
                else:
                    files[path] = data
        elif op == "env":
            if action.get("version") == "3.11":
                receipts.add("env-ok")
            else:
                reason = "PYTHON_ENV_MISMATCH"
        elif op == "check":
            if files.get(path) == action.get("expected") and path in files:
                receipts.add("check-ok")
            else:
                reason = "CHECK_FAILED"
        else:
            reason = "UNKNOWN_TOOL"
        events.append({"op": op, "status": "denied" if reason else "ok",
                       "error_class": reason})
        if reason:
            errors.append(reason)
            break

    if files != case["expected_files"]:
        errors.append("STATE_MISMATCH")
    if any((p, off) not in reads for p, offsets in case["required_reads"].items()
           for off in offsets):
        errors.append("MISSING_READ_RECEIPT")
    if not set(case["required_checks"]).issubset(receipts):
        errors.append("MISSING_CHECK_RECEIPT")
    if len(events) > case["call_budget"]:
        errors.append("EXCESS_TOOL_CALLS")
    if errors and claimed_success:
        errors.append("FALSE_SUCCESS_CLAIM")
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000, 4)
    return {
        "status": "PASS" if not errors else "FAIL",
        "tool_calls": len(events), "retries": retries,
        "error_classes": list(dict.fromkeys(errors)),
        "output_bytes": output_bytes, "elapsed_ms": elapsed_ms,
        "model": None, "tokens": None, "actual_cost": None,
    }


def run_case(case):
    baseline = _evaluate(case, case["baseline"])
    candidate = _evaluate(case, case["candidate"])
    if candidate["status"] != "PASS":
        verdict = "REGRESSED"
    elif baseline["status"] != "PASS":
        verdict = "FIXED"
    elif (candidate["tool_calls"] < baseline["tool_calls"] or
          candidate["output_bytes"] < baseline["output_bytes"]):
        verdict = "IMPROVED"
    else:
        verdict = "NO_GAIN"
    return {
        "task_id": case["task_id"], "category": case["category"],
        "fixture_sha256": fixture_sha256(case),
        "baseline": baseline, "candidate": candidate,
        "verdict": verdict,
    }


def run(*, sha=None, cases=None):
    if sha is not None and not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ToolperfError("invalid_repository_sha")
    dataset = load_cases() if cases is None else cases
    rows = [run_case(c) for c in dataset]
    return {
        "schema": SCHEMA, "dataset_version": VERSION, "repository_sha": sha,
        "mode": "synthetic_offline", "execution": "in_memory_no_tools",
        "results": rows,
        "candidate_passed": sum(x["candidate"]["status"] == "PASS" for x in rows),
        "task_count": len(rows), "model_effectiveness": "NOT_MEASURED",
        "live_tool_latency": "NOT_MEASURED",
        "live_tokens": None, "live_cost": None,
    }


def markdown(report):
    lines = [
        "### H-26 offline tool performance (synthetic only)",
        "",
        f"Exact SHA: \`{report['repository_sha'] or 'UNKNOWN'}\`; "
        f"fixtures: {report['task_count']}; candidate PASS: {report['candidate_passed']}.",
        "",
        "| Case | Baseline | Candidate | Calls B/C | Verdict |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in report["results"]:
        lines.append(
            f"| {r['task_id']} | {r['baseline']['status']} | "
            f"{r['candidate']['status']} | "
            f"{r['baseline']['tool_calls']}/{r['candidate']['tool_calls']} | "
            f"{r['verdict']} |")
    lines.extend(["", "No LLM/model/tool/device executed. Live latency, tokens and cost: NOT_MEASURED."])
    return "\n".join(lines) + "\n"
