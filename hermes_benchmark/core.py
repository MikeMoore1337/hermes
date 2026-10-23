"""Offline deterministic Hermes benchmark. No network, subprocess or model executor."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parent
TASK_SET_VERSION = "1"
VERIFIER_VERSION = "1"
BENCHMARK_VERSION = "1"
STATUSES = {"not_run", "passed", "failed", "infra_failure", "unverified"}
OUTCOMES = {"accepted", "rejected", "blocked"}
SAFE_BLOCKS = {
    "APPROVAL_DENIED", "QUOTA_DEFERRED", "QUOTA_UNKNOWN",
    "START_ACK_AMBIGUOUS", "TOOL_UNAVAILABLE", "TOOL_DENIED",
}
CATEGORIES = {
    "PATCH_MISMATCH": "correctness",
    "PATH_OUT_OF_SCOPE": "tool_boundary",
    "TEST_FAILED": "correctness",
    "UNVERIFIED_TEST_CLAIM": "evidence_integrity",
    "UNVERIFIED_CI_CLAIM": "evidence_integrity",
    "SHA_MISMATCH": "evidence_integrity",
    "FALSE_DELIVERY": "evidence_integrity",
    "APPROVAL_DENIED": "authorization",
    "TOOL_DENIED": "tool_boundary",
    "TOOL_UNAVAILABLE": "reliability",
    "QUOTA_DEFERRED": "reliability",
    "QUOTA_UNKNOWN": "reliability",
    "START_ACK_AMBIGUOUS": "recovery",
    "DUPLICATE_DISPATCH": "idempotency",
    "DOUBLE_CLAIM": "idempotency",
    "MISSING_EVIDENCE": "evidence_integrity",
    "TOOL_ERROR": "reliability",
    "INTERNAL_ERROR": "reliability",
}


class BenchmarkError(Exception):
    """An invalid fixture, comparable-run contract, or report destination."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _path(path: str) -> Path:
    # Require one unambiguous POSIX spelling for every fixture file. Otherwise
    # "src//task.txt" and "src/task.txt" can refer to the same file but have
    # different allowlist/evidence identities.
    if not isinstance(path, str) or not path or chr(0) in path:
        raise BenchmarkError("invalid_fixture_path")
    p = PurePosixPath(path)
    if (not p.parts or p.is_absolute() or p.as_posix() != path
            or any(part in (".", "..") for part in p.parts)
            or "\\" in path or ":" in path or p.parts[0].startswith(".")):
        raise BenchmarkError("invalid_fixture_path")
    return Path(*p.parts)


def load_cases(directory: Path | None = None) -> list[dict[str, Any]]:
    directory = directory or (ROOT / "fixtures")
    try:
        lock = json.loads((directory / "checksums-v1.json").read_text(encoding="utf-8"))
        cases = json.loads((directory / "tasks-v1.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BenchmarkError("fixture_read_failure") from exc
    if not isinstance(cases, list) or len(cases) != 16 or not isinstance(lock, dict):
        raise BenchmarkError("fixture_set_invalid")
    if set(lock) != {x.get("task_id") for x in cases if isinstance(x, dict)}:
        raise BenchmarkError("fixture_lock_mismatch")
    seen: set[str] = set()
    required = {
        "task_id", "task_version", "objective", "fixture_hash", "sandbox_state",
        "allowed_tools", "allowed_operations", "expected_evidence",
        "expected_outcome", "expected_reason", "verification_rules",
        "verifier_version", "timeout", "resource_limits", "simulation",
    }
    for case in cases:
        if not isinstance(case, dict) or set(case) != required:
            raise BenchmarkError("fixture_schema_invalid")
        ident = case["task_id"]
        if (not isinstance(ident, str) or not ident.startswith("hb-")
                or ident in seen or case["task_version"] != 1
                or case["verifier_version"] != VERIFIER_VERSION
                or case["expected_outcome"] not in OUTCOMES):
            raise BenchmarkError("fixture_version_invalid")
        seen.add(ident)
        pinned = digest({k: v for k, v in case.items() if k != "fixture_hash"})
        if case["fixture_hash"] != pinned or lock.get(ident) != pinned:
            raise BenchmarkError("fixture_hash_mismatch")
        if (type(case["timeout"]) is not int or not 1 <= case["timeout"] <= 30
                or case["resource_limits"] != {"max_files": 8, "max_actions": 12}
                or not isinstance(case["simulation"], list)
                or len(case["simulation"]) > 12
                or not isinstance(case["allowed_tools"], list)
                or not isinstance(case["allowed_operations"], list)
                or not isinstance(case["expected_evidence"], list)
                or not isinstance(case["verification_rules"], dict)
                or not isinstance(case["sandbox_state"], dict)):
            raise BenchmarkError("fixture_limits_invalid")
        initial = case["sandbox_state"].get("files", {})
        if not isinstance(initial, dict) or len(initial) > 8:
            raise BenchmarkError("fixture_files_invalid")
        for name, content in initial.items():
            _path(name)
            if not isinstance(content, str) or len(content) > 4096:
                raise BenchmarkError("fixture_file_invalid")
    return cases


class MockBus:
    """Trusted observation ledger for deterministic, built-in mock operations."""

    def __init__(self, case: dict[str, Any], workspace: Path):
        self.case = case
        self.workspace = workspace
        self.events: list[dict[str, Any]] = []
        self.receipts: dict[str, Any] = {}
        self.claim: dict[str, Any] = {}
        self.dispatch_count = 0
        self.lease_owner: str | None = None
        self.deliveries = 0
        self.errors: list[str] = []
        for name, content in case["sandbox_state"].get("files", {}).items():
            file = workspace / _path(name)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding="utf-8")

    def snapshot(self) -> dict[str, str]:
        observed: dict[str, str] = {}
        for file in sorted(self.workspace.rglob("*")):
            if file.is_symlink():
                raise BenchmarkError("sandbox_symlink")
            if file.is_file():
                if file.stat().st_size > 4096 or len(observed) >= 8:
                    raise BenchmarkError("sandbox_file_limit")
                observed[file.relative_to(self.workspace).as_posix()] = file.read_text(
                    encoding="utf-8")
        return observed

    def event(self, operation: str, status: str, reason: str = "OK") -> None:
        self.events.append({"seq": len(self.events) + 1, "op": operation,
                            "status": status, "reason": reason})

    def step(self, action: dict[str, Any]) -> None:
        if not isinstance(action, dict):
            raise BenchmarkError("invalid_simulation_step")
        op = action.get("op")
        if not isinstance(op, str):
            raise BenchmarkError("invalid_simulation_step")
        required_tool = {
            "write": "mock_git", "commit": "mock_git",
            "test": "mock_ci", "ci": "mock_ci",
            "deploy": "mock_deploy", "dispatch": "mock_scheduler",
            "start_uncertain": "mock_scheduler", "retry": "mock_scheduler",
            "save_result": "mock_scheduler", "deliver_result": "mock_scheduler",
            "claim_lease": "mock_scheduler", "unavailable": "mock_git",
            "error": "mock_git",
        }.get(op)
        if required_tool and required_tool not in self.case["allowed_tools"]:
            self.event(op, "denied", "TOOL_DENIED")
            return
        if op == "claim":
            # This is untrusted output, never itself a tool receipt.
            for key in ("tests_passed", "ci_passed", "commit_sha", "deployed"):
                if key in action:
                    self.claim[key] = action[key]
            return
        if op == "report_commit":
            self.claim["commit_sha"] = self.receipts.get("commit_sha")
            return
        if op == "tool":
            name = action.get("name", "")
            if name not in self.case["allowed_tools"]:
                self.event("tool", "denied", "TOOL_DENIED")
            else:
                self.event("tool", "ok")
            return
        if op == "write":
            name = action.get("path")
            if name not in self.case["allowed_operations"]:
                self.event("write", "denied", "TOOL_DENIED")
                return
            data = action.get("content")
            if not isinstance(data, str) or len(data) > 4096:
                raise BenchmarkError("invalid_simulation_data")
            file = self.workspace / _path(name)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(data, encoding="utf-8")
            self.event("write", "ok")
            return
        if op in ("test", "ci"):
            ok = self.snapshot().get("src/task.txt") == "fixed\n"
            self.receipts[op] = "pass" if ok else "fail"
            self.event(op, "ok" if ok else "failed", "OK" if ok else "TEST_FAILED")
            return
        if op == "commit":
            sha = digest({"base": "synthetic-base", "files": self.snapshot()})
            self.receipts["commit_sha"] = sha
            self.event("commit", "ok")
            return
        if op == "deploy":
            if not self.case["sandbox_state"].get("approval_active", False):
                self.event("deploy", "denied", "APPROVAL_DENIED")
            else:
                self.receipts["deploy"] = "synthetic-approved-receipt"
                self.event("deploy", "ok")
            return
        if op == "dispatch":
            state = self.case["sandbox_state"]
            if not state.get("approval_active", False):
                self.event("dispatch", "denied", "APPROVAL_DENIED")
            else:
                # Reuse #255's quota policy with a pinned clock;
                # never launch a real Codex/model call.
                from control_center.codex_policy import decision
                quota = decision(state.get("quota_snapshot"), now=datetime(
                    2026, 10, 18, tzinfo=timezone.utc))
                if quota["decision"] == "DEFER":
                    self.event("dispatch", "denied", "QUOTA_DEFERRED")
                elif quota["decision"] != "ALLOW":
                    self.event("dispatch", "denied", "QUOTA_UNKNOWN")
                else:
                    # Counts only mock admission; no actual model inference.
                    self.dispatch_count += 1
                    self.event("dispatch", "ok")
            return
        if op == "start_uncertain":
            self.receipts["start_uncertain"] = True
            self.dispatch_count += 1
            self.event("start_uncertain", "ok")
            return
        if op == "retry":
            if self.receipts.get("start_uncertain"):
                self.event("retry", "denied", "START_ACK_AMBIGUOUS")
            else:
                self.dispatch_count += 1
                self.event("retry", "ok")
            return
        if op == "save_result":
            self.receipts["saved_result"] = "synthetic-result-digest"
            self.event("save_result", "ok")
            return
        if op == "deliver_result":
            if "saved_result" not in self.receipts:
                self.event("deliver_result", "failed", "MISSING_EVIDENCE")
            else:
                self.deliveries += 1
                self.event("deliver_result", "ok")
            return
        if op == "claim_lease":
            owner = action.get("worker", "")
            if not isinstance(owner, str) or not owner:
                raise BenchmarkError("invalid_worker")
            if self.lease_owner is None:
                self.lease_owner = owner
                self.event("claim_lease", "ok")
            else:
                self.event("claim_lease", "denied", "LEASE_CONFLICT")
            return
        if op == "unavailable":
            self.event("github", "denied", "TOOL_UNAVAILABLE")
            return
        if op == "error":
            self.event("tool", "failed", "TOOL_ERROR")
            return
        raise BenchmarkError("unknown_simulation_operation")


def verify(case: dict[str, Any], bus: MockBus) -> dict[str, Any]:
    """Read the sandbox and trusted ledger, not the executor's success text."""
    rules = case["verification_rules"]
    errors: list[str] = []
    before = case["sandbox_state"].get("files", {})
    after = bus.snapshot()
    changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
    if changed - set(case["allowed_operations"]):
        errors.append("PATH_OUT_OF_SCOPE")
    expected_file = rules.get("expected_file")
    if expected_file is not None and after.get("src/task.txt") != expected_file:
        errors.append("PATCH_MISMATCH")
    if rules.get("require_tests") and bus.receipts.get("test") != "pass":
        errors.append("TEST_FAILED" if bus.receipts.get("test") == "fail" else "MISSING_EVIDENCE")
    if rules.get("require_ci") and bus.receipts.get("ci") != "pass":
        errors.append("TEST_FAILED" if bus.receipts.get("ci") == "fail" else "MISSING_EVIDENCE")
    if rules.get("require_commit") and not bus.receipts.get("commit_sha"):
        errors.append("MISSING_EVIDENCE")
    if bus.claim.get("tests_passed") is True and bus.receipts.get("test") != "pass":
        errors.append("UNVERIFIED_TEST_CLAIM")
    if bus.claim.get("ci_passed") is True and bus.receipts.get("ci") != "pass":
        errors.append("UNVERIFIED_CI_CLAIM")
    if "commit_sha" in bus.claim and bus.claim["commit_sha"] != bus.receipts.get("commit_sha"):
        errors.append("SHA_MISMATCH")
    if bus.claim.get("deployed") is True and "deploy" not in bus.receipts:
        errors.append("FALSE_DELIVERY")
    if rules.get("require_deploy") and "deploy" not in bus.receipts:
        errors.append("MISSING_EVIDENCE")
    if rules.get("require_saved_result") and not bus.receipts.get("saved_result"):
        errors.append("MISSING_EVIDENCE")
    if bus.dispatch_count > 1:
        errors.append("DUPLICATE_DISPATCH")
    claims = [e for e in bus.events if e["op"] == "claim_lease" and e["status"] == "ok"]
    if len(claims) > 1:
        errors.append("DOUBLE_CLAIM")
    if rules.get("require_one_lease") and len(claims) != 1:
        errors.append("MISSING_EVIDENCE")
    if rules.get("require_two_deliveries") and bus.deliveries != 2:
        errors.append("MISSING_EVIDENCE")
    for event in bus.events:
        if event["status"] in ("denied", "failed") and event["reason"] != "LEASE_CONFLICT":
            if event["reason"] not in errors:
                errors.append(event["reason"])
    # Safe denials have a separate outcome; a missing trusted artifact cannot be
    # repaired by an executor claim or by the expected outcome in the fixture.
    if errors and all(reason in SAFE_BLOCKS for reason in errors):
        observed = "blocked"
    elif errors:
        observed = "rejected"
    else:
        observed = "accepted"
    reason = errors[0] if errors else "OK"
    missing = {"test": "test", "ci": "ci", "commit": "commit_sha",
               "deploy": "deploy", "result": "saved_result"}
    expected = case["expected_evidence"]
    available = sum(bool(bus.receipts.get(missing[item])) for item in expected
                    if item in missing)
    completeness = round(available / len(expected), 4) if expected else 1.0
    return {"observed_outcome": observed, "reason_code": reason, "errors": errors,
            "failure_category": CATEGORIES.get(reason) if reason != "OK" else None,
            "evidence_completeness": completeness,
            "tool_calls": len(bus.events),
            "synthetic_dispatches": bus.dispatch_count,
            "changed_paths": sorted(changed),
            "audit_digest": digest(bus.events),
            "state_digest": digest(after)}


def execute_case(case: dict[str, Any]) -> dict[str, Any]:
    start = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="hermes-benchmark-") as name:
            bus = MockBus(case, Path(name))
            for index, step in enumerate(case["simulation"]):
                if (index >= case["resource_limits"]["max_actions"]
                        or time.monotonic() - start >= case["timeout"]):
                    raise BenchmarkError("synthetic_execution_limit")
                bus.step(step)
                if time.monotonic() - start >= case["timeout"]:
                    raise BenchmarkError("synthetic_execution_timeout")
            observed = verify(case, bus)
        matched = (observed["observed_outcome"] == case["expected_outcome"] and
                   observed["reason_code"] == case["expected_reason"])
        status = "passed" if matched else "failed"
        if observed["reason_code"] == "MISSING_EVIDENCE" and not matched:
            status = "unverified"
        payload = {**observed, "status": status, "score": 1 if matched else 0}
    except (OSError, ValueError, BenchmarkError, UnicodeError):
        payload = {"observed_outcome": None, "reason_code": "INTERNAL_ERROR",
                   "errors": ["INTERNAL_ERROR"], "failure_category": "reliability",
                   "evidence_completeness": None, "tool_calls": None,
                   "synthetic_dispatches": None, "changed_paths": [],
                   "audit_digest": None, "state_digest": None,
                   "status": "infra_failure", "score": None}
    result = {
        "task_id": case["task_id"], "task_version": case["task_version"],
        "fixture_hash": case["fixture_hash"], "verifier_version": VERIFIER_VERSION,
        "executor_type": "offline_synthetic", "model": None, "effort": None,
        "runtime_version": None, "codex_cli_version": None,
        "tokens": None, "actual_cost": None,
        **payload, "duration": round(time.monotonic() - start, 6),
    }
    result["result_digest"] = digest({
        key: value for key, value in result.items() if key not in
        ("result_digest", "duration")
    })
    return result


def run(*, selected: set[str] | None = None,
        sha: str | None = None, fixture_dir: Path | None = None) -> dict[str, Any]:
    cases = load_cases(fixture_dir)
    ids = {case["task_id"] for case in cases}
    if selected is not None and (not selected or selected - ids):
        raise BenchmarkError("unknown_case_id")
    results = []
    for case in cases:
        if selected is not None and case["task_id"] not in selected:
            results.append({"task_id": case["task_id"], "task_version": 1,
                            "fixture_hash": case["fixture_hash"],
                            "verifier_version": VERIFIER_VERSION,
                            "status": "not_run", "score": None,
                            "model": None, "effort": None, "tokens": None,
                            "actual_cost": None, "duration": None})
        else:
            results.append(execute_case(case))
    if sha and (len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha)):
        raise BenchmarkError("invalid_commit_sha")
    report = {
        "benchmark_version": BENCHMARK_VERSION, "task_set_version": TASK_SET_VERSION,
        "verifier_version": VERIFIER_VERSION,
        "mode": "offline_synthetic",
        "run_id": __import__("uuid").uuid4().hex,
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "hermes_commit_sha": sha,
        "task_count": len(cases),
        **{state: sum(r["status"] == state for r in results) for state in sorted(STATUSES)},
        "results": results,
    }
    report["aggregate_digest"] = digest([r.get("result_digest") for r in results])
    return report


def summary(report: dict[str, Any]) -> str:
    lines = ["# Hermes Agent Benchmark (offline synthetic)",
             "", "| Result | Count |", "| --- | ---: |"]
    for key in ("passed", "failed", "unverified", "infra_failure", "not_run"):
        lines.append(f"| {key} | {report[key]} |")
    lines.extend(["", "Synthetic checks only; real Hermes/LLM quality is not measured.",
                  "", "| Case | Status | Reason |", "| --- | --- | --- |"])
    for row in report["results"]:
        lines.append("| {} | {} | {} |".format(row["task_id"], row["status"],
                                              row.get("reason_code", "-")))
    return "\n".join(lines) + "\n"


def compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    for field in ("task_set_version", "verifier_version", "benchmark_version"):
        if old.get(field) != new.get(field):
            raise BenchmarkError("incompatible_" + field)
    left = {r["task_id"]: r for r in old["results"]}
    right = {r["task_id"]: r for r in new["results"]}
    if left.keys() != right.keys() or any(
        left[k].get("fixture_hash") != right[k].get("fixture_hash") for k in left
    ):
        raise BenchmarkError("incompatible_fixtures")
    # Never interpret unexecuted/unknown results as successes or failures.
    regressions = sorted(k for k in left if left[k]["status"] == "passed"
                         and right[k]["status"] != "passed")
    fixes = sorted(k for k in left if left[k]["status"] != "passed"
                   and right[k]["status"] == "passed")
    return {"task_set_version": new["task_set_version"],
            "verifier_version": new["verifier_version"],
            "passed_before": sum(r["status"] == "passed" for r in left.values()),
            "passed_after": sum(r["status"] == "passed" for r in right.values()),
            "regressions": regressions, "fixed": fixes,
            "duration_delta_seconds": {
                k: round(right[k]["duration"] - left[k]["duration"], 6)
                for k in left if isinstance(right[k].get("duration"), (int, float))
                and isinstance(left[k].get("duration"), (int, float))},
            "evidence_delta": {
                k: round(right[k]["evidence_completeness"] -
                         left[k]["evidence_completeness"], 4)
                for k in left
                if isinstance(right[k].get("evidence_completeness"), (int, float))
                and isinstance(left[k].get("evidence_completeness"), (int, float))}}


def save(report: dict[str, Any], directory: Path, *, retention: int = 20) -> None:
    if not 1 <= retention <= 100:
        raise BenchmarkError("retention_invalid")
    if directory.is_symlink():
        raise BenchmarkError("report_symlink")
    directory.mkdir(parents=True, exist_ok=True)
    for label, content in (("report.json", json.dumps(report, sort_keys=True, indent=2)),
                           ("summary.md", summary(report))):
        target = directory / label
        if target.is_symlink():
            raise BenchmarkError("report_symlink")
        temporary = directory / (label + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                stream.write(content + ("" if content.endswith("\n") else "\n"))
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    # Optional bounded local history, no recursion into arbitrary paths.
    hist = directory / "history"
    if hist.is_symlink():
        raise BenchmarkError("report_symlink")
    hist.mkdir(exist_ok=True)
    target = hist / (report["run_id"] + ".json")
    target.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    entries = sorted((p for p in hist.glob("*.json") if p.is_file() and
                      not p.is_symlink()), key=lambda p: p.stat().st_mtime_ns)
    for stale in entries[:-retention]:
        stale.unlink()
