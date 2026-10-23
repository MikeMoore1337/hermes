"""Opt-in H-453 comparison: one vs two isolated, tool-free model calls.

This is NOT native Hermes delegate_task, not two autonomous subagents.
No background services, no MCP, no file tools, no new provider, no retries.
Use only an operator-attested Free account on an authorized local executor.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

from agent_budget.pilot import (
    CloudflareFreeProvider, MAX_DAILY_LOCAL_CALLS, PilotError,
    QUOTA_RESERVE_NEURONS, _load_state, _prepared_case, _run_lock,
    _write_json_atomic, load_account_status,
)
from ops_watch.incident_advisor import evaluate_result, validate_result

CASES = ("ops:provider_http_429", "ops:healthy_no_publications")
ROLES = ("signal", "safety")
SCHEMA = "hermes-h453-tool-free-ab-v1"
ROLE_HINTS = {
    "single": "Проверь все ограничения H-A1..H-A5 для этого события.",
    "signal": "Независимо проверь сигнал, состояние инцидента, признаки восстановления и доказательства.",
    "safety": "Независимо проверь ограничение доверия, неподтверждённые факты и запреты действий.",
}


def _client(attestation: dict[str, object]) -> CloudflareFreeProvider:
    return CloudflareFreeProvider.from_environment(attestation)


def _one(role: str, prompt: str, context: dict[str, object], client: CloudflareFreeProvider) -> dict[str, object]:
    started = time.perf_counter()
    response = client.complete(prompt + "\n\n" + ROLE_HINTS[role])
    # Fail closed before admitting another stage if real zero-cost is unknown.
    if type(response.provider_cost_usd) not in (float, int) or response.provider_cost_usd != 0:
        raise PilotError("cost_not_verified_zero")
    result = validate_result(response.content, context)
    quality = evaluate_result(context, result)
    return {
        "role": role,
        "local_invocation_id": uuid4().hex,
        "provider_request_id": "NOT_REPORTED",
        "result": result,
        "quality": quality,
        "metrics": {
            "wall_seconds": round(time.perf_counter() - started, 6),
            "provider_seconds": response.duration_seconds,
            "attempts": response.attempts,
            "http_status": response.http_status,
            "input_tokens": response.input_tokens if response.input_tokens is not None else "NOT_REPORTED",
            "output_tokens": response.output_tokens if response.output_tokens is not None else "NOT_REPORTED",
            "provider_neurons": response.provider_neurons if response.provider_neurons is not None else "NOT_REPORTED",
            "provider_cost_usd": response.provider_cost_usd,
        },
    }


def run(*, case: str, account_status: Path, state: Path, output: Path, owner_approved: bool) -> dict[str, object]:
    if not owner_approved or os.getenv("HERMES_AI_LIVE_APPROVED") != "1":
        raise PilotError("owner_approval_required")
    if case not in CASES:
        raise PilotError("case_not_allowlisted")
    if (state.resolve() == output.resolve() or account_status.resolve() == output.resolve()
            or account_status.resolve() == state.resolve()
            or output.is_symlink() or state.is_symlink() or output.exists()):
        raise PilotError("unsafe_state_output")
    attestation = load_account_status(account_status)
    if attestation["daily_neurons_remaining"] < 3 * QUOTA_RESERVE_NEURONS:
        raise PilotError("insufficient_free_quota_for_three_calls")
    task, case_id, provenance, context, prompt, _ = _prepared_case(case)
    if task != "ops":
        raise PilotError("non_ops_case_denied")
    # Construct and authenticate all clients before reserving any external call.
    clients = [_client(attestation) for _ in range(3)]
    with _run_lock(state):
        ledger = _load_state(state)
        if ledger["calls"] + 3 > MAX_DAILY_LOCAL_CALLS:
            raise PilotError("daily_local_call_cap")
        if ledger["date"] != datetime.now(UTC).date().isoformat():
            raise PilotError("utc_day_changed")
        ledger["calls"] += 3
        # Durable debit before any possible request; no retry or refund on error.
        _write_json_atomic(state, ledger)
        started = time.perf_counter()
        single = _one("single", prompt, context, clients[0])
        after_single = time.perf_counter()
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="h453-readonly") as pool:
            jobs = [pool.submit(_one, role, prompt, context, clients[i + 1])
                    for i, role in enumerate(ROLES)]
            # Collect both outcomes; no second attempts after any error.
            children = [job.result() for job in jobs]
        elapsed = time.perf_counter() - started
        report = {
            "schema": SCHEMA,
            "case": case,
            "case_id": case_id,
            "provenance": provenance,
            "model": "@cf/openai/gpt-oss-20b",
            "execution": "LIVE_TOOL_FREE_REQUESTS_NOT_NATIVE_DELEGATION",
            "provider_dispatches_reserved": 3,
            "automatic_retries": 0,
            "agent_tools_enabled": False,
            "a_single": single,
            "b_independent_requests": children,
            "metrics": {
                "a_wall_seconds": round(after_single - started, 6),
                "b_wall_seconds": round(elapsed - (after_single - started), 6),
                "total_wall_seconds": round(elapsed, 6),
                "usage_source": "PROVIDER_RESPONSE_IF_REPORTED",
            },
        }
        _write_json_atomic(output, report)
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-453 bounded tool-free model A/B; NOT native Hermes subagents")
    parser.add_argument("--run-live", action="store_true")
    parser.add_argument("--owner-approved", action="store_true")
    parser.add_argument("--case", choices=CASES, default=CASES[0])
    parser.add_argument("--account-status", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.run_live:
        print(json.dumps({"schema": SCHEMA, "live": False, "cases": CASES, "model_calls": 0}))
        return 0
    try:
        if not all((args.account_status, args.state, args.output)):
            raise PilotError("account_status_state_output_required")
        result = run(case=args.case, account_status=args.account_status, state=args.state,
                     output=args.output, owner_approved=args.owner_approved)
        print(json.dumps({"status": "PASS", "report": str(args.output), "schema": result["schema"]}))
        return 0
    except (PilotError, ValueError, OSError) as exc:
        print("H453_FAIL_CLOSED=" + type(exc).__name__ + ":" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
