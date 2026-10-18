"""Offline, fail-closed H-10 permission/budget policy for future agent designs.

Policy is NOT a runtime, not a provider adapter, not a payment service,
and does not confer OS/Git/Telegram privileges. No network or secrets.
"""
from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CONTRACT = Path(__file__).with_name("policy.json")
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{1,39}\Z")
PERMITTED_ROLES = ("analyst", "planner", "proposer")
ROLE_ACTIONS = {
    "analyst": frozenset({"classify_sanitized_codes"}),
    "planner": frozenset({"plan_from_public_metadata"}),
    "proposer": frozenset({"draft_without_delivery"}),
}
ALLOWED_OFFLINE_ACTIONS = frozenset({
    "classify_sanitized_codes",
    "plan_from_public_metadata",
    "draft_without_delivery",
})
DENIED_EFFECTS = frozenset({
    "shell", "browser", "mcp", "git_write", "github_write", "telegram_send",
    "publish", "deploy", "database_write", "read_private_vault",
    "restart_service", "new_provider", "paid_fallback",
})
ALLOWED_KINDS = frozenset({"offline", "model"})
MAX_DURATION_SECONDS = 205
MAX_CALLS = 1
MAX_RETRIES = 0


class BudgetDenied(ValueError):
    """Static local refusal, never include model output or token."""


def validate(data: object) -> dict[str, Any]:
    if type(data) is not dict or set(data) != {
        "schema", "runtime_enabled", "provider_billing_verified",
        "daily_spend_cap_usd", "model_calls_per_job", "retries_per_job",
        "timeout_seconds", "roles", "allowed_actions",
    }:
        raise BudgetDenied("invalid_policy_schema")
    if data["schema"] != "hermes-role-budget-v1":
        raise BudgetDenied("invalid_policy_version")
    if type(data["runtime_enabled"]) is not bool or type(data["provider_billing_verified"]) is not bool:
        raise BudgetDenied("invalid_policy_flags")
    if type(data["daily_spend_cap_usd"]) not in (int, float) or data["daily_spend_cap_usd"] != 0:
        raise BudgetDenied("nonzero_or_invalid_spend_budget")
    if type(data["model_calls_per_job"]) is not int or not 0 <= data["model_calls_per_job"] <= MAX_CALLS:
        raise BudgetDenied("invalid_model_call_limit")
    if type(data["retries_per_job"]) is not int or data["retries_per_job"] != MAX_RETRIES:
        raise BudgetDenied("automatic_retry_denied")
    if type(data["timeout_seconds"]) is not int or not 1 <= data["timeout_seconds"] <= MAX_DURATION_SECONDS:
        raise BudgetDenied("time_limit_outside_safe_bounds")
    roles = data["roles"]
    if type(roles) is not dict or set(roles) != set(PERMITTED_ROLES):
        raise BudgetDenied("unknown_role")
    for role, operations in roles.items():
        if type(operations) is not list or len(operations) > 3 or len(set(map(str, operations))) != len(operations):
            raise BudgetDenied("invalid_role_permissions")
        if not all(type(op) is str and op in ROLE_ACTIONS[role] for op in operations):
            raise BudgetDenied("role_permission_denied")
    actions = data["allowed_actions"]
    if type(actions) is not list or len(set(map(str, actions))) != len(actions):
        raise BudgetDenied("invalid_actions")
    if not all(type(action) is str and action in ALLOWED_OFFLINE_ACTIONS for action in actions):
        raise BudgetDenied("action_not_approved")
    if any(op not in actions for granted in roles.values() for op in granted):
        raise BudgetDenied("role_not_in_global_allowlist")
    return data


def load(path: Path = CONTRACT) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
        raise BudgetDenied("unsafe_policy_file")
    try:
        with path.open("r", encoding="utf-8") as source:
            return validate(json.load(source, object_pairs_hook=_reject_duplicate_fields))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BudgetDenied("policy_unreadable") from None


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BudgetDenied("duplicate_policy_key")
        result[key] = value
    return result


def authorize(
    policy: dict[str, Any], *, role: str, action: str, kind: str,
    expected_calls: int, estimated_cost_usd: float | None,
    quota_remaining: int | None, owner_approved: bool,
) -> dict[str, object]:
    """Admit an offline task; never allow model calls without independent GO."""
    config = validate(policy)
    if type(role) is not str or role not in config["roles"]:
        raise BudgetDenied("role_unknown")
    if type(action) is not str or action not in ALLOWED_OFFLINE_ACTIONS or action not in config["roles"][role]:
        raise BudgetDenied("permission_denied")
    if type(kind) is not str or kind not in ALLOWED_KINDS:
        raise BudgetDenied("execution_kind_denied")
    if type(expected_calls) is not int or not 0 <= expected_calls <= config["model_calls_per_job"]:
        raise BudgetDenied("call_limit_exceeded")
    if kind == "offline":
        if expected_calls != 0 or estimated_cost_usd != 0:
            raise BudgetDenied("offline_must_have_zero_cost_and_calls")
        return {"status": "ALLOWED_OFFLINE", "side_effect": "none", "model_calls": 0}
    if owner_approved is not True:
        raise BudgetDenied("owner_approval_required")
    if config["runtime_enabled"] is not True or config["provider_billing_verified"] is not True:
        raise BudgetDenied("runtime_or_billing_gate_closed")
    if type(quota_remaining) is not int or quota_remaining <= 0:
        raise BudgetDenied("unknown_or_exhausted_provider_quota")
    if type(estimated_cost_usd) not in (int, float) or not estimated_cost_usd == 0:
        raise BudgetDenied("unknown_or_nonzero_provider_cost")
    if expected_calls != 1:
        raise BudgetDenied("model_call_count_invalid")
    return {"status": "ELIGIBLE_BY_LOCAL_POLICY_ONLY", "side_effect": "none", "model_calls": 1}


def verify_metrics(metrics: object) -> dict[str, object]:
    """Record only observed counters; unknown token/cost values are not estimates."""
    if type(metrics) is not dict or set(metrics) != {
        "duration_seconds", "attempts", "input_tokens", "output_tokens",
        "provider_neurons", "provider_cost_usd", "http_status",
    }:
        raise BudgetDenied("metrics_schema_invalid")
    duration = metrics["duration_seconds"]
    if type(duration) not in (float, int) or not 0 <= duration <= MAX_DURATION_SECONDS:
        raise BudgetDenied("duration_invalid")
    if type(metrics["attempts"]) is not int or not 0 <= metrics["attempts"] <= 1:
        raise BudgetDenied("attempts_invalid")
    for name in ("input_tokens", "output_tokens", "provider_neurons"):
        value = metrics[name]
        if value is not None and (type(value) is not int or not 0 <= value <= 1_000_000):
            raise BudgetDenied("counter_invalid")
    spent = metrics["provider_cost_usd"]
    if spent is not None and (
        type(spent) not in (float, int) or spent < 0
        or (type(spent) is float and not math.isfinite(spent))
    ):
        raise BudgetDenied("cost_invalid")
    status = metrics["http_status"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise BudgetDenied("http_status_invalid")
    if status is not None and metrics["attempts"] != 1:
        # A self-reported HTTP response without any attempted request cannot
        # prove a real zero-cost operation, even with a forged 200 and $0.
        raise BudgetDenied("http_attempts_inconsistent")
    if status is None:
        # An omitted HTTP result is not evidence of a successful free request.
        return {"status": "UNKNOWN_PROVIDER_STATUS",
                "reason": "provider_result_not_observed"}
    if status != 200:
        # A 3xx (potential redirect), 4xx (all client errors), or 5xx
        # never proves a successful bill-free model call.
        return {"status": "STOP_NO_RETRY", "reason": "provider_error_or_quota"}
    if spent is None:
        return {"status": "UNKNOWN_SPEND", "reason": "provider_cost_not_observed"}
    if spent != 0:
        return {"status": "STOP_NONZERO_COST", "reason": "zero_dollar_budget_breached"}
    return {"status": "MEASURED_ZERO_RECORDED", "reason": "does_not_verify_account_billing"}


def main() -> int:
    try:
        config = load()
    except BudgetDenied as exc:
        print(json.dumps({"status": "INVALID", "reason": str(exc)}))
        return 2
    print(json.dumps({
        "status": "VALID_OFFLINE",
        "resident_agent_enabled": config["runtime_enabled"],
        "provider_billing_verified": config["provider_billing_verified"],
        "daily_spend_cap_usd": config["daily_spend_cap_usd"],
        "role_count": len(config["roles"]),
        "no_runtime_created": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
