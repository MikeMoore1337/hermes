"""Fail-closed, read-only admission policy for NEW Codex subscription tasks.

A decision is advisory: ALLOW is never an authorization to run a job.
The job launcher must separately check owner permission, task identity and
runtime gates immediately before dispatch. No queue, model call or billing here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any

from .codex_usage import SCHEMA, SOURCE, TTL_SECONDS

DEFAULT_WARNING_PERCENT = 20


def decision(snapshot: Any, *, now: datetime | None = None,
             threshold_percent: int = DEFAULT_WARNING_PERCENT) -> dict[str, Any]:
    """Return ALLOW, DEFER or UNKNOWN without inferring recovery from resetsAt."""
    if type(threshold_percent) is not int or not 0 <= threshold_percent <= 50:
        raise ValueError("threshold_percent must be an integer from 0 to 50")

    def result(value: str, reason: str, observed: str | None = None) -> dict[str, Any]:
        return {"decision": value, "reason": reason,
                "threshold_percent": threshold_percent, "observed_at": observed}

    if not isinstance(snapshot, dict) or snapshot.get("schema") != SCHEMA or snapshot.get("source") != SOURCE:
        return result("UNKNOWN", "snapshot_invalid")
    observed = snapshot.get("observed_at")
    if not isinstance(observed, str):
        return result("UNKNOWN", "observation_missing")
    try:
        moment = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("naive datetime")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("naive current time")
        age = (current.astimezone(timezone.utc) - moment.astimezone(timezone.utc)).total_seconds()
    except (ValueError, OverflowError, TypeError):
        return result("UNKNOWN", "observation_invalid")
    if not -120 <= age <= TTL_SECONDS:
        return result("UNKNOWN", "snapshot_stale", observed)

    status = snapshot.get("status")
    if status in ("stale", "unavailable", "not_configured", "unknown", "auth_required"):
        return result("UNKNOWN", "provider_" + status, observed)
    if status not in ("available", "low", "limited", "exhausted"):
        return result("UNKNOWN", "provider_status_invalid", observed)
    allowed = snapshot.get("ordinary_usage_allowed")
    if allowed is False:
        return result("DEFER", "ordinary_usage_denied", observed)
    if status in ("exhausted", "limited"):
        return result("DEFER", "provider_limit_reached", observed)
    if allowed is not True:
        return result("UNKNOWN", "ordinary_usage_unconfirmed", observed)

    limits = snapshot.get("limits")
    if not isinstance(limits, list) or not 1 <= len(limits) <= 24:
        return result("UNKNOWN", "quota_windows_missing", observed)
    remaining_values = []
    for group in limits:
        if not isinstance(group, dict) or group.get("status") not in ("available", "low", "exhausted"):
            return result("UNKNOWN", "quota_window_invalid", observed)
        windows = group.get("windows")
        if not isinstance(windows, list) or not 1 <= len(windows) <= 2:
            return result("UNKNOWN", "quota_window_invalid", observed)
        for window in windows:
            if not isinstance(window, dict):
                return result("UNKNOWN", "quota_window_invalid", observed)
            remaining = window.get("remaining_percent")
            if (type(remaining) not in (int, float) or not math.isfinite(remaining)
                    or not 0 <= remaining <= 100):
                return result("UNKNOWN", "quota_window_invalid", observed)
            remaining_values.append(remaining)
        if group["status"] == "exhausted":
            return result("DEFER", "provider_limit_reached", observed)

    if min(remaining_values) <= 0:
        return result("DEFER", "quota_exhausted", observed)
    if min(remaining_values) <= threshold_percent:
        return result("DEFER", "warning_threshold", observed)
    return result("ALLOW", "quotas_confirmed", observed)


def may_dispatch(result: dict[str, Any], *, task_authorized: bool) -> bool:
    """Launcher-facing contract: a quota decision alone never grants permission."""
    return task_authorized is True and isinstance(result, dict) and result.get("decision") == "ALLOW"
