"""#295 per-provider read-only quota registry, with no billing or inference calls.

Only existing owner-authorized local snapshots can provide account use.
Documented Cloudflare daily *limit* is not observed Cloudflare account usage.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from control_center.cloudflare_billing import (
    OUTPUT as CLOUDFLARE_BILLING_PATH,
    snapshot as read_cloudflare_billing,
)
from control_center.codex_usage import (
    DEFAULT_OUTPUT as CODEX_PATH, UsageError,
    read_snapshot as read_codex_snapshot,
)
from control_center.desktop_commander import (
    DEFAULT_OUTPUT as DC_PATH, CommanderError,
    read_snapshot as read_desktop_snapshot,
)

SCHEMA = 1
PROVIDERS = ("cloudflare_workers_ai", "codex", "desktop_commander", "github_api")
NEURONS_DAILY_FREE = 10_000
CLOUDFLARE_DOCS = "https://developers.cloudflare.com/workers-ai/platform/pricing/"


def timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _pct(value: object) -> float | None:
    if type(value) not in (int, float) or not 0 <= value <= 100:
        return None
    return round(float(value), 2)


def empty(provider: str, title: str, *, configured: bool = False) -> dict:
    return {
        "id": provider, "title": title,
        "status": "unknown" if configured else "not_connected",
        "observed_at": None, "source_kind": "unknown",
        "confidence": "none", "windows": [],
        "notes": "usage_not_exposed" if configured else "not_configured",
    }


def _window(*, metric: str, label: str, unit: str, limit: int | None = None,
            used: float | None = None, remaining: float | None = None,
            used_percent: float | None = None,
            remaining_percent: float | None = None,
            reset_at_utc: str | None = None,
            source_kind: str = "unknown") -> dict:
    return {
        "metric": metric, "label": label, "unit": unit,
        "quota_limit": limit, "used": used, "remaining": remaining,
        "used_percent": used_percent, "remaining_percent": remaining_percent,
        "reset_at_utc": reset_at_utc, "source_kind": source_kind,
    }


def registry(*, codex_path: Path = CODEX_PATH, desktop_path: Path = DC_PATH,
             cloudflare_path: Path = CLOUDFLARE_BILLING_PATH,
             now: dt.datetime | None = None) -> dict:
    moment = now or dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("timezone_required")
    utc = moment.astimezone(dt.timezone.utc)
    next_reset = (utc.date() + dt.timedelta(days=1)).isoformat() + "T00:00:00Z"

    # Confirmed Free-only contract of this Hermes deployment; NOT a claim of
    # access to Cloudflare account-wide billing data or recent AI success.
    cloudflare = empty("cloudflare_workers_ai", "Cloudflare Workers AI", configured=True)
    cloudflare["notes"] = "account_usage_unavailable"
    # Published invoice/account usage is delayed by a day or more. Expose
    # completed historical days only. Never subtract these from today's Free
    # allowance or infer an account-wide CURRENT remaining balance.
    bill = read_cloudflare_billing(cloudflare_path, now=utc)
    cloudflare["billing_history"] = bill["days"] if bill["status"] == "ok" else []
    cloudflare["billing_observed_at"] = bill["observed_at"] if bill["status"] == "ok" else None
    cloudflare["billing_last_complete_day"] = (
        bill["last_complete_day"] if bill["status"] == "ok" else None
    )
    if cloudflare["billing_history"]:
        cloudflare["notes"] = "official_delayed_historical_usage"
    cloudflare["limit_documentation"] = CLOUDFLARE_DOCS
    cloudflare["windows"] = [
        _window(metric="neurons_daily", label="Суточная квота Free",
                unit="neurons", limit=NEURONS_DAILY_FREE,
                reset_at_utc=next_reset, source_kind="unknown")
    ]

    codex = empty("codex", "Codex / ChatGPT")
    try:
        raw = read_codex_snapshot(codex_path, now=utc)
    except (UsageError, OSError, PermissionError):
        raw = {"status": "unavailable", "observed_at": None, "limits": []}
    status = raw["status"]
    codex["status"] = {
        "available": "ok", "low": "low", "limited": "low",
        "exhausted": "exhausted", "auth_required": "auth_required",
        "stale": "stale", "not_configured": "not_connected",
        "unknown": "unknown", "unavailable": "unknown",
    }.get(status, "unknown")
    codex["observed_at"] = timestamp(raw.get("observed_at"))
    codex["source_kind"] = "official_api" if status in (
        "available", "low", "limited", "exhausted") else "unknown"
    codex["confidence"] = "account_observed" if codex["source_kind"] == "official_api" else "none"
    codex["notes"] = {
        "exhausted": "provider_limit_exhausted",
        "limited": "some_windows_exhausted",
        "auth_required": "reauthorization_required",
        "stale": "snapshot_stale",
    }.get(status, "official_account_snapshot" if codex["source_kind"] == "official_api" else "usage_unavailable")
    if status in ("available", "low", "limited", "exhausted"):
        for group in raw.get("limits", [])[:24]:
            for index, window in enumerate(group.get("windows", [])[:2]):
                percent = _pct(window.get("used_percent"))
                remain = _pct(window.get("remaining_percent"))
                if percent is None or remain is None:
                    continue
                reset = window.get("resets_at")
                reset_at = None
                if isinstance(reset, int) and not isinstance(reset, bool) and 0 < reset <= 253402300799:
                    reset_at = dt.datetime.fromtimestamp(reset, dt.timezone.utc).isoformat().replace("+00:00", "Z")
                duration = window.get("duration_minutes")
                name = "Окно " + str(index + 1)
                if isinstance(duration, int) and not isinstance(duration, bool) and duration > 0:
                    name = f"{duration} мин"
                codex["windows"].append(
                    _window(metric="subscription_share", label=name,
                            unit="percent", used_percent=percent,
                            remaining_percent=remain, reset_at_utc=reset_at,
                            source_kind="official_api")
                )

    desktop = empty("desktop_commander", "Desktop Commander")
    try:
        dc = read_desktop_snapshot(desktop_path, now=utc)
    except (CommanderError, OSError, PermissionError):
        dc = {"status": "unavailable", "observed_at": None,
              "quota_remaining_percent": None, "remote_execution": "unverified"}
    state = dc.get("status")
    pct = _pct(dc.get("quota_remaining_percent"))
    desktop["observed_at"] = timestamp(dc.get("observed_at"))
    desktop["status"] = {
        "monitored": "unknown" if pct is None else "exhausted" if pct == 0 else "ok" if pct > 20 else "low",
        "exhausted": "exhausted", "stale": "stale",
        "not_configured": "not_connected", "unavailable": "unknown",
        "auth_required": "auth_required", "unknown": "unknown",
    }.get(state, "unknown")
    desktop["source_kind"] = "local_meter" if state in ("monitored", "exhausted") and pct is not None else "unknown"
    desktop["confidence"] = "provider_reported" if desktop["source_kind"] == "local_meter" else "none"
    desktop["notes"] = "remote_calls_blocked" if state == "exhausted" else (
        "device_presence_not_execution_permission" if state == "monitored" else "usage_unavailable")
    if pct is not None and state in ("monitored", "exhausted"):
        desktop["windows"] = [
            _window(metric="remote_calls", label="Удалённые вызовы",
                    unit="percent", used_percent=100 - pct,
                    remaining_percent=pct, source_kind="local_meter")
        ]

    # GitHub is genuinely used in Hermes CI/CD, but GitHub's rate-limit
    # headers are scoped to each token/resource; no official account-wide
    # meter is present in the Control Center. Never invent a shared budget.
    github = empty("github_api", "GitHub API", configured=True)
    github["notes"] = "per_token_rate_limit_not_collected"

    return {
        "schema": SCHEMA,
        "read_only": True,
        "observed_at": utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "providers": [cloudflare, codex, desktop, github],
    }
