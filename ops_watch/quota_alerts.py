"""Read-only, allowlisted quota status for Ops Watch. No model/API requests.

Codex #255 already owns its independent Ops Watch alert semantics. Workers AI
historical billing is too stale for a real-time alarm or quota admission.
These signals concern fresh Desktop Commander and configured-token GitHub.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from control_center.provider_registry import registry
from control_center.codex_usage import DEFAULT_OUTPUT as CODEX
from control_center.desktop_commander import DEFAULT_OUTPUT as DESKTOP
from control_center.cloudflare_billing import OUTPUT as CLOUDFLARE
from control_center.github_rate_limit import OUTPUT as GITHUB

PROVIDERS = ("desktop_commander", "github_api")
ALLOWED = frozenset({"not_connected", "unknown", "auth_required", "stale",
                     "healthy", "warn80", "warn95", "exhausted"})


def observe(*, now:datetime|None=None, paths:dict[str,Path]|None=None)->dict[str,str]:
    paths = paths or {"codex":CODEX,"desktop":DESKTOP,
                       "cloudflare":CLOUDFLARE,"github":GITHUB}
    actual=registry(
        codex_path=paths["codex"],desktop_path=paths["desktop"],
        cloudflare_path=paths["cloudflare"],github_path=paths["github"],
        now=now or datetime.now(UTC))["providers"]
    by_id={item["id"]:item for item in actual}
    states={}
    for provider in PROVIDERS:
        row=by_id[provider]
        status=row["status"]
        if status in ("not_connected","auth_required","stale","unknown","throttled"):
            states[provider] = status if status in ALLOWED else "unknown"
            continue
        values=[window.get("used_percent") for window in row["windows"]]
        values=[value for value in values if type(value) in (int,float) and 0<=value<=100]
        if not values:
            states[provider] = "exhausted" if status=="exhausted" else "unknown"
            continue
        high=max(values)
        states[provider]="exhausted" if high>=100 or status=="exhausted" else (
            "warn95" if high>=95 else "warn80" if high>=80 else "healthy")
    return states
