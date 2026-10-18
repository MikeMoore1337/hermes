"""Read-only, allowlisted quota status for Ops Watch. No model/API requests.

Codex #255 already owns its independent Ops Watch alert semantics. Workers AI
historical billing is too stale for a real-time alarm or quota admission.
These signals concern fresh Desktop Commander and configured-token GitHub.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from importlib.util import find_spec
import re
import stat
import sys


def trusted_provider_release(*, ui_root: Path = Path("/opt/hermes-control-center"),
                             owner_root: Path = Path("/opt/hermes-agent-owner"),
                             expected_uid: int = 0) -> Path:
    """Resolve only the pinned, root-owned UI release when running on the VPS.

    Ops Watch runs from /opt/hermes-agent-owner. That directory deliberately
    does not contain the control_center package: the deploy handler places it
    in /opt/hermes-control-center/releases/main-<sha>/control_center.
    Never import from a mutable temp path or an unverified symlink target.
    """
    try:
        canonical_ui = ui_root.resolve(strict=True)
        release = (ui_root / "current").resolve(strict=True)
        canonical_releases = (ui_root / "releases").resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("provider_release_unavailable") from exc
    if (canonical_ui != ui_root or release.parent != canonical_releases
            or not re.fullmatch(r"main-[0-9a-f]{40}", release.name)):
        raise RuntimeError("provider_release_untrusted")
    owner_release = owner_root / "releases" / release.name
    # Match the deployment's exact source tree; never silently import a
    # package from a different SHA than the Ops Watch release.
    required = (
        ui_root, canonical_releases, release, release / "control_center",
        release / "control_center" / "__init__.py",
        release / "control_center" / "provider_registry.py",
        owner_root, owner_root / "releases", owner_release,
        owner_release / "ops_watch" / "quota_alerts.py",
    )
    try:
        for path in required:
            if path.is_symlink():
                raise RuntimeError("provider_release_untrusted")
            meta = path.stat(follow_symlinks=False)
            if meta.st_uid != expected_uid or meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError("provider_release_untrusted")
        if not (release / "control_center" / "provider_registry.py").is_file():
            raise RuntimeError("provider_release_untrusted")
        if not (owner_release / "ops_watch" / "quota_alerts.py").is_file():
            raise RuntimeError("provider_release_untrusted")
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("provider_release_untrusted") from exc
    return release


def _bind_control_center() -> None:
    # Full monorepo layout (CI/developer): import the existing canonical
    # package; never modify search paths in ordinary offline tests.
    if find_spec("control_center") is not None:
        return
    # Production split-root layout: add exactly one validated, root-owned
    # immutable release. No credentials, network or model calls.
    sys.path.insert(0, str(trusted_provider_release()))


_bind_control_center()
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
