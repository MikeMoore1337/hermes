"""Sanitized, read-only Hermes BRC observation contract for #455.

No MCP/network calls or filesystem writes. Presence is NOT permission or
proof of command execution. Never expose raw device IDs or vendor secrets.
"""
from __future__ import annotations

import datetime as dt
import re

SCHEMA = 1
SOURCE = "hermes_brc_mcp"
STALE_AFTER_MS = 300_000
CLOCK_SKEW_MS = 60_000
DEVICES = (
    "H15 Windows permanent sandbox",
    "H15 Hermes VPS sandbox",
    "H15 YFC VPS sandbox",
)
PROJECTS = {
    "hermes": "main",
    "your-fitness-coach": "master",
    "second-brain": "main",
    "ai-development-toolkit": "main",
}
WINDOWS = DEVICES[0]
DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class SnapshotRejected(ValueError):
    """Short failure code, never untrusted payload text."""


def _reject(code: str) -> None:
    raise SnapshotRejected(code)


def normalize(devices: object, catalog: object, *, now_ms: int) -> dict:
    """Validate owner-scoped MCP results; return safe display-only metadata.

    The results must be captured by an authorized separate collector.
    This function does NOT authorize or perform operations on devices.
    """
    if type(now_ms) is not int or now_ms < 1_600_000_000_000:
        _reject("invalid_clock")
    if not isinstance(devices, dict) or set(devices) != {"devices"}:
        _reject("invalid_device_envelope")
    raw = devices["devices"]
    if not isinstance(raw, list) or len(raw) != len(DEVICES):
        _reject("invalid_device_count")
    seen_names, seen_ids = set(), set()
    ids, output = {}, []
    for row in raw:
        if not isinstance(row, dict):
            _reject("invalid_device")
        name, identifier = row.get("name"), row.get("deviceId")
        if (name not in DEVICES or name in seen_names or
            not isinstance(identifier, str) or not DEVICE_ID.fullmatch(identifier) or
            identifier in seen_ids):
            _reject("invalid_device_identity")
        seen_names.add(name)
        seen_ids.add(identifier)
        ids[name] = identifier
        if type(row.get("online")) is not bool or type(row.get("paused")) is not bool:
            _reject("invalid_presence")
        stamp = row.get("lastSeen")
        if type(stamp) is not int or stamp < 0 or stamp > now_ms + CLOCK_SKEW_MS:
            _reject("invalid_last_seen")
        age = max(0, now_ms - stamp)
        status = ("paused" if row["paused"] else
                  "offline" if not row["online"] else
                  "stale" if age > STALE_AFTER_MS else "online")
        output.append({"name": name, "status": status,
                       "last_seen_age_seconds": age // 1000,
                       "command_execution": "not_verified"})
    output.sort(key=lambda row: DEVICES.index(row["name"]))
    windows_online = output[0]["status"] == "online"

    if not isinstance(catalog, dict) or catalog.get("schema") != 1 or catalog.get("status") != "catalog":
        _reject("invalid_workspace_catalog")
    entries = catalog.get("workspaces")
    if not isinstance(entries, list) or len(entries) != len(PROJECTS):
        _reject("invalid_workspace_count")
    result, seen_projects = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            _reject("invalid_workspace")
        name = entry.get("name")
        if name not in PROJECTS or name in seen_projects:
            _reject("unexpected_workspace")
        seen_projects.add(name)
        expected_origin = f"https://github.com/MikeMoore1337/{name}.git"
        if (entry.get("scope") != "sandbox"
            or entry.get("root") != f"/workspace/projects/{name}"
            or entry.get("branch") != PROJECTS[name]
            or entry.get("origin") != expected_origin
            or entry.get("deviceId") != ids[WINDOWS]
            or entry.get("device_status") != "online"
            or entry.get("git_verified") is not False):
            _reject("workspace_scope_mismatch")
        result.append({"name": name,
                       "root": f"/workspace/projects/{name}",
                       "branch": PROJECTS[name], "git_verified": False,
                       "state": "reachable_not_git_verified" if windows_online else "not_ready"})
    result.sort(key=lambda row: tuple(PROJECTS).index(row["name"]))
    healthy = sum(row["status"] == "online" for row in output)
    status = "online" if healthy == len(DEVICES) else "partial" if healthy else "unavailable"
    when = dt.datetime.fromtimestamp(now_ms / 1000, tz=dt.timezone.utc)
    return {"schema": SCHEMA, "source": SOURCE,
            "observed_at": when.isoformat().replace("+00:00", "Z"),
            "status": status, "execution_verified": False,
            "onboarding_enabled": False, "native_host_access": False,
            "devices": output, "workspaces": result}
