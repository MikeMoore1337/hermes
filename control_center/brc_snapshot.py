"""Sanitized, read-only Hermes BRC observation contract for #455.

No MCP/network calls or filesystem writes. Presence is NOT permission or
proof of command execution. Never expose raw device IDs or vendor secrets.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
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
# A separately owner-approved, currently disabled original Windows reader is
# registered alongside the three permanent sandboxes. It is NOT a fourth
# workspace target and must never grant host permissions through this snapshot.
NATIVE_READER_NAME = "H15 Windows native read-only"
NATIVE_READER_ID = "h454-win-01335a1f6e6705b4"
DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")
PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


class SnapshotRejected(ValueError):
    """Short failure code, never untrusted payload text."""


def _reject(code: str) -> None:
    raise SnapshotRejected(code)


def _validate_fork_snapshot(value: dict, age_seconds: float) -> dict:
    records, projects = value["devices"], value["workspaces"]
    if not isinstance(records, list) or len(records) > 64:
        _reject("invalid_snapshot_devices")
    devices = {}
    for device in records:
        if (not isinstance(device, dict)
            or set(device) != {"name", "status", "last_seen_age_seconds", "command_execution"}
            or not isinstance(device["name"], str) or not LABEL.fullmatch(device["name"])
            or device["name"] in devices
            or device["status"] not in ("online", "offline", "paused", "stale")
            or type(device["last_seen_age_seconds"]) is not int
            or not 0 <= device["last_seen_age_seconds"] <= 86400
            or (device["status"] == "online" and device["last_seen_age_seconds"] + age_seconds > 300)
            or device["command_execution"] != "not_verified"):
            _reject("invalid_snapshot_device")
        devices[device["name"]] = device["status"]
    online = sum(state == "online" for state in devices.values())
    status = "online" if online and online == len(devices) else "partial" if online else "unavailable"
    if value["status"] != status:
        _reject("snapshot_inconsistent_status")
    if not isinstance(projects, list) or len(projects) > 64:
        _reject("invalid_snapshot_workspaces")
    names, roots = set(), set()
    for entry in projects:
        if (not isinstance(entry, dict)
            or set(entry) != {"name", "root", "branch", "device_name", "git_verified", "state"}
            or not isinstance(entry["name"], str) or not PROJECT.fullmatch(entry["name"])
            or entry["name"].lower() in names
            or not isinstance(entry["root"], str) or not entry["root"].startswith("/workspace/projects/")
            or not PROJECT.fullmatch(entry["root"][len("/workspace/projects/"):])
            or not isinstance(entry["branch"], str) or not BRANCH.fullmatch(entry["branch"])
            or ".." in entry["branch"] or "//" in entry["branch"]
            or entry["branch"].endswith(("/", "."))
            or any(part.startswith(".") or part.endswith(".lock") for part in entry["branch"].split("/"))
            or not isinstance(entry["device_name"], str) or entry["device_name"] not in devices
            or (entry["device_name"], entry["root"]) in roots
            or entry["git_verified"] is not False
            or entry["state"] != ("reachable_not_git_verified" if devices[entry["device_name"]] == "online" else "not_ready")):
            _reject("invalid_snapshot_workspace")
        names.add(entry["name"].lower())
        roots.add((entry["device_name"], entry["root"]))
    return value


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
    if not isinstance(raw, list) or len(raw) not in (len(DEVICES), len(DEVICES) + 1):
        _reject("invalid_device_count")
    seen_names, seen_ids = set(), set()
    ids, output = {}, []
    for row in raw:
        if not isinstance(row, dict):
            _reject("invalid_device")
        name, identifier = row.get("name"), row.get("deviceId")
        if (name not in (*DEVICES, NATIVE_READER_NAME) or name in seen_names or
            not isinstance(identifier, str) or not DEVICE_ID.fullmatch(identifier) or
            identifier in seen_ids):
            _reject("invalid_device_identity")
        if name == NATIVE_READER_NAME and (
            identifier != NATIVE_READER_ID or row.get("platform") != "win32"
        ):
            _reject("invalid_native_reader_identity")
        seen_names.add(name)
        seen_ids.add(identifier)
        ids[name] = identifier
        if type(row.get("online")) is not bool or type(row.get("paused")) is not bool:
            _reject("invalid_presence")
        stamp = row.get("lastSeen")
        if type(stamp) is not int or stamp < 0 or stamp > now_ms + CLOCK_SKEW_MS:
            _reject("invalid_last_seen")
        age = max(0, now_ms - stamp)
        # Validate the native reader exactly, then exclude it from the three
        # sandbox observation and project list. It is never host access approval.
        if name == NATIVE_READER_NAME:
            continue
        status = ("paused" if row["paused"] else
                  "offline" if not row["online"] else
                  "stale" if age > STALE_AFTER_MS else "online")
        output.append({"name": name, "status": status,
                       "last_seen_age_seconds": age // 1000,
                       "command_execution": "not_verified"})
    if len(output) != len(DEVICES):
        _reject("invalid_device_count")
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


# Optional sanitized snapshot produced only by a separately authorized collector.
# No raw device credentials, OAuth tokens, host paths, or MCP commands may be read.
DEFAULT_OUTPUT = Path("/var/lib/hermes-brc-observer/status.json")
MAX_SNAPSHOT_BYTES = 16384

def read_snapshot(path: Path = DEFAULT_OUTPUT, *, now: dt.datetime | None = None) -> dict:
    """Read an owner-authenticated collector's already sanitized public snapshot.

    Missing, stale, foreign or overbroad files fail closed. This is a
    metadata reader only; it does not start a collector or authorize tools.
    """
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SNAPSHOT_BYTES:
            _reject("snapshot_unavailable")
        raw = path.read_bytes()
        if len(raw) > MAX_SNAPSHOT_BYTES:
            _reject("snapshot_oversize")
        value = json.loads(raw)
    except (OSError, ValueError, UnicodeError) as exc:
        raise SnapshotRejected("snapshot_unavailable") from exc
    fields = {"schema", "source", "observed_at", "status", "execution_verified",
              "native_host_access", "onboarding_enabled", "devices", "workspaces"}
    if (not isinstance(value, dict) or set(value) != fields
        or type(value["schema"]) is not int
        or (value["schema"], value["source"]) not in ((SCHEMA, SOURCE), (2, "hermes_brc_fork"))
        or value["execution_verified"] is not False or value["onboarding_enabled"] is not False
        or value["native_host_access"] != (False if value["schema"] == 1 else "not_verified")
        or (value["schema"] == 1 and value["native_host_access"] is not False)):
        _reject("invalid_snapshot_schema")
    time_text = value["observed_at"]
    if not isinstance(time_text, str) or not 19 <= len(time_text) <= 35:
        _reject("invalid_observation_time")
    try:
        when = dt.datetime.fromisoformat(time_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotRejected("invalid_observation_time") from exc
    if when.tzinfo is None:
        _reject("invalid_observation_timezone")
    now_utc = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    delta = (now_utc - when.astimezone(dt.timezone.utc)).total_seconds()
    if delta > STALE_AFTER_MS / 1000 or delta < -(CLOCK_SKEW_MS / 1000):
        _reject("snapshot_stale_or_future")
    if value["schema"] == 2:
        return _validate_fork_snapshot(value, max(0, delta))
    records = value["devices"]
    if not isinstance(records, list) or len(records) != len(DEVICES):
        _reject("invalid_snapshot_devices")
    for i, d in enumerate(records):
        if (not isinstance(d, dict)
            or set(d) != {"name", "status", "last_seen_age_seconds", "command_execution"}
            or d["name"] != DEVICES[i]
            or d["status"] not in ("online", "offline", "paused", "stale")
            or type(d["last_seen_age_seconds"]) is not int
            or not 0 <= d["last_seen_age_seconds"] <= 86400
            or d["command_execution"] != "not_verified"):
            _reject("invalid_snapshot_device")
    online = sum(d["status"] == "online" for d in records)
    aggregate = "online" if online == len(DEVICES) else "partial" if online else "unavailable"
    if value["status"] != aggregate:
        _reject("snapshot_inconsistent_status")
    projects = value["workspaces"]
    if not isinstance(projects, list) or len(projects) != len(PROJECTS):
        _reject("invalid_snapshot_workspaces")
    ready = records[0]["status"] == "online"
    for entry, (name, branch) in zip(projects, PROJECTS.items()):
        if (not isinstance(entry, dict)
            or set(entry) != {"name", "root", "branch", "git_verified", "state"}
            or entry["name"] != name
            or entry["root"] != "/workspace/projects/" + name
            or entry["branch"] != branch
            or entry["git_verified"] is not False
            or entry["state"] != ("reachable_not_git_verified" if ready else "not_ready")):
            _reject("invalid_snapshot_workspace")
    return value
