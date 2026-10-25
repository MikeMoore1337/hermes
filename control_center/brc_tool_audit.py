"""Read-only, metadata-only evidence of REAL historical Hermes BRC tool calls.

Never opens a socket, invokes a remote tool, handles client arguments, or
returns device identifiers, file paths, tool outputs or audit arguments.
A successful audit row is not proof of a completed shell process.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from urllib.parse import quote

from control_center.brc_snapshot import DEVICES, SnapshotRejected

DB = Path("/var/lib/hermes-brc-relay/relay.sqlite")
OUTPUT = Path("/var/lib/hermes-brc-observer/tool-evidence.json")
SOURCE = "hermes_brc_relay_audit"
WINDOW_SECONDS = 86400
MAX_BYTES = 4096
MAX_DATABASE_BYTES = 67108864
TOOLS = frozenset({
    "read_file", "read_multiple_files", "list_directory", "get_file_info",
    "read_process_output", "list_sessions",
})
IDENTIFIER = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")


def _deny(reason: str):
    raise SnapshotRejected(reason)


def collect(database: Path = DB, *, now: dt.datetime | None = None,
            expected_uid: int | None = None) -> dict:
    moment = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    ms = int(moment.timestamp() * 1000)
    path = Path(database)
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotRejected("audit_database_missing") from exc
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_size > MAX_DATABASE_BYTES or info.st_size < 4096
        or stat.S_IMODE(info.st_mode) & 0o022
        or (expected_uid is not None and info.st_uid != expected_uid)):
        _deny("audit_database_untrusted")
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=0.6) as connection:
            connection.execute("PRAGMA query_only=ON")
            devices = connection.execute(
                "SELECT device_id,user_id,name,platform,paused FROM devices"
            ).fetchall()
            # Use indexed audit_ts; bounded result size even with large history.
            calls = connection.execute(
                "SELECT ts,device_id,user_id,tool,ok,ms FROM audit "
                "WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 200",
                (ms - WINDOW_SECONDS * 1000, ms + 60000),
            ).fetchall()
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise SnapshotRejected("audit_database_unavailable") from exc

    known = {}
    owners = set()
    for device_id, owner, name, platform, paused in devices:
        if name not in DEVICES:
            continue  # Native Windows is never a diagnostic target.
        if (name in known or not isinstance(owner, str) or not owner
            or not isinstance(device_id, str) or not IDENTIFIER.fullmatch(device_id)
            or platform != "linux/docker" or paused not in (0, 1)):
            _deny("audit_device_untrusted")
        known[name] = (device_id, owner)
        owners.add(owner)
    if len(known) != len(DEVICES) or len(owners) != 1:
        _deny("audit_device_registry_mismatch")
    ids = {v[0]: (k, v[1]) for k, v in known.items()}
    successes = {}
    for ts, device_id, user_id, tool, ok, duration in calls:
        device = ids.get(device_id)
        if (device is None or device[1] != user_id or device[0] in successes
            or tool not in TOOLS or ok != 1 or type(ts) is not int
            or not ms - WINDOW_SECONDS * 1000 <= ts <= ms + 60000
            or type(duration) is not int or not 0 <= duration <= 60000):
            continue
        successes[device[0]] = (tool, ts, duration)
    entries = []
    for name in DEVICES:
        item = successes.get(name)
        entries.append({
            "name": name,
            "state": "historical_success" if item else "no_recent_evidence",
            "last_tool": item[0] if item else None,
            "last_at": (dt.datetime.fromtimestamp(item[1] / 1000, dt.timezone.utc)
                        .isoformat().replace("+00:00", "Z")) if item else None,
            "duration_ms": item[2] if item else None,
        })
    return {
        "schema": 1, "source": SOURCE, "kind": "historical_only",
        "observed_at": moment.isoformat().replace("+00:00", "Z"),
        "window_seconds": WINDOW_SECONDS, "execution_verified": False,
        "native_host_access": False, "devices": entries,
    }


def validate(value: object, *, now: dt.datetime | None = None) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema", "source", "kind", "observed_at", "window_seconds",
        "execution_verified", "native_host_access", "devices"
    } or type(value["schema"]) is not int or value["schema"] != 1 or (
        value["source"], value["kind"], value["window_seconds"],
        value["execution_verified"], value["native_host_access"]
    ) != (SOURCE, "historical_only", WINDOW_SECONDS, False, False):
        _deny("audit_schema_invalid")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    try:
        timestamp = dt.datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError) as exc:
        raise SnapshotRejected("audit_time_invalid") from exc
    if timestamp.tzinfo is None:
        _deny("audit_time_invalid")
    age = (current - timestamp.astimezone(dt.timezone.utc)).total_seconds()
    if age > 300 or age < -60:
        _deny("audit_stale")
    rows = value["devices"]
    if not isinstance(rows, list) or len(rows) != len(DEVICES):
        _deny("audit_devices_invalid")
    for name, row in zip(DEVICES, rows):
        if not isinstance(row, dict) or set(row) != {
            "name", "state", "last_tool", "last_at", "duration_ms"
        } or row["name"] != name:
            _deny("audit_device_invalid")
        if row["state"] == "no_recent_evidence":
            if (row["last_tool"], row["last_at"], row["duration_ms"]) != (None, None, None):
                _deny("audit_empty_invalid")
        elif row["state"] == "historical_success":
            if row["last_tool"] not in TOOLS or type(row["duration_ms"]) is not int \
                    or not 0 <= row["duration_ms"] <= 60000:
                _deny("audit_tool_invalid")
            try:
                tool_at = dt.datetime.fromisoformat(row["last_at"].replace("Z", "+00:00"))
            except (ValueError, AttributeError, TypeError) as exc:
                raise SnapshotRejected("audit_tool_time_invalid") from exc
            if tool_at.tzinfo is None or not -60 <= (current - tool_at).total_seconds() <= WINDOW_SECONDS:
                _deny("audit_tool_time_invalid")
        else:
            _deny("audit_state_invalid")
    return value


def read_receipt(path: Path = OUTPUT, *, now: dt.datetime | None = None) -> dict:
    source = Path(path)
    try:
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_size > MAX_BYTES or stat.S_IMODE(info.st_mode) & 0o022):
            _deny("audit_receipt_untrusted")
        raw = source.read_bytes()
        if len(raw) > MAX_BYTES:
            _deny("audit_receipt_too_large")
        return validate(json.loads(raw), now=now)
    except (OSError, ValueError, UnicodeError) as exc:
        raise SnapshotRejected("audit_receipt_unavailable") from exc


def publish(database: Path = DB, target: Path = OUTPUT,
            *, now: dt.datetime | None = None,
            uid: int | None = None, gid: int | None = None) -> dict:
    owner = os.geteuid() if uid is None else uid
    group = os.getegid() if gid is None else gid
    if owner == 0 or os.geteuid() != owner or os.getegid() != group:
        _deny("audit_publisher_identity_denied")
    value = collect(database, now=now, expected_uid=owner)
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_BYTES:
        _deny("audit_receipt_oversize")
    target = Path(target)
    parent = target.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != owner or parent.st_gid != group
        or stat.S_IMODE(parent.st_mode) != 0o750):
        _deny("audit_output_directory_untrusted")
    if target.exists() or target.is_symlink():
        old = target.lstat()
        if (not stat.S_ISREG(old.st_mode) or old.st_uid != owner
            or old.st_gid != group or stat.S_IMODE(old.st_mode) != 0o640):
            _deny("audit_existing_target_untrusted")
    name = None
    try:
        fd, name = tempfile.mkstemp(prefix=".brc-evidence-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), owner, group)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink():
            _deny("audit_target_symlink")
        os.replace(name, target)
        name = None
    except OSError as exc:
        raise SnapshotRejected("audit_publish_failed") from exc
    finally:
        if name is not None:
            try: os.unlink(name)
            except FileNotFoundError: pass
    return value
