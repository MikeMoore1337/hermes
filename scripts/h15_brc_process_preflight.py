#!/usr/bin/env python3
"""Read-only process/PID1 preflight for the existing Windows BRC Docker sandbox.

Issue #445 / #454. Does NOT stop processes, change cgroups, grant access,
run subprocesses, or imply approval for a Windows host Docker replacement.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any

SCHEMA = "hermes-h445-process-preflight-v1"
EXPECTED_UID = 65534
MIN_PIDS_HEADROOM = 24
MIN_TMP_BYTES = 8 * 1024 * 1024
MIN_MEMORY_BYTES = 64 * 1024 * 1024
MAX_CGROUP_PIDS = 1024
MAX_PID_DIRS = 8192


class ProcessPreflightDenied(ValueError):
    """Only fixed public denial reasons; do not print host cmdlines."""


def _number(raw: str, *, ceiling: int = 2**42) -> int:
    if type(raw) is not str or len(raw) > 16 or not raw.isascii() or not raw.isdecimal():
        raise ProcessPreflightDenied("UNTRUSTED_CGROUP")
    value = int(raw)
    if value < 0 or value > ceiling:
        raise ProcessPreflightDenied("UNTRUSTED_CGROUP")
    return value


def _read_number(root: Path, field: str, *, ceiling: int = 2**42) -> int:
    return _number((root / field).read_text(encoding="ascii").strip(), ceiling=ceiling)


def _count_pid1_zombies(proc: Path) -> int:
    count = 0
    seen = 0
    for entry in proc.iterdir():
        if not entry.name.isdecimal() or not entry.name.isascii():
            continue
        seen += 1
        if seen > MAX_PID_DIRS:
            raise ProcessPreflightDenied("PROCESS_SNAPSHOT_UNAVAILABLE")
        try:
            raw = (entry / "status").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            # A process can disappear during a snapshot; its status is not
            # proof that an inaccessible, still-live PID had no zombie state.
            continue
        except PermissionError as exc:
            raise ProcessPreflightDenied("PROCESS_SNAPSHOT_UNAVAILABLE") from exc
        if len(raw) > 8192:
            raise ProcessPreflightDenied("PROCESS_SNAPSHOT_UNAVAILABLE")
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            if line.startswith(("State:", "PPid:")):
                key, _, value = line.partition(":")
                if key in fields:
                    raise ProcessPreflightDenied("PROCESS_SNAPSHOT_UNAVAILABLE")
                fields[key] = value.strip()
        if set(fields) != {"State", "PPid"} or not fields["PPid"].isdecimal():
            raise ProcessPreflightDenied("PROCESS_SNAPSHOT_UNAVAILABLE")
        if fields["State"].startswith("Z") and fields["PPid"] == "1":
            count += 1
    return count


def collect(*, cgroup: Path = Path("/sys/fs/cgroup"),
            proc: Path = Path("/proc"), tmp: str = "/tmp") -> dict[str, int]:
    """Read metadata only. Never read process argv, env, files, or credentials."""
    if os.geteuid() != EXPECTED_UID:
        raise ProcessPreflightDenied("UNEXPECTED_SANDBOX_UID")
    total = _read_number(cgroup, "pids.max", ceiling=MAX_CGROUP_PIDS)
    current = _read_number(cgroup, "pids.current", ceiling=MAX_CGROUP_PIDS + 1024)
    memory_max = _read_number(cgroup, "memory.max")
    memory_current = _read_number(cgroup, "memory.current")
    if not 1 <= total <= MAX_CGROUP_PIDS or current > total:
        raise ProcessPreflightDenied("UNTRUSTED_PID_LIMIT")
    if not 128 * 1024 * 1024 <= memory_max <= 2 * 1024 * 1024 * 1024:
        raise ProcessPreflightDenied("UNTRUSTED_MEMORY_LIMIT")
    if memory_current > memory_max:
        raise ProcessPreflightDenied("UNTRUSTED_MEMORY_LIMIT")
    stat = os.statvfs(tmp)
    return {
        "uid": os.geteuid(), "pids_current": current, "pids_max": total,
        "memory_current": memory_current, "memory_max": memory_max,
        "tmp_free_bytes": stat.f_bavail * stat.f_frsize,
        "pid1_zombies": _count_pid1_zombies(proc),
    }


def evaluate(snapshot: Any) -> dict[str, Any]:
    if type(snapshot) is not dict or set(snapshot) != {
        "uid", "pids_current", "pids_max", "memory_current", "memory_max",
        "tmp_free_bytes", "pid1_zombies",
    } or any(type(value) is not int or value < 0 for value in snapshot.values()):
        raise ProcessPreflightDenied("MEASUREMENT_INVALID")
    n = snapshot
    if n["uid"] != EXPECTED_UID:
        raise ProcessPreflightDenied("UNEXPECTED_SANDBOX_UID")
    if not 1 <= n["pids_max"] <= MAX_CGROUP_PIDS or n["pids_current"] > n["pids_max"]:
        raise ProcessPreflightDenied("UNTRUSTED_PID_LIMIT")
    if (not 128 * 1024 * 1024 <= n["memory_max"] <= 2 * 1024 * 1024 * 1024
            or n["memory_current"] > n["memory_max"]):
        raise ProcessPreflightDenied("UNTRUSTED_MEMORY_LIMIT")
    available = n["pids_max"] - n["pids_current"]
    reasons = []
    if available < MIN_PIDS_HEADROOM:
        reasons.append("PID_HEADROOM_LOW")
    if n["pid1_zombies"]:
        reasons.append("PID1_ZOMBIES_NOT_REAPED")
    if n["tmp_free_bytes"] < MIN_TMP_BYTES:
        reasons.append("TMP_HEADROOM_LOW")
    if n["memory_max"] - n["memory_current"] < MIN_MEMORY_BYTES:
        reasons.append("MEMORY_HEADROOM_LOW")
    return {
        "schema": SCHEMA,
        "status": "HOLD" if reasons else "CAPACITY_OBSERVED_NOT_AUTHORIZED",
        "reasons": reasons,
        "pids_current": n["pids_current"], "pids_max": n["pids_max"],
        "pids_available": available,
        "pid1_zombies": n["pid1_zombies"],
        "tmp_free_mib": n["tmp_free_bytes"] // (1024 * 1024),
        "memory_headroom_mib": (n["memory_max"] - n["memory_current"]) // (1024 * 1024),
        "host_repair_verified": False, "reconnect_verified": False,
        "reboot_verified": False, "actions_executed": 0,
    }


def main() -> int:
    try:
        result = evaluate(collect())
    except ProcessPreflightDenied as exc:
        result = {"schema": SCHEMA, "status": "HOLD",
                  "reasons": [str(exc)], "actions_executed": 0,
                  "host_repair_verified": False}
    except (OSError, UnicodeError, OverflowError, ValueError):
        result = {"schema": SCHEMA, "status": "HOLD",
                  "reasons": ["OBSERVATION_UNAVAILABLE"], "actions_executed": 0,
                  "host_repair_verified": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "CAPACITY_OBSERVED_NOT_AUTHORIZED" else 2


if __name__ == "__main__":
    sys.exit(main())
