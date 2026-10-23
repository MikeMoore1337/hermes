#!/usr/bin/env python3
"""#483: read-only, fail-closed preflight for the Windows BRC sandbox /tmp.

Checks capacity, identity and cgroup headroom without writing temporary files.
This is a diagnostic gate, NOT a replacement for runtime concurrency/OS ACLs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

SCHEMA = "hermes-h483-tmp-preflight-v1"
MIN_FREE_BYTES = 8 * 1024 * 1024
MIN_MEMORY_HEADROOM = 64 * 1024 * 1024
MIN_INODES = 64
MIN_MEMORY_LIMIT = 128 * 1024 * 1024
MAX_MEMORY_LIMIT = 1024 * 1024 * 1024


class TempPreflightDenied(ValueError):
    """Fixed public refusal reason; never include raw environment values."""


def validate(measurement: Any) -> dict[str, Any]:
    """Pure snapshot validator. All inputs represent untrusted observations."""
    if type(measurement) is not dict or set(measurement) != {
        "uid", "owner", "mode", "is_dir", "is_symlink", "filesystem",
        "free_bytes", "free_inodes", "memory_max", "memory_current",
        "environment_ok",
    }:
        raise TempPreflightDenied("MEASUREMENT_INVALID")
    for key in ("uid", "owner", "mode", "free_bytes", "free_inodes",
                "memory_max", "memory_current"):
        if type(measurement[key]) is not int or measurement[key] < 0:
            raise TempPreflightDenied("MEASUREMENT_INVALID")
    if type(measurement["is_dir"]) is not bool or type(measurement["is_symlink"]) is not bool:
        raise TempPreflightDenied("MEASUREMENT_INVALID")
    if type(measurement["environment_ok"]) is not bool:
        raise TempPreflightDenied("MEASUREMENT_INVALID")
    if type(measurement["filesystem"]) is not str:
        raise TempPreflightDenied("MEASUREMENT_INVALID")

    if measurement["filesystem"] != "tmpfs":
        raise TempPreflightDenied("NOT_PINNED_TMPFS")
    if (not measurement["is_dir"] or measurement["is_symlink"]
            or measurement["owner"] != measurement["uid"]
            or measurement["mode"] & 0o077):
        raise TempPreflightDenied("TMP_ACCESS_NOT_PRIVATE")
    if not measurement["environment_ok"]:
        raise TempPreflightDenied("TMP_ENV_NOT_PINNED")
    if measurement["free_bytes"] < MIN_FREE_BYTES:
        raise TempPreflightDenied("TMP_SPACE_EXHAUSTED")
    if measurement["free_inodes"] < MIN_INODES:
        raise TempPreflightDenied("TMP_INODES_EXHAUSTED")
    limit = measurement["memory_max"]
    current = measurement["memory_current"]
    if not MIN_MEMORY_LIMIT <= limit <= MAX_MEMORY_LIMIT or current > limit:
        raise TempPreflightDenied("MEMORY_LIMIT_UNVERIFIED")
    if limit - current < MIN_MEMORY_HEADROOM:
        raise TempPreflightDenied("MEMORY_HEADROOM_LOW")
    return {
        "schema": SCHEMA,
        "status": "SPACE_OK_NOT_AUTHORIZED",
        "available_bytes": measurement["free_bytes"],
        "available_inodes": measurement["free_inodes"],
        "memory_headroom_bytes": limit - current,
        "required_free_bytes": MIN_FREE_BYTES,
        "concurrency_limit_verified": False,
        "host_docker_config_verified": False,
        "identity_persistence_verified": False,
        "actions_executed": 0,
    }


def _mount_fs_type() -> str:
    # Exact Linux mountpoint only; never infer it from df output strings.
    data = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    if len(data) > 262144:
        raise TempPreflightDenied("MOUNTINFO_UNAVAILABLE")
    matches = [
        right.split()[0] for line in data.splitlines()
        if " - " in line
        for left, right in [line.split(" - ", 1)]
        if len(left.split()) > 4 and left.split()[4] == "/tmp" and right.split()
    ]
    if len(matches) != 1:
        raise TempPreflightDenied("MOUNTINFO_UNAVAILABLE")
    return matches[0]


def collect() -> dict[str, Any]:
    """Only kernel metadata and the three known sandbox environment keys."""
    meta = os.lstat("/tmp")
    fs = os.statvfs("/tmp")
    limit = Path("/sys/fs/cgroup/memory.max").read_text(encoding="ascii").strip()
    current = Path("/sys/fs/cgroup/memory.current").read_text(encoding="ascii").strip()
    if (not limit.isdecimal() or not current.isdecimal()
            or len(limit) > 16 or len(current) > 16):
        raise TempPreflightDenied("MEMORY_LIMIT_UNVERIFIED")
    return {
        "uid": os.geteuid(), "owner": meta.st_uid,
        "mode": stat.S_IMODE(meta.st_mode),
        "is_dir": stat.S_ISDIR(meta.st_mode),
        "is_symlink": stat.S_ISLNK(meta.st_mode),
        "filesystem": _mount_fs_type(),
        "free_bytes": fs.f_bavail * fs.f_frsize,
        "free_inodes": fs.f_favail,
        "memory_max": int(limit),
        "memory_current": int(current),
        "environment_ok": all(
            os.environ.get(name, "/tmp") == "/tmp"
            for name in ("TMPDIR", "TMP", "TEMP")
        ),
    }


def main() -> int:
    try:
        result = validate(collect())
    except TempPreflightDenied as exc:
        result = {"schema": SCHEMA, "status": "DENIED", "reason": str(exc),
                  "actions_executed": 0, "concurrency_limit_verified": False}
        code = 2
    except (OSError, UnicodeError, ValueError, OverflowError):
        result = {"schema": SCHEMA, "status": "DENIED",
                  "reason": "OBSERVATION_UNAVAILABLE", "actions_executed": 0,
                  "concurrency_limit_verified": False}
        code = 2
    else:
        code = 0
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
