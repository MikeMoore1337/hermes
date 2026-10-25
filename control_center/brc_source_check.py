"""Bounded owner-only source validity check for the H455 Control Center panel.

Reads the same already-sanitized observation as the existing status endpoint.
This is NOT a direct MCP ping, tool invocation, permission grant or device audit.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from control_center.brc_snapshot import read_snapshot


def source_check(path: Path, *, now: dt.datetime | None = None) -> dict:
    checked = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    snapshot = read_snapshot(path, now=checked)
    observed = dt.datetime.fromisoformat(
        snapshot["observed_at"].replace("Z", "+00:00")
    ).astimezone(dt.timezone.utc)
    age = max(0, int((checked - observed).total_seconds()))
    return {
        "schema": 1,
        "source": "hermes_brc_validated_snapshot",
        "check": "snapshot_validity_only",
        "checked_at": checked.isoformat().replace("+00:00", "Z"),
        "snapshot_age_seconds": age,
        "status": snapshot["status"],
        "devices": [
            {
                "name": device["name"],
                "status": device["status"],
                "last_seen_age_seconds": device["last_seen_age_seconds"] + age,
                "command_execution": "not_verified",
            }
            for device in snapshot["devices"]
        ],
        "verification": {
            "snapshot": "valid",
            "relay": "not_probed",
            "oauth": "not_probed",
            "tools": "not_probed",
            "git": "not_probed",
            "onboarding": "disabled",
            "native_host": "disabled",
        },
    }
