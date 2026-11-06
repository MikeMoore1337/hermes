"""H-01 #33: preserve the exact bounded agent image during Docker garbage collection.

Replacement for the *existing* VPS docker-gc job, not a scheduler or installer.
By default this is read-only. Only an separately owner-approved on-host
installation may invoke --apply from the existing docker-gc.service.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys

from scripts.h01_ops_agent_service import H01Denied, safe_image

TARGET_HOST = "vps1777112993"
PROTECTED_POLICY_LABEL = "label!=hermes.native.tool.policy=bounded-v0222"
GC_JOBS = (
    ("rollback", (sys.executable, "/usr/local/sbin/hermes-docker-rollback-gc.py", "--apply")),
    ("builder", ("docker", "builder", "prune", "-af", "--filter", "until=168h")),
    ("images", (
        "docker", "image", "prune", "-af", "--filter", "until=168h",
        "--filter", PROTECTED_POLICY_LABEL,
    )),
)


class GCBlocked(ValueError):
    """Sanitized, non-secret operational refusal."""


def run_gc(*, apply: bool = False) -> dict[str, object]:
    if os.geteuid() != 0 or socket.gethostname() != TARGET_HOST:
        raise GCBlocked("wrong_host_or_privilege")
    try:
        before = safe_image()  # validated digest + arch + upstream SHA + policy label
    except (H01Denied, OSError, ValueError):
        # No cleanup is safe until the actual pinned image can be inspected.
        raise GCBlocked("h01_image_pin_not_verified") from None

    if not apply:
        return {"status": "DRY_RUN", "pin": "VERIFIED", "mutated": False}

    for name, command in GC_JOBS:
        try:
            process = subprocess.run(
                command, capture_output=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=75,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GCBlocked(name + "_execution_unavailable") from None
        if process.returncode != 0:
            raise GCBlocked(name + "_failed")
    try:
        after = safe_image()
    except (H01Denied, OSError, ValueError):
        raise GCBlocked("h01_image_missing_after_gc") from None
    if after != before:
        raise GCBlocked("h01_image_changed_after_gc")
    return {"status": "GC_PASS", "pin": "VERIFIED", "mutated": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Owner-gated H-01-safe Docker GC")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = run_gc(apply=args.apply)
    except GCBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
