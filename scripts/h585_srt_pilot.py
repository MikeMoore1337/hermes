#!/usr/bin/env python3
"""#585: synthetic, reproducible Docker vs Anthropic SRT OS-boundary probe.

Only disposable paths; never asks for host secrets or touches production.
This fixture does not install or activate a resident agent.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


CHECKS = (
    "workspace_write",
    "protected_read",
    "protected_write_denied",
    "private_read_denied",
    "symlink_private_read_denied",
    "direct_tcp_denied",
)


def prepare(root: Path) -> None:
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("refusing nonempty fixture directory")
    workspace = root / "workspace"
    private = root / "private"
    protected = root / "protected"
    for location in (workspace, private, protected):
        location.mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o777)  # synthetic CI-only fixture shared with Docker UID 65534
    (private / "canary.txt").write_text("synthetic-only-not-a-secret", encoding="utf-8")
    (protected / "marker.txt").write_text("synthetic-read-only", encoding="utf-8")
    config = {
        "filesystem": {
            "denyRead": [str(private)],
            "allowRead": [],
            "allowWrite": [str(workspace), "/tmp"],
            "denyWrite": [str(private), str(protected)],
        },
        "network": {"allowedDomains": [], "deniedDomains": []},
    }
    (root / "srt-settings.json").write_text(
        json.dumps(config, indent=2), encoding="utf-8"
    )


def readable(location: Path) -> bool:
    try:
        location.read_text(encoding="utf-8")
        return True
    except (OSError, UnicodeError):
        return False


def writable(location: Path) -> bool:
    try:
        location.write_text("synthetic-test", encoding="utf-8")
        return True
    except OSError:
        return False


def tcp_reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def check(workspace: Path, private: Path, protected: Path, host: str, port: int) -> dict[str, bool]:
    workspace.mkdir(parents=True, exist_ok=True)
    symlink = workspace / "private-link.txt"
    try:
        if symlink.is_symlink():
            symlink.unlink()
        symlink.symlink_to(private / "canary.txt")
        link_denied = not readable(symlink)
    except OSError:
        # Not being able to create the test link is not evidence of blocked traversal.
        link_denied = False
    return {
        "workspace_write": writable(workspace / "permitted.txt"),
        "protected_read": readable(protected / "marker.txt"),
        "protected_write_denied": not writable(protected / "marker.txt"),
        "private_read_denied": not readable(private / "canary.txt"),
        "symlink_private_read_denied": link_denied,
        "direct_tcp_denied": not tcp_reachable(host, port),
    }


def verify(report: dict) -> None:
    if report.get("schema") != "h585-sandbox-comparison-v1":
        raise ValueError("unknown schema")
    if report.get("probe_executed") is not True:
        raise ValueError("probe never executed")
    for level in ("checks", "child_checks"):
        values = report.get(level)
        if not isinstance(values, dict) or set(values) != set(CHECKS):
            raise ValueError("missing checks: " + level)
        if any(values[key] is not True for key in CHECKS):
            failed = [key for key in CHECKS if values[key] is not True]
            raise ValueError(level + " failed: " + ",".join(failed))


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="operation", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("root", type=Path)
    run = commands.add_parser("probe")
    run.add_argument("--workspace", type=Path, required=True)
    run.add_argument("--private", type=Path, required=True)
    run.add_argument("--protected", type=Path, required=True)
    run.add_argument("--tcp-host", default="1.1.1.1")
    run.add_argument("--tcp-port", type=int, default=443)
    run.add_argument("--child", action="store_true")
    validate = commands.add_parser("verify")
    validate.add_argument("report", type=Path)
    args = parser.parse_args()
    if args.operation == "prepare":
        prepare(args.root)
        return 0
    if args.operation == "verify":
        verify(json.loads(args.report.read_text(encoding="utf-8")))
        print("H585_NEGATIVE_BOUNDARIES=PASS")
        return 0

    own = check(args.workspace, args.private, args.protected, args.tcp_host, args.tcp_port)
    if args.child:
        print(json.dumps(own, sort_keys=True))
        return 0
    cmd = [
        sys.executable, os.path.abspath(__file__), "probe",
        "--workspace", str(args.workspace),
        "--private", str(args.private),
        "--protected", str(args.protected),
        "--tcp-host", args.tcp_host,
        "--tcp-port", str(args.tcp_port),
        "--child",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
    child = {}
    if completed.returncode == 0:
        try:
            child = json.loads(completed.stdout)
        except json.JSONDecodeError:
            pass
    report = {
        "schema": "h585-sandbox-comparison-v1",
        "probe_executed": True,
        "checks": own,
        "child_checks": child,
        "child_exit": completed.returncode,
    }
    verify(report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
