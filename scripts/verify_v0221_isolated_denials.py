"""Real OS/container denials for one immutable offline Hermes Docker image.

Does NOT invoke the Hermes agent, tools, browser, models or host services.
Any verified availability of shell is an explicit remaining security gap.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any, Callable

from .bounded_subprocess import BoundedProcessError, run_bounded
from . import verify_v0221_core_python as core
from .verify_v0221_local_image import IMAGE

INSPECTOR = r"""
import json
import os
import socket
import subprocess
from pathlib import Path

def connection_refused(ip):
    try:
        with socket.create_connection((ip, 443), timeout=0.6):
            return False
    except OSError:
        return True

def root_immutable():
    file = Path("/opt/hermes/.h01-offline-denial-probe")
    try:
        with file.open("x") as opened:
            opened.write("synthetic")
    except OSError:
        return True
    file.unlink(missing_ok=True)
    return False

def limited_resources():
    cg = Path("/sys/fs/cgroup")
    try:
        quota, period = (cg / "cpu.max").read_text().split()
        return (
            quota != "max" and int(quota) / int(period) <= 0.25
            and int((cg / "memory.max").read_text()) <= 268435456
            and int((cg / "pids.max").read_text()) <= 25
        )
    except (ValueError, OSError):
        return False

def capabilities_zero():
    try:
        data = Path("/proc/self/status").read_text()
        return any(
            line.startswith("CapEff:") and int(line.split()[1], 16) == 0
            for line in data.splitlines()
        )
    except (OSError, ValueError):
        return False

def shell_spawn():
    try:
        return subprocess.run(
            ["/bin/sh", "-c", "true"], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False

checks = {
    "nonroot": os.getuid() == 65534 and os.geteuid() == 65534,
    "capabilities_dropped": capabilities_zero(),
    "cgroup_cpu_ram_pid_bounded": limited_resources(),
    "root_fs_write_denied": root_immutable(),
    "docker_socket_absent": not Path("/var/run/docker.sock").exists(),
    "metadata_connect_denied": connection_refused("169.254.169.254"),
    "testnet_connect_denied": connection_refused("192.0.2.1"),
    "service_token_not_provided": not any(
        os.getenv(name) for name in (
            "CLOUDFLARE_WORKERS_AI_API_TOKEN",
            "TELEGRAM_BOT_TOKEN", "GITHUB_TOKEN", "DATABASE_URL",
        )
    ),
}
print(json.dumps({
    "schema": "hermes-v0221-offline-os-negatives-v1",
    "checks": checks,
    "shell_spawn_possible": shell_spawn(),
}, sort_keys=True, separators=(",", ":")))
"""

REQUIRED = frozenset({
    "nonroot", "capabilities_dropped", "cgroup_cpu_ram_pid_bounded",
    "root_fs_write_denied", "docker_socket_absent",
    "metadata_connect_denied", "testnet_connect_denied",
    "service_token_not_provided",
})


class SecurityProbeDenied(ValueError):
    """No stderr, IP destinations, secrets or input text in exception."""


def commands() -> tuple[list[str], list[str]]:
    inspect, run = core.commands()
    return inspect, [*run[:-1], INSPECTOR]


def verify(raw: bytes) -> dict[str, Any]:
    try:
        packet = core._json(raw, limit=8192)
    except core.ParityDenied:
        raise SecurityProbeDenied("invalid_probe_payload") from None
    if (type(packet) is not dict
            or set(packet) != {"schema", "checks", "shell_spawn_possible"}
            or packet["schema"] != "hermes-v0221-offline-os-negatives-v1"
            or type(packet["checks"]) is not dict
            or set(packet["checks"]) != REQUIRED
            or any(type(value) is not bool for value in packet["checks"].values())
            or type(packet["shell_spawn_possible"]) is not bool):
        raise SecurityProbeDenied("invalid_probe_schema")
    failing = sorted(key for key, passed in packet["checks"].items() if not passed)
    shell_possible = packet["shell_spawn_possible"]
    return {
        "status": ("OFFLINE_SANDBOX_DENIALS_PASS_SHELL_AVAILABLE"
                   if not failing and shell_possible
                   else "OFFLINE_SANDBOX_DENIALS_PASS_SHELL_DENIED"
                   if not failing else "OFFLINE_SANDBOX_DENIALS_FAIL"),
        "pinned_image": IMAGE,
        "checks_total": len(REQUIRED),
        "checks_passed": len(REQUIRED) - len(failing),
        "failed_checks": failing,
        "shell_spawn_possible": shell_possible,
        "hermes_tool_permissions_verified": False,
        "production_os_permissions_verified": False,
        "cloudflare_billing_verified": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> dict[str, Any]:
    inspect, run = commands()
    try:
        initial = runner(inspect, timeout=10, stdout_limit=8192, stderr_limit=16384)
        if initial.returncode:
            raise SecurityProbeDenied("pinned_image_unavailable")
        core.image_identity(initial.stdout)
        probe = runner(run, timeout=30, stdout_limit=8192, stderr_limit=16384)
        if probe.returncode:
            raise SecurityProbeDenied("probe_execution_failed")
        return verify(probe.stdout)
    except (OSError, subprocess.TimeoutExpired, core.ParityDenied,
            BoundedProcessError):
        raise SecurityProbeDenied("offline_runtime_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline OS negative checks, no GO")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        result = observe()
    except SecurityProbeDenied:
        print(json.dumps({"status": "NO_DATA", "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
