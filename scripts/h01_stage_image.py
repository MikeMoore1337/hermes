"""H-01 #33: one opt-in, resource-gated v0.22.2 image staging attempt.

The default command is read-only. --execute may pull ONLY the exact official
Linux/AMD64 digest, never build, start or enable an agent. It supervises the
CLI process and stops on load, memory, swap, disk or existing-service drift.
Stopping the CLI cannot instantly cancel Docker daemon layer extraction.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from .host_capacity import HostFacts, read_host_facts

PINNED_IMAGE = (
    "nousresearch/hermes-agent@sha256:"
    "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05"
)
TARGET_ARCH = "amd64"
MAX_LOAD1 = 1.30
MIN_AVAILABLE_MIB = 768 + 640 + 256
MAX_SWAP_USED_MIB = 1024
MIN_DISK_FREE_MIB = 5120
MAX_STAGING_SECONDS = 900
INTERVAL_SECONDS = 2
NEWS_STATE = Path("/var/lib/hermes")
REQUIRED_UNITS = (
    "hermes-discovery.timer",
    "hermes-ops-watch.timer",
    "hermes-control-center.service",
    "hermes-cloudflare-network-guard.service",
)


def blockers(facts: HostFacts, *, units_healthy: bool) -> list[str]:
    """A separate peak gate, stricter than the startup admission of 1.50."""
    errors: list[str] = []
    if not units_healthy:
        errors.append("required_service_unhealthy")
    if facts.news_phase_active:
        errors.append("news_job_in_progress")
    if facts.load1 > MAX_LOAD1:
        errors.append("host_load_exceeded")
    if facts.available_mib < MIN_AVAILABLE_MIB:
        errors.append("available_memory_low")
    if facts.swap_used_mib > MAX_SWAP_USED_MIB:
        errors.append("swap_pressure")
    if facts.disk_free_mib < MIN_DISK_FREE_MIB:
        errors.append("disk_space_low")
    return errors


def required_units_healthy() -> bool:
    for unit in REQUIRED_UNITS:
        try:
            completed = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if completed.returncode != 0:
            return False
    return True


def facts_now() -> HostFacts:
    return read_host_facts(NEWS_STATE)


def verify_image_present() -> bool:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", PINNED_IMAGE, "--format",
             "{{json .RepoDigests}}|{{.Architecture}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        if result.returncode != 0 or len(result.stdout) > 8192:
            return False
        digests_raw, architecture = result.stdout.decode("utf-8").strip().split("|")
        digests = json.loads(digests_raw)
        return (
            architecture == TARGET_ARCH
            and isinstance(digests, list)
            and PINNED_IMAGE in digests
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def execute(
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    facts: Callable[[], HostFacts] = facts_now,
    healthy: Callable[[], bool] = required_units_healthy,
    present: Callable[[], bool] = verify_image_present,
    spawn: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> dict[str, object]:
    if sys.platform != "linux" or os.geteuid() != 0:
        return {"status": "DENIED_PLATFORM_OR_PERMISSIONS", "image_started": False}
    try:
        errors = blockers(facts(), units_healthy=healthy())
    except (OSError, RuntimeError, ValueError, KeyError):
        errors = ["preflight_unavailable"]
    if errors:
        return {"status": "BLOCKED_PRECHECK", "reasons": errors, "image_started": False}
    if present():
        return {"status": "PINNED_IMAGE_PRESENT", "image_started": False}

    try:
        # Detached process group is needed for an unambiguous bounded stop.
        process = spawn(
            ["nice", "-n", "19", "ionice", "-c", "3",
             "docker", "pull", "--platform", "linux/amd64", PINNED_IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return {"status": "PULL_START_FAILED", "image_started": False}
    start = clock()
    reason: str | None = None
    try:
        while process.poll() is None:
            if clock() - start >= MAX_STAGING_SECONDS:
                reason = "staging_timeout"
                break
            try:
                state = blockers(facts(), units_healthy=healthy())
            except (OSError, RuntimeError, ValueError, KeyError):
                state = ["observation_unavailable"]
            if state:
                reason = state[0]
                break
            sleep(INTERVAL_SECONDS)
        if reason is not None:
            _stop_process_group(process)
            return {"status": "PULL_STOPPED_BY_GUARD", "reason": reason,
                    "image_started": True, "daemon_may_still_be_extracting": True}
        if process.returncode != 0:
            return {"status": "PULL_FAILED", "image_started": True}
        if not present():
            return {"status": "IMAGE_IDENTITY_UNVERIFIED", "image_started": True}
        # The downloaded image remains inert. No gateway, service, egress or token.
        return {"status": "PINNED_IMAGE_READY_OFFLINE_ONLY", "image_started": True}
    finally:
        if process.poll() is None:
            _stop_process_group(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-01 bounded official v0.22.2 staging")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result = execute() if args.execute else {
        "status": "PREVIEW_ONLY",
        "image": PINNED_IMAGE,
        "max_load1": MAX_LOAD1,
        "execute_required": True,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] in {
        "PREVIEW_ONLY", "PINNED_IMAGE_PRESENT", "PINNED_IMAGE_READY_OFFLINE_ONLY"
    } else 2


if __name__ == "__main__":
    raise SystemExit(main())
