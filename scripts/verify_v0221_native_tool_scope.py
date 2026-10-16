"""Test one native tool-scope dispatch path in pinned offline Hermes v0.22.1.

No AI, shell execution, plugin invocation, credentials or network. The final
tool executor is always replaced by a synthetic mock before the call.
This is an evidence probe, not a full agent policy test or runtime approval.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any, Callable

from . import verify_v0221_core_python as core
from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0221_local_image import IMAGE

INSPECTOR = r"""
import json
from unittest.mock import patch
import model_tools

enabled = ["safe"]
disabled = ["terminal"]
scoped = model_tools._select_tool_names(enabled, disabled, quiet_mode=True)
listed = "terminal" in scoped
with patch.object(model_tools, "_execute_tool", return_value="SYNTHETIC_DISPATCH") as stub:
    response = model_tools.handle_function_call(
        "terminal", {"command": "SYNTHETIC_NO_EXEC"},
        enabled_toolsets=enabled, disabled_toolsets=disabled,
    )
    reached = stub.called
print(json.dumps({
    "schema": "hermes-v0221-native-tool-scope-v1",
    "terminal_listed": listed,
    "native_dispatch_reached": reached,
    "mocked_executor": True,
    "synthetic_response": response == "SYNTHETIC_DISPATCH",
}, sort_keys=True, separators=(",", ":")))
"""


class NativeScopeDenied(ValueError):
    """Sanitized inspector or evidence failure; never reveal stderr."""


def commands() -> tuple[list[str], list[str]]:
    inspect, base = core.commands()
    run = list(base)
    run[run.index("--cpus") + 1] = "0.5"
    run[run.index("--memory") + 1] = "768m"
    run[run.index("--memory-swap") + 1] = "768m"
    run[run.index("--tmpfs") + 1] = "/tmp:rw,noexec,nosuid,nodev,size=32m"
    pos = run.index("--entrypoint")
    run[pos:pos] = ["--env", "HOME=/tmp", "--env", "HERMES_HOME=/tmp/hermes"]
    run[-1] = INSPECTOR
    return inspect, run


def validate(raw: bytes) -> dict[str, Any]:
    try:
        packet = core._json(raw, limit=4096)
    except core.ParityDenied:
        raise NativeScopeDenied("invalid_probe_json") from None
    if (type(packet) is not dict
            or set(packet) != {"schema", "terminal_listed", "native_dispatch_reached",
                               "mocked_executor", "synthetic_response"}
            or packet["schema"] != "hermes-v0221-native-tool-scope-v1"
            or any(type(packet[name]) is not bool for name in (
                "terminal_listed", "native_dispatch_reached",
                "mocked_executor", "synthetic_response"))
            or not packet["mocked_executor"]):
        raise NativeScopeDenied("invalid_probe_contract")
    if not packet["terminal_listed"] and packet["native_dispatch_reached"]:
        status = "DIRECT_NATIVE_SCOPE_GAP_OBSERVED"
    elif not packet["terminal_listed"] and not packet["native_dispatch_reached"]:
        status = "DIRECT_NATIVE_SCOPE_BLOCK_OBSERVED"
    else:
        status = "UNEXPECTED_TOOL_SCOPE"
    return {
        "status": status,
        "pinned_image": IMAGE,
        "terminal_listed": packet["terminal_listed"],
        "native_dispatch_reached": packet["native_dispatch_reached"],
        "synthetic_response": packet["synthetic_response"],
        "real_tool_executed": False,
        "model_executed": False,
        "full_agent_surface_verified": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> dict[str, Any]:
    inspect, run = commands()
    try:
        metadata = runner(inspect, timeout=10, stdout_limit=8192, stderr_limit=16384)
        if metadata.returncode:
            raise NativeScopeDenied("image_missing")
        core.image_identity(metadata.stdout)
        result = runner(run, timeout=45, stdout_limit=4096, stderr_limit=16384)
        if result.returncode:
            raise NativeScopeDenied("inspector_failed")
        return validate(result.stdout)
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError, core.ParityDenied):
        raise NativeScopeDenied("offline_docker_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline direct native tool scope, always NO-GO")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        result = observe()
    except NativeScopeDenied:
        print(json.dumps({"status": "NO_DATA", "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
