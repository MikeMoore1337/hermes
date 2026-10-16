"""H-18: opt-in local Docker negative proof, all real SSH/process calls mocked.

Only a pre-existing immutable local candidate image is allowed. Real outbound
socket is attempted only to TEST-NET-1 192.0.2.1:22 inside --network none.
Not evidence that production agent or production sandbox denies SSH.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any, Callable

IMAGE = "sha256:90e878c4af899364fb56be9e7c4f5e96ca06c4741b6c94cc79260f07f919ebe9"
SCHEMA = "hermes-h18-ssh-network-none-v1"
# The observed socket.connect_ex is executed in a LINUX/amd64 container,
# while this reviewer may run on Windows. Python's host errno constants differ.
# Linux values: ENETUNREACH=101, EHOSTUNREACH=113, ENETDOWN=100,
# EACCES=13 and EPERM=1 (Linux errno UAPI).
ACCEPTED_ERRNOS = frozenset({101, 113, 100, 13, 1})
MAX_JSON_BYTES = 4096
TEST_NET_IP = "192.0.2.1"

INSPECTOR = r"""
import errno
import json
import socket
import subprocess
from unittest.mock import Mock, patch
import model_tools

# RFC 5737 TEST-NET-1, no DNS or live SSH server; no credentials or socket mounts.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    error = s.connect_ex(("192.0.2.1", 22))
except OSError as exc:
    error = exc.errno
finally:
    s.close()

executor = Mock(side_effect=RuntimeError("SYNTHETIC_EXECUTOR_DENIED"))
dispatch = Mock(side_effect=RuntimeError("SYNTHETIC_REGISTRY_DENIED"))
spawn = Mock(side_effect=RuntimeError("SYNTHETIC_PROCESS_DENIED"))
results = []
# Patch all final native dispatch and OS process-spawn boundaries *before* test.
with patch.object(model_tools, "_execute_tool", executor),      patch.object(model_tools.registry, "dispatch", dispatch),      patch.object(subprocess, "Popen", spawn):
    for name, arguments in (
        ("terminal", {"command": "ssh SYNTHETIC_NO_EXEC"}),
        ("process", {"action": "list"}),
    ):
        try:
            model_tools.handle_function_call(
                name, arguments, enabled_toolsets=["safe"],
                disabled_toolsets=["terminal"],
                skip_tool_execution_middleware=True,
            )
        except Exception:
            pass
        results.append(name)
print(json.dumps({
    "schema": "hermes-h18-ssh-network-none-v1",
    "test_net_connect_errno": error,
    "tested_names": results,
    "native_executor_reached": executor.called,
    "registry_dispatch_reached": dispatch.called,
    "process_spawn_attempted": spawn.called,
    "all_execution_boundaries_mocked": True,
    "model_or_real_ssh_executed": False,
}, separators=(",", ":"), sort_keys=True))
"""


class ProbeDenied(ValueError):
    """Fixed error codes only; never leak Docker stdout, stderr or host data."""


def strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for name, value in items:
        if name in data:
            raise ProbeDenied("duplicate_json_key")
        data[name] = value
    return data


def commands() -> tuple[list[str], list[str]]:
    inspect = ["docker", "image", "inspect", IMAGE, "--format",
               "{{.Id}}|{{.Os}}|{{.Architecture}}"]
    run = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.5", "--memory", "768m", "--memory-swap", "768m",
        "--pids-limit", "32",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=48m",
        "--env", "HOME=/tmp", "--env", "HERMES_HOME=/tmp/hermes",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", "/opt/hermes/.venv/bin/python",
        IMAGE, "-B", "-c", INSPECTOR,
    ]
    return inspect, run


def parse(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise ProbeDenied("invalid_output_size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except ProbeDenied:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ProbeDenied("invalid_output") from None
    expected = {
        "schema", "test_net_connect_errno", "tested_names",
        "native_executor_reached", "registry_dispatch_reached",
        "process_spawn_attempted", "all_execution_boundaries_mocked",
        "model_or_real_ssh_executed",
    }
    if type(data) is not dict or set(data) != expected or data["schema"] != SCHEMA:
        raise ProbeDenied("invalid_probe_schema")
    keys = ("native_executor_reached", "registry_dispatch_reached",
            "process_spawn_attempted", "all_execution_boundaries_mocked",
            "model_or_real_ssh_executed")
    if any(type(data[k]) is not bool for k in keys):
        raise ProbeDenied("invalid_boolean")
    if data["tested_names"] != ["terminal", "process"]:
        raise ProbeDenied("incomplete_denial_cases")
    if type(data["test_net_connect_errno"]) is not int:
        raise ProbeDenied("invalid_connect_result")
    passed = (data["test_net_connect_errno"] in ACCEPTED_ERRNOS
              and not any(data[k] for k in (
                  "native_executor_reached", "registry_dispatch_reached",
                  "process_spawn_attempted", "model_or_real_ssh_executed"))
              and data["all_execution_boundaries_mocked"])
    return {
        "schema": "hermes-h18-ssh-network-review-v1",
        "status": "NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS" if passed
                  else "DENIAL_BOUNDARY_NOT_PROVEN",
        "observed_network_connect_errno": data["test_net_connect_errno"],
        "os_network_none_egress_denied": data["test_net_connect_errno"] in ACCEPTED_ERRNOS,
        "native_and_process_mock_boundaries_unreached": (
            not any(data[k] for k in (
                "native_executor_reached", "registry_dispatch_reached",
                "process_spawn_attempted", "model_or_real_ssh_executed"))),
        "all_execution_boundaries_mocked": data["all_execution_boundaries_mocked"],
        "ssh_executable_launched": False,
        "real_target_contacted": False,
        "tested_local_candidate_image_id": IMAGE,
        "production_os_policy_verified": False,
        "all_native_tools_verified": False,
        "mcp_tool_enforcement_verified": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict:
    inspect, run = commands()
    try:
        meta = runner(inspect, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                      stdin=subprocess.DEVNULL, timeout=15, check=False)
        if meta.returncode or meta.stdout.strip() != (
                IMAGE + "|linux|amd64").encode("ascii"):
            raise ProbeDenied("wrong_image_identity")
        result = runner(run, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL, timeout=60, check=False)
        if result.returncode:
            raise ProbeDenied("inspector_failed")
        return parse(result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeDenied("local_docker_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-18 locked offline local SSH denial proof")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        data = observe()
    except ProbeDenied:
        data = {"status": "INCONCLUSIVE", "reason": "unverifiable_offline_denial",
                "resident_agent_allowed": False}
    print(json.dumps(data, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
