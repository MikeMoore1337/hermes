"""H-19 opt-in *process-local* Linux execve/execveat seccomp proof.

This runs only within the disposable, pinned networkless v0.22.2 container.
It does NOT install seccomp into the H-01 production agent or Docker daemon.
No live model, agent tool, provider, secrets or production endpoint is used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0222_immutable import IMAGE, commands, image_identity

SCHEMA = "h19-process-local-execve-seccomp-v1"
# The only shell execution here is a fixed, harmless 'printf' in isolated
# Docker, first without, and then after installing a kernel seccomp filter.
# Python is the ENTRYPOINT and already started when the filter is installed.
PROBE = r"""
import ctypes
import errno
import json
import os
import platform
import subprocess

def output(**fields):
    print(json.dumps(fields, sort_keys=True, separators=(",", ":")))

if platform.machine() != "x86_64":
    output(status="UNSUPPORTED_ARCH")
    raise SystemExit(2)

class Rule(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

class Filter(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Rule))]

# Linux seccomp_data: syscall number at 0, AUDIT_ARCH at 4.
# BPF exits on non-x86_64; all x32 ABI calls are blocked.
# On native x86_64, execve (59) and execveat (322) return EPERM.
# This is a narrow experimental deny-list, NOT a complete syscall sandbox.
rules = (Rule * 11)(
    Rule(0x20, 0, 0, 4),
    Rule(0x15, 1, 0, 0xC000003E),
    Rule(0x06, 0, 0, 0x80000000),
    Rule(0x20, 0, 0, 0),
    Rule(0x45, 0, 1, 0x40000000),
    Rule(0x06, 0, 0, 0x00050001),
    Rule(0x15, 0, 1, 59),
    Rule(0x06, 0, 0, 0x00050001),
    Rule(0x15, 0, 1, 322),
    Rule(0x06, 0, 0, 0x00050001),
    Rule(0x06, 0, 0, 0x7FFF0000),
)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]

# Baseline: actual non-writing process execution in the same container,
# before the filter is installed. No host commands or agent tool execution.
try:
    baseline = subprocess.run(
        ["/bin/sh", "-c", "printf H19_SAFE_EXEC_BASELINE"],
        capture_output=True, timeout=3, check=False,
        cwd="/", env={"PATH": "/usr/bin:/bin"})
    before = ("EXECUTED" if baseline.returncode == 0
              and baseline.stdout == b"H19_SAFE_EXEC_BASELINE"
              else "UNVERIFIED")
except (OSError, subprocess.TimeoutExpired):
    before = "UNVERIFIED"

no_new_privs = libc.prctl(38, 1, 0, 0, 0) == 0
prog = Filter(len(rules), rules)
installed = (no_new_privs and
             libc.prctl(22, 2, ctypes.addressof(prog), 0, 0) == 0)
after = "UNVERIFIED"
direct = "UNVERIFIED"
at = "UNVERIFIED"
x32 = "UNVERIFIED"
if installed:
    try:
        child = subprocess.run(
            ["/bin/sh", "-c", "printf H19_SHOULD_NOT_EXECUTE"],
            capture_output=True, timeout=3, check=False,
            cwd="/", env={"PATH": "/usr/bin:/bin"})
        after = "EXECUTED" if child.returncode == 0 else "UNVERIFIED"
    except OSError as exc:
        after = "BLOCKED_EPERM" if exc.errno == errno.EPERM else "UNVERIFIED"
    except subprocess.TimeoutExpired:
        after = "UNVERIFIED"

    # Nonexistent path guarantees there is no filesystem side effect even
    # when the filter is broken: errno must be EPERM, not ENOENT.
    try:
        os.execve("/h19-nonexistent-execve-test", ["h19"], {})
        direct = "EXECUTED"
    except OSError as exc:
        direct = "BLOCKED_EPERM" if exc.errno == errno.EPERM else "UNVERIFIED"

    libc.syscall.restype = ctypes.c_long
    for syscall_nr, key in ((322, "at"), (0x40000000 | 59, "x32")):
        ctypes.set_errno(0)
        ret = libc.syscall(ctypes.c_long(syscall_nr), ctypes.c_long(-100),
                           ctypes.c_char_p(b"/h19-nonexistent-execveat-test"),
                           ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_long(0))
        outcome = ("BLOCKED_EPERM" if ret == -1 and
                   ctypes.get_errno() == errno.EPERM else "UNVERIFIED")
        if key == "at":
            at = outcome
        else:
            x32 = outcome

output(
    schema="h19-process-local-execve-seccomp-v1",
    arch="linux/amd64",
    baseline_shell=before,
    no_new_privs=no_new_privs,
    filter_installed=installed,
    kernel_seccomp_mode=libc.prctl(21, 0, 0, 0, 0),
    guarded_subprocess_shell=after,
    guarded_direct_execve=direct,
    guarded_execveat=at,
    guarded_x32_execve=x32,
    model_executed=False,
    real_agent_tools_executed=False,
    full_os_enforcement_verified=False,
    h01_resident_allowed=False,
)
"""

EXPECTED_FIELDS = frozenset({
    "schema", "arch", "baseline_shell", "no_new_privs", "filter_installed",
    "kernel_seccomp_mode", "guarded_subprocess_shell",
    "guarded_direct_execve", "guarded_execveat", "guarded_x32_execve",
    "model_executed", "real_agent_tools_executed",
    "full_os_enforcement_verified", "h01_resident_allowed",
})


class EvidenceDenied(ValueError):
    """Invalid or overclaiming experimental kernel receipt."""


def validate(data: Any) -> dict[str, Any]:
    if (type(data) is not dict or set(data) != EXPECTED_FIELDS
            or data.get("schema") != SCHEMA or data.get("arch") != "linux/amd64"
            or any(data.get(key) is not False for key in (
                "model_executed", "real_agent_tools_executed",
                "full_os_enforcement_verified", "h01_resident_allowed"))):
        raise EvidenceDenied("invalid_report_contract")
    passed = (
        data["baseline_shell"] == "EXECUTED"
        and data["no_new_privs"] is True
        and data["filter_installed"] is True
        and type(data["kernel_seccomp_mode"]) is int
        and data["kernel_seccomp_mode"] == 2
        and all(data[key] == "BLOCKED_EPERM" for key in (
            "guarded_subprocess_shell", "guarded_direct_execve",
            "guarded_execveat", "guarded_x32_execve"))
    )
    allowed = {"EXECUTED", "BLOCKED_EPERM", "UNVERIFIED"}
    if (type(data["baseline_shell"]) is not str or
            data["baseline_shell"] not in allowed
            or any(type(data[key]) is not str or data[key] not in allowed for key in (
                "guarded_subprocess_shell", "guarded_direct_execve",
                "guarded_execveat", "guarded_x32_execve"))
            or type(data["no_new_privs"]) is not bool
            or type(data["filter_installed"]) is not bool
            or type(data["kernel_seccomp_mode"]) is not int):
        raise EvidenceDenied("invalid_os_receipt")
    return {
        "schema": SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "evidence_kind": "real_process_local_seccomp_in_disposable_container",
        "image": IMAGE,
        "shell_executed_before_filter": data["baseline_shell"] == "EXECUTED",
        "shell_execve_blocked_after_filter": passed,
        "observations": data,
        "full_agent_os_enforcement": "UNVERIFIED",
        "live_model": "NOT_RUN",
        "h01_resident_allowed": False,
    }


def run(*, runner=run_bounded) -> tuple[int, dict[str, Any]]:
    # Reuses the pinned v0.22.2 exact-digest, nonroot, no-egress sandbox
    # command (the same verified template used by H-19 #322/#323).
    image_inspect, _, docker_cmd = commands()
    try:
        metadata = runner(image_inspect, timeout=20, stdout_limit=8192, stderr_limit=8192)
        if metadata.returncode or not image_identity(metadata.stdout):
            raise EvidenceDenied("image_mismatch")
        cmd = list(docker_cmd)
        cmd[-1] = PROBE
        child = runner(cmd, timeout=65, stdout_limit=4096, stderr_limit=4096)
        if child.returncode:
            raise EvidenceDenied("probe_process_failed")
        data = json.loads(child.stdout)
        report = validate(data)
        return (0 if report["status"] == "PASS" else 1), report
    except (OSError, BoundedProcessError, UnicodeError, ValueError, TypeError,
            KeyError):
        return 2, {
            "schema": SCHEMA, "status": "INFRA_FAILURE",
            "h01_resident_allowed": False, "full_agent_os_enforcement": "UNVERIFIED",
            "live_model": "NOT_RUN",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"schema": SCHEMA, "status": "NOT_RUN",
                          "h01_resident_allowed": False}))
        return 0
    code, report = run()
    if args.out:
        try:
            args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                                encoding="utf-8")
        except OSError:
            return 2
    print("H-19 process-local seccomp:", report["status"],
          "(H-01 OS enforcement UNVERIFIED; real model NOT_RUN)")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
