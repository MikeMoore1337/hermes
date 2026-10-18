"""Read-only Linux offline isolation evidence for Hermes #349.

This proves a *subset* of kernel controls. It NEVER authorizes network/model
execution and does not set OperatorGates. No dependencies, service or secrets.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys


MEMORY_CEILING = 768 * 1024 * 1024
CPU_CEILING = 0.45
PIDS_CEILING = 32


def _read(path: Path, limit: int = 16384) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing_or_linked_kernel_file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("kernel_file_too_large")
    return raw.decode("ascii", "strict")


def _status(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            result[name] = value.strip()
    return result


def _cgroup_relative(text: str) -> Path:
    entries = [line.split(":", 2) for line in text.splitlines()]
    paths = [parts[2] for parts in entries
             if len(parts) == 3 and parts[0] == "0" and parts[1] == ""]
    if len(paths) != 1:
        raise ValueError("cgroup_v2_not_found")
    path = paths[0]
    if not path.startswith("/") or ".." in Path(path).parts or "\x00" in path:
        raise ValueError("cgroup_path_invalid")
    return Path(path.lstrip("/"))


def inspect_offline_controls(*, proc: Path = Path("/proc"),
                             cgroup: Path = Path("/sys/fs/cgroup"),
                             interfaces: Path = Path("/sys/class/net"),
                             effective_uid: int | None = None,
                             require_linux: bool = True) -> dict:
    """Observations only. Even PASS never permits a model request or network.

    `proc`/`cgroup`/`interfaces` overrides are solely for synthetic tests;
    a production caller must use the defaults and verify its actual PID.
    """
    uid = os.geteuid() if effective_uid is None else effective_uid
    observed = {"nonroot": False, "no_new_privileges": False,
                "no_effective_capabilities": False, "no_bounding_capabilities": False,
                "seccomp_filter": False, "private_cgroup_limits": False,
                "only_loopback_interface": False}
    result = {"schema_version": 1, "checks": observed,
              "actual_outbound_deny_test": "NOT_PERFORMED",
              "provider_cost_cap": "NOT_VERIFIED",
              "live_model_execution_allowed": False,
              "status": "NO_GO"}
    if (require_linux and not sys.platform.startswith("linux")) or uid == 0:
        return result
    observed["nonroot"] = True
    try:
        status = _status(_read(proc / "self" / "status"))
        observed["no_new_privileges"] = status.get("NoNewPrivs") == "1"
        observed["no_effective_capabilities"] = status.get("CapEff") == "0000000000000000"
        observed["no_bounding_capabilities"] = status.get("CapBnd") == "0000000000000000"
        observed["seccomp_filter"] = status.get("Seccomp") == "2"
        rel = _cgroup_relative(_read(proc / "self" / "cgroup"))
        scoped = cgroup / rel
        if scoped.resolve().is_relative_to(cgroup.resolve()):
            mem = _read(scoped / "memory.max").strip()
            cpu = _read(scoped / "cpu.max").strip().split()
            pids = _read(scoped / "pids.max").strip()
            if (mem.isdecimal() and pids.isdecimal() and len(cpu) == 2
                    and all(x.isdecimal() for x in cpu)
                    and 0 < int(mem) <= MEMORY_CEILING
                    and 0 < int(pids) <= PIDS_CEILING
                    and int(cpu[1]) > 0
                    and 0 < int(cpu[0]) / int(cpu[1]) <= CPU_CEILING + 1e-9):
                observed["private_cgroup_limits"] = True
        if interfaces.is_dir() and not interfaces.is_symlink():
            observed["only_loopback_interface"] = (
                sorted(p.name for p in interfaces.iterdir()) == ["lo"])
    except (OSError, ValueError, UnicodeError, OverflowError):
        pass
    if all(observed.values()):
        result["status"] = "OFFLINE_OS_CONTROLS_OBSERVED"
    return result


def main() -> int:
    evidence = inspect_offline_controls()
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["status"] == "OFFLINE_OS_CONTROLS_OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
