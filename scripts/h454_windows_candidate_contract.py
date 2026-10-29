#!/usr/bin/env python3
"""H454: read-only, fail-closed Docker --init candidate parity gate.

Checks the owner Windows BRC original and a *stopped* candidate.  Never prints
Docker inspect payloads, env, mount sources, credentials, process arguments, or
tool stderr.  Does not create/start/stop/recreate containers or change tasks.
A PASS is *only* candidate config parity, not permission to cut over.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
from pathlib import Path
import subprocess
import sys
from typing import Any

ORIGINAL_ID = "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162"
IMAGE_ID = "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3"
ORIGINAL_NAME = "/hermes-h15-windows-permanent"
CANDIDATE_NAME = "/h454-init-stage-571a1e2b"
CANDIDATE_V2_NAME = "/h454-init-stage-571a1e2b-v2"
ALLOWED_CANDIDATES = frozenset((CANDIDATE_NAME, CANDIDATE_V2_NAME))
SCOPE = "h15-windows-owner-permanent"
REQUIRED_TMPFS = frozenset(("/run/brc", "/tmp"))
REQUIRED_TMPFS_FLAGS = {
    "/run/brc": frozenset(("rw", "nosuid", "nodev", "noexec", "uid=65534", "gid=65534", "mode=0700", "size=8m")),
    "/tmp": frozenset(("rw", "nosuid", "nodev", "noexec", "uid=65534", "gid=65534", "mode=0700", "size=64m")),
}
VOLATILE_CONFIG = frozenset(("Hostname", "Domainname", "MacAddress", "Image"))


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ContractHold(code)


class ContractHold(Exception):
    """Safe enum-only denial; never format untrusted contents."""


def _host(item: dict[str, Any]) -> dict[str, Any]:
    host = item.get("HostConfig")
    _need(isinstance(host, dict), "HOST_CONFIG")
    return host


def _cfg(item: dict[str, Any]) -> dict[str, Any]:
    cfg = item.get("Config")
    _need(isinstance(cfg, dict), "CONTAINER_CONFIG")
    return cfg


def _tmpfs(host: dict[str, Any]) -> dict[str, frozenset[str]]:
    value = host.get("Tmpfs")
    _need(isinstance(value, dict), "TMPFS")
    _need(frozenset(value) == REQUIRED_TMPFS, "TMPFS")
    parsed: dict[str, frozenset[str]] = {}
    for location in REQUIRED_TMPFS:
        options = value[location]
        _need(isinstance(options, str), "TMPFS")
        entries = options.split(",")
        _need(len(entries) == len(set(entries)), "TMPFS")
        parsed[location] = frozenset(entries)
        _need(parsed[location] == REQUIRED_TMPFS_FLAGS[location], "TMPFS")
    return parsed


def _normal_config(config: dict[str, Any]) -> dict[str, Any]:
    kept = copy.deepcopy(config)
    for key in VOLATILE_CONFIG:
        kept.pop(key, None)
    return kept


def _normalized_candidate_config(original: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Allow only Docker create's detached stdout/stderr attach default.

    An original made by docker run -d has AttachStdout/Stderr=False.
    A stopped docker create candidate may have these two booleans True.
    No stdin, tty, env, entrypoint, label or other difference is allowed.
    This is NOT an authorization to start/attach to the candidate.
    """
    normalized = _normal_config(candidate)
    for name in ("AttachStdout", "AttachStderr"):
        if original.get(name) is False and candidate.get(name) is True:
            normalized[name] = False
    return normalized


def _safe_diff_keys(left: dict[str, Any], right: dict[str, Any], excluded: frozenset[str]) -> list[str]:
    """Only field names, not values. Never serialize Docker inspect/env to stdout."""
    return sorted(
        key if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", key) else "OTHER"
        for key in (set(left) | set(right))
        if key not in excluded and left.get(key) != right.get(key)
    )


def diagnose(original: dict[str, Any], candidate: dict[str, Any], candidate_name: str) -> list[str]:
    """Read-only, fail-closed diff-key inspection for an already-created candidate."""
    _need(candidate_name in ALLOWED_CANDIDATES, "CANDIDATE_SELECTOR")
    _need(original.get("Id") == ORIGINAL_ID and original.get("Image") == IMAGE_ID, "ORIGINAL_IDENTITY")
    _need(original.get("Name") == ORIGINAL_NAME, "ORIGINAL_IDENTITY")
    _need((original.get("State") or {}).get("Running") is True, "ORIGINAL_NOT_RUNNING")
    _need(candidate.get("Name") == candidate_name and candidate.get("Image") == IMAGE_ID, "CANDIDATE_IDENTITY")
    _need((candidate.get("State") or {}).get("Status") == "created" and
          (candidate.get("State") or {}).get("Running") is False, "CANDIDATE_NOT_CREATED")
    config_keys = _safe_diff_keys(_cfg(original), _cfg(candidate), VOLATILE_CONFIG)
    host_keys = _safe_diff_keys(_host(original), _host(candidate), frozenset(("Init", "Tmpfs")))
    return [
        "H454_DIAGNOSTIC=PASS",
        "H454_CONFIG_DIFF_KEYS=" + ",".join(config_keys),
        "H454_HOST_DIFF_KEYS=" + ",".join(host_keys),
        "H454_CHANGES_APPLIED=FALSE",
        "H454_CUTOVER=NOT_PERFORMED",
    ]


def _normal_host(host: dict[str, Any]) -> dict[str, Any]:
    kept = copy.deepcopy(host)
    kept.pop("Init", None)
    tmpfs = kept.pop("Tmpfs", None)
    _need(isinstance(tmpfs, dict), "TMPFS")
    return kept


def _normalized_host_pair(
    original: dict[str, Any], candidate: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Match the Docker OOM-killer-enabled default without disabling OOM safety.

    Engine HostConfig.OomKillDisable is a nullable boolean: absent default
    setting is represented by JSON null or false. Both mean the OOM killer
    remains enabled. Explicit true, missing field, strings/numbers are
    forbidden even when both containers share the unsafe value.
    All other HostConfig keys remain strictly compared.
    """
    for host in (original, candidate):
        _need("OomKillDisable" in host, "OOM_FIELD_MISSING")
        _need(
            host["OomKillDisable"] is None or host["OomKillDisable"] is False,
            "OOM_KILLER_DISABLED_OR_INVALID",
        )
    old = _normal_host(original)
    new = _normal_host(candidate)
    old["OomKillDisable"] = False
    new["OomKillDisable"] = False
    return old, new


def _mount_contract(container: dict[str, Any]) -> list[dict[str, Any]]:
    mounts = container.get("Mounts")
    _need(isinstance(mounts, list), "MOUNTS")
    external = [mount for mount in mounts if mount.get("Type") != "tmpfs"]
    _need(len(external) == 1, "MOUNTS")
    mount = external[0]
    _need(mount.get("Destination") == "/workspace" and mount.get("Type") == "bind", "MOUNTS")
    _need(mount.get("RW") is True, "MOUNTS")
    selected = ("Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation")
    return [{key: mount.get(key) for key in selected}]


def verify(original: dict[str, Any], candidate: dict[str, Any], *, expected_candidate_name: str = CANDIDATE_NAME) -> str:
    """Raise ContractHold with a fixed reason, else return candidate-parity PASS."""
    _need(isinstance(original, dict) and isinstance(candidate, dict), "INVALID_INPUT")
    _need(expected_candidate_name in ALLOWED_CANDIDATES, "CANDIDATE_SELECTOR")
    _need(original.get("Id") == ORIGINAL_ID and candidate.get("Id") != ORIGINAL_ID, "IDENTITY")
    _need(isinstance(candidate.get("Id"), str) and len(candidate["Id"]) == 64, "IDENTITY")
    _need(original.get("Image") == IMAGE_ID and candidate.get("Image") == IMAGE_ID, "IMAGE")
    _need(original.get("Name") == ORIGINAL_NAME and candidate.get("Name") == expected_candidate_name, "NAME")

    oldstate = original.get("State") or {}
    newstate = candidate.get("State") or {}
    _need(oldstate.get("Running") is True, "ORIGINAL_NOT_RUNNING")
    _need(newstate.get("Running") is False and newstate.get("Status") == "created", "CANDIDATE_NOT_CREATED")

    oldhost, newhost = _host(original), _host(candidate)
    _need(newhost.get("Init") is True, "INIT_MISSING")
    _need(oldhost.get("PidsLimit") == 128 and newhost.get("PidsLimit") == 128, "PIDS_LIMIT")
    _need(oldhost.get("Memory") == 536870912, "MEMORY")
    _need(oldhost.get("ReadonlyRootfs") is True and oldhost.get("Privileged") is False, "ISOLATION")
    _need(oldhost.get("NetworkMode") == "bridge", "NETWORK")
    _need("ALL" in (oldhost.get("CapDrop") or []), "CAPABILITIES")
    _need("no-new-privileges" in (oldhost.get("SecurityOpt") or []), "SECURITY_OPTIONS")
    _need(_tmpfs(oldhost) == _tmpfs(newhost), "TMPFS")

    oldcfg, newcfg = _cfg(original), _cfg(candidate)
    _need(oldcfg.get("User") == "65534:65534", "USER")
    oldlabels = oldcfg.get("Labels") or {}
    _need(oldlabels.get("com.hermes.scope") == SCOPE, "LABELS")
    _need(_normal_config(oldcfg) == _normalized_candidate_config(oldcfg, newcfg), "CONFIG_DRIFT")
    canonical_old_host, canonical_new_host = _normalized_host_pair(oldhost, newhost)
    _need(canonical_old_host == canonical_new_host, "HOST_DRIFT")
    _need(_mount_contract(original) == _mount_contract(candidate), "MOUNT_DRIFT")
    return "PASS"


def _read_live(target: str, docker: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(docker), "container", "inspect", target],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=15, check=False,
    )
    _need(result.returncode == 0 and len(result.stdout) < 2_097_152, "INSPECT")
    objects = json.loads(result.stdout)
    _need(isinstance(objects, list) and len(objects) == 1 and isinstance(objects[0], dict), "INSPECT")
    return objects[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only H454 Windows candidate parity gate")
    parser.add_argument("--candidate-name", choices=sorted(n.lstrip("/") for n in ALLOWED_CANDIDATES), default=CANDIDATE_NAME.lstrip("/"))
    parser.add_argument("--diagnose", action="store_true", help="Print only differing Docker field names")
    args = parser.parse_args()
    try:
        _need(os.name == "nt", "OWNER_WINDOWS_REQUIRED")
        program_files = os.environ.get("ProgramFiles", "")
        _need(bool(program_files), "DOCKER_UNAVAILABLE")
        docker = Path(program_files) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
        _need(docker.is_file() and not docker.is_symlink(), "DOCKER_UNAVAILABLE")
        original = _read_live(ORIGINAL_ID, docker)
        candidate = _read_live(args.candidate_name, docker)
        if args.diagnose:
            for line in diagnose(original, candidate, "/" + args.candidate_name):
                print(line)
            return 0
        verify(original, candidate, expected_candidate_name="/" + args.candidate_name)
    except ContractHold as error:
        print("H454_CANDIDATE_CONTRACT=HOLD")
        print("H454_REASON=" + str(error))
        print("H454_CHANGES_APPLIED=FALSE")
        return 2
    except Exception:  # Fail closed; never echo inspect data or exception text.
        print("H454_CANDIDATE_CONTRACT=HOLD")
        print("H454_REASON=INSPECTION_UNAVAILABLE")
        print("H454_CHANGES_APPLIED=FALSE")
        return 2

    print("H454_CANDIDATE_CONTRACT=PASS")
    print("H454_INIT=TRUE")
    print("H454_TMPFS_PARITY=PASS")
    print("H454_IDENTITY_PRESERVED=TRUE")
    print("H454_CHANGES_APPLIED=FALSE")
    print("H454_CUTOVER_AUTHORIZED=FALSE")
    print("H454_CREDENTIAL_STAGE=NOT_TESTED")
    print("H454_RECONNECT=NOT_TESTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())