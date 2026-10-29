#!/usr/bin/env python3
"""H454: owner-Windows-only creation of one STOPPED, parity-checked init candidate.

Default: read-only preflight. --create --owner-approved: docker container create
for one pinned candidate; never starts/stops/removes any container. Does not
read DPAPI secrets, call SSH, emit inspect/env/mount metadata or modify tasks.
"""
from __future__ import annotations

import argparse
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from h454_windows_candidate_contract import (
    CANDIDATE_V2_NAME,
    IMAGE_ID,
    ORIGINAL_ID,
    ORIGINAL_NAME,
    REQUIRED_TMPFS_FLAGS,
    SCOPE,
    ContractHold,
    verify,
)

CANDIDATE = CANDIDATE_V2_NAME.lstrip("/")
TASK_NAME = "HermesH15BRCWindows"


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractHold(code)


def docker_call(binary: Path, args: list[str], *, max_bytes: int = 2_097_152) -> str:
    result = subprocess.run(
        [str(binary), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=25,
    )
    require(result.returncode == 0 and len(result.stdout) <= max_bytes, "DOCKER_CALL")
    return result.stdout.decode("utf-8")


def inspect(binary: Path, kind: str, identifier: str) -> dict[str, Any]:
    raw = docker_call(binary, [kind, "inspect", identifier])
    obj = json.loads(raw)
    require(isinstance(obj, list) and len(obj) == 1 and isinstance(obj[0], dict), "INSPECT")
    return obj[0]


def canonical(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value.rstrip("\\/")))


def check_original(original: dict[str, Any], image: dict[str, Any]) -> str:
    """Return a private bind source only after fail-closed contract validation."""
    require(original.get("Id") == ORIGINAL_ID, "ORIGINAL_IDENTITY")
    require(original.get("Name") == ORIGINAL_NAME, "ORIGINAL_IDENTITY")
    require(original.get("Image") == IMAGE_ID and image.get("Id") == IMAGE_ID, "IMAGE_IDENTITY")
    require(original.get("State", {}).get("Running") is True, "ORIGINAL_NOT_RUNNING")
    cfg, host = original.get("Config"), original.get("HostConfig")
    img_cfg = image.get("Config")
    require(isinstance(cfg, dict) and isinstance(host, dict) and isinstance(img_cfg, dict), "INSPECT")
    require(cfg.get("User") == "65534:65534" and cfg.get("WorkingDir") == "/workspace", "USER_WORKDIR")
    require(cfg.get("Entrypoint") == ["/bin/sh", "/usr/local/bin/h15-entry.sh"], "ENTRYPOINT")
    require(cfg.get("Entrypoint") == img_cfg.get("Entrypoint"), "IMAGE_ENTRYPOINT")
    require(cfg.get("Cmd") == img_cfg.get("Cmd"), "IMAGE_CMD")
    require(cfg.get("Env") == img_cfg.get("Env"), "ENV_NOT_IMAGE_DEFAULT")
    expected_labels = dict(img_cfg.get("Labels") or {})
    expected_labels["com.hermes.scope"] = SCOPE
    require(cfg.get("Labels") == expected_labels, "LABELS_NOT_IMAGE_DEFAULT")
    require(host.get("PidsLimit") == 128 and host.get("Memory") == 536870912, "LIMITS")
    require(host.get("NanoCpus") == 1_000_000_000, "CPU_LIMIT")
    require(host.get("ReadonlyRootfs") is True and host.get("Privileged") is False, "ISOLATION")
    require(host.get("NetworkMode") == "bridge", "NETWORK")
    require(set(host.get("CapDrop") or []) == {"ALL"}, "CAP_DROP")
    require(set(host.get("SecurityOpt") or []) == {"no-new-privileges"}, "SECURITY_OPTS")
    require(host.get("RestartPolicy", {}).get("Name") == "no", "RESTART_POLICY")
    require(host.get("Init") is not True, "ORIGINAL_INIT_DRIFT")
    tmpfs = host.get("Tmpfs")
    require(isinstance(tmpfs, dict) and set(tmpfs) == set(REQUIRED_TMPFS_FLAGS), "TMPFS")
    for name, flags in REQUIRED_TMPFS_FLAGS.items():
        require(isinstance(tmpfs[name], str) and set(tmpfs[name].split(",")) == flags, "TMPFS")
    mounts = original.get("Mounts")
    require(isinstance(mounts, list), "MOUNT")
    bind_mounts = [m for m in mounts if isinstance(m, dict) and m.get("Type") != "tmpfs"]
    require(len(bind_mounts) == 1, "MOUNT")
    m = bind_mounts[0]
    require(m.get("Type") == "bind" and m.get("Destination") == "/workspace" and m.get("RW") is True, "MOUNT")
    source = m.get("Source")
    require(isinstance(source, str) and len(source) > 3, "MOUNT_SOURCE")
    # Docker Desktop may expose a translated Linux-side mount path even
    # when the Windows CLI originally passed a Windows source. Accept only
    # the exact native owner folder or two known Docker Desktop translations.
    owner_workspace = Path.home() / "Hermes-H15-Test"
    expected = str(owner_workspace)
    drive, tail = ntpath.splitdrive(expected)
    approved = {canonical(expected)}
    if len(drive) == 2 and drive[1] == ":" and drive[0].isalpha():
        unix_tail = tail.replace("\\", "/").lstrip("/")
        letter = drive[0].lower()
        approved.update({
            canonical(f"/run/desktop/mnt/host/{letter}/{unix_tail}"),
            canonical(f"/host_mnt/{letter}/{unix_tail}"),
        })
    require(canonical(source) in approved, "BIND_SOURCE_NOT_OWNER_WORKSPACE")
    require(
        owner_workspace.is_dir()
        and not owner_workspace.is_symlink()
        and not getattr(owner_workspace, "is_junction", lambda: False)(),
        "BIND_SOURCE_NOT_DIRECTORY",
    )
    # Pass the owner-native path to Docker CLI, as the pinned launcher does.
    return expected


def build_create_args(source: str) -> list[str]:
    """Fixed explicit Docker flags only; no Env, token, host execution or shell."""
    return [
        "container", "create", "--pull", "never",
        "--name", CANDIDATE,
        "--init",
        "--label", f"com.hermes.scope={SCOPE}",
        "--network", "bridge", "--read-only",
        "--user", "65534:65534", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
        "--mount", f"type=bind,source={source},target=/workspace",
        "--tmpfs", "/run/brc:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=64m",
        "--workdir", "/workspace", IMAGE_ID,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="H454 protected owner-Windows candidate preparation")
    parser.add_argument("--create", action="store_true", help="Create exactly one stopped candidate")
    parser.add_argument("--owner-approved", action="store_true", help="Explicit owner gate")
    args = parser.parse_args()
    created = False
    create_attempted = False
    try:
        require(os.name == "nt", "OWNER_WINDOWS_REQUIRED")
        require(not args.owner_approved or args.create, "APPROVAL_WITHOUT_CREATE")
        require(not args.create or args.owner_approved, "OWNER_APPROVAL_REQUIRED")
        program_files = os.environ.get("ProgramFiles", "")
        require(bool(program_files), "DOCKER_NOT_FOUND")
        docker = Path(program_files) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
        require(docker.is_file() and not docker.is_symlink(), "DOCKER_NOT_FOUND")
        original = inspect(docker, "container", ORIGINAL_ID)
        image = inspect(docker, "image", IMAGE_ID)
        source = check_original(original, image)
        # Ensure the existing failed attempt remains a stopped rollback artifact.
        from h454_windows_candidate_contract import CANDIDATE_NAME
        old_attempt = inspect(docker, "container", CANDIDATE_NAME.lstrip("/"))
        require(old_attempt.get("State", {}).get("Running") is False, "OLD_CANDIDATE_ACTIVE")
        # No candidate v2 should exist. Docker inspect --type container is
        # considered safer than ambiguous image/container shorthand.
        probe = subprocess.run(
            [str(docker), "container", "inspect", CANDIDATE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
        require(probe.returncode != 0, "CANDIDATE_ALREADY_EXISTS")
        if args.create:
            # No user-controlled command, extra mounts, secret env or HTTP calls.
            create_attempted = True
            docker_call(docker, build_create_args(source), max_bytes=1024)
            created = True
            candidate = inspect(docker, "container", CANDIDATE)
            verify(original, candidate, expected_candidate_name=CANDIDATE_V2_NAME)
    except ContractHold as error:
        print("H454_CREATE_CANDIDATE=HOLD")
        print("H454_REASON=" + str(error))
        print("H454_CANDIDATE_CREATE_ATTEMPTED=" + ("TRUE" if create_attempted else "FALSE"))
        print("H454_ORIGINAL_CHANGED=FALSE")
        return 2
    except Exception:
        print("H454_CREATE_CANDIDATE=HOLD")
        print("H454_REASON=INTERNAL_UNAVAILABLE")
        print("H454_CANDIDATE_CREATE_ATTEMPTED=" + ("TRUE" if create_attempted else "FALSE"))
        print("H454_ORIGINAL_CHANGED=FALSE")
        return 2
    print("H454_PREFLIGHT=PASS")
    print("H454_CREATE_CANDIDATE=" + ("PASS_CREATED_STOPPED" if created else "READY_OWNER_GATE"))
    print("H454_ORIGINAL_CHANGED=FALSE")
    print("H454_CANDIDATE_INIT=" + ("TRUE" if created else "NOT_CREATED"))
    print("H454_CUTOVER_AUTHORIZED=FALSE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
