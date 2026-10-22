#!/usr/bin/env python3
"""#454 owner-host only: prepare a verified OCI or approve a one-time cutover."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys

from scripts.h15_brc_owner_artifact_stage import discover, stage, StagingDenied
from scripts.h15_brc_upgrade_preflight import admit, UpgradeDenied
from scripts.h15_brc_transactional_upgrade import (
    APPROVAL, CutoverDenied, main as transactional_main,
)

BACKUP_ROOT = Path("/var/backups/hermes-brc-relay")
STAGING = BACKUP_ROOT / "verified-oci"
DECISION = "OWNER_APPROVED_LIVE_BRC_RELAY_CUTOVER"
SCOPE = "EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE"


class HandoffDenied(ValueError):
    pass


def refuse(reason):
    raise HandoffDenied(reason)


def private_root_directory(path):
    if path.is_symlink() or not path.is_dir():
        refuse("private_directory_missing")
    info = path.stat()
    if (info.st_uid != 0 or info.st_gid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700):
        refuse("private_directory_not_root_0700")


def check_host():
    if os.geteuid() != 0:
        refuse("owner_host_root_required")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        refuse("owner_host_must_be_linux_amd64")
    private_root_directory(BACKUP_ROOT)
    if not Path("/var/run/docker.sock").is_socket():
        refuse("host_docker_socket_unavailable")


def doctor():
    """Sanitized read-only diagnostics; never print secrets or Docker inspect."""
    names = ("docker", "gh", "zstd", "python3")
    programs = {n: shutil.which(n) is not None for n in names}
    checks = {
        "linux_amd64": platform.system() == "Linux" and platform.machine() == "x86_64",
        "root": os.geteuid() == 0,
        "host_docker_socket": Path("/var/run/docker.sock").is_socket(),
        "backup_directory_exists": BACKUP_ROOT.is_dir() and not BACKUP_ROOT.is_symlink(),
        "existing_approval": APPROVAL.exists() or APPROVAL.is_symlink(),
    }
    reachable = False
    if programs["docker"] and checks["root"] and checks["host_docker_socket"]:
        try:
            result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                    capture_output=True, text=True, timeout=8)
            reachable = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    checks["docker_reachable"] = reachable
    return {"status": "READ_ONLY_HOST_DIAGNOSTIC", "programs": programs,
            "checks": checks, "service_changed": False, "secrets_displayed": False}


def prepare():
    check_host()
    if APPROVAL.exists() or APPROVAL.is_symlink():
        refuse("previous_approval_needs_manual_review")
    if not STAGING.exists():
        STAGING.mkdir(mode=0o700)
    private_root_directory(STAGING)
    selected = discover()
    result = stage(STAGING, selected, load=True)
    if result.get("status") != "IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER":
        refuse("staging_and_owner_admission_failed")
    result["cutover_approved"] = False
    return result


def make_approval(result, old):
    if (result.get("status") != "IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER"
            or result.get("live_relay_changed") is not False
            or not isinstance(old, str) or not old.startswith("sha256:")):
        refuse("untrusted_approval_request")
    return {
        "schema": 1, "decision": DECISION, "scope": SCOPE,
        "image_id": result["image_id"], "previous_image_id": old,
        "archive_sha256": result["archive_sha256"], "hermes_commit": result["source_sha"]
    }


@contextmanager
def temporary_approval(doc):
    """Create exclusive root-only approval; clean only our own inode on exit."""
    private_root_directory(APPROVAL.parent)
    if APPROVAL.exists() or APPROVAL.is_symlink():
        refuse("existing_approval_not_overwritten")
    body = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(body) > 4096:
        refuse("approval_oversized")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(APPROVAL, flags, 0o600)
    except FileExistsError as exc:
        raise HandoffDenied("approval_creation_raced") from exc
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        yield
    finally:
        try:
            now = APPROVAL.lstat()
        except FileNotFoundError:
            pass
        else:
            if (now.st_ino == identity.st_ino and now.st_dev == identity.st_dev
                    and stat.S_ISREG(now.st_mode)):
                APPROVAL.unlink()


def execute():
    # Noninteractive MCP/CI calls are rejected BEFORE stage or Docker load.
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        refuse("interactive_owner_host_tty_required")
    check_host()
    result = prepare()
    image, original_sha, digest, bundle = (
        result["image_id"], result["source_sha"],
        result["archive_sha256"], result["staging_dir"])
    admit_result = admit(Path(bundle), image, digest, original_sha)
    if admit_result.get("status") != "PREFLIGHT_PASS":
        refuse("live_relay_admission_failed")
    old = admit_result["current_image"]
    phrase = "APPLY BRC " + image[-12:]
    print("Existing relay will restart. Old container and SQLite backup retained.")
    print("Image:", image, " Source:", original_sha, " Previous:", old)
    print("Confirm exactly:", phrase)
    try:
        answer = input("> ").strip()
    except (OSError, EOFError) as exc:
        raise HandoffDenied("owner_confirmation_unavailable") from exc
    if answer != phrase:
        refuse("owner_confirmation_denied")
    with temporary_approval(make_approval(result, old)):
        rc = transactional_main([
            "cutover", "--bundle-dir", bundle, "--image", image,
            "--archive-sha", digest, "--hermes-sha", original_sha, "--execute"])
    if rc != 0:
        refuse("transactional_cutover_or_rollback_failed")
    return {"status": "CUTOVER_PENDING_BOTH_CLIENTS_E2E",
            "candidate_image": image, "previous_image": old,
            "image_source_sha": original_sha, "original_container_retained": True,
            "actual_chatgpt_codex_mcp_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "prepare", "execute"))
    args = parser.parse_args(argv)
    try:
        answer = doctor() if args.action == "doctor" else (
            prepare() if args.action == "prepare" else execute())
    except (HandoffDenied, StagingDenied, UpgradeDenied, CutoverDenied,
            OSError, ValueError, KeyError) as exc:
        reason = str(exc) if isinstance(exc, HandoffDenied) else "existing_gate_refused"
        print(json.dumps({"status": "REFUSED", "reason": reason}, sort_keys=True))
        return 2
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
