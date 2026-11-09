"""Hermes #454: strictly READ-ONLY SSH forced-command proof and native plan.

This module provides only a future restricted per-host installation *plan*
contract. It does NOT install/enable services, create accounts, ACLs, keys,
SSH users, alter BRC/WSS, start an agent or approve owner permissions.

The host administrator must separately provision a dedicated locked
non-root SSH forced-command identity with this exact operator pinned to
an immutable, separately approved release. Until then, every live plan
must fail closed and no GitHub workflow may elevate via old deploy SSH.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re

from device_fabric.native_install_preview import (
    InstallPlanDenied, inspect_linux_roots, parse_candidate,
)
from scripts.h454_native_install_preflight import _private_manifest

PROOF = "h454-native-proof-v1"
PLAN = re.compile(
    r"h454-native-plan-v1 (hermes-vps|yfc-vps) ([0-9a-f]{40}) ([0-9a-f]{64})\Z"
)
ALLOWED_TARGETS = frozenset({"hermes-vps", "yfc-vps"})

# Fixed operator-owned paths, not taken from SSH_ORIGINAL_COMMAND or MCP.
TARGET_FILE = Path("/etc/hermes-native-plan/target")
MANIFEST_FILE = Path("/var/lib/hermes-native-plan/candidate.json")
INSTALLED_SOURCE_SHA_FILE = Path("/var/lib/hermes-main-deploy/last-success.sha")
OPERATOR_USER = "hermes-native-plan"


class NativeHostPlanDenied(ValueError):
    """Sanitized denial; never expose original host path or SSH metadata."""


def _uid_ready() -> None:
    """Reject root or an unrelated host identity before reading manifests."""
    try:
        uid = os.geteuid()
        identity = pwd.getpwuid(uid)
        if (uid <= 0 or identity.pw_name != OPERATOR_USER
            or identity.pw_uid != uid):
            raise NativeHostPlanDenied("native_host_plan_denied")
    except (OSError, ValueError, KeyError):
        raise NativeHostPlanDenied("native_host_plan_denied") from None


def _read_fixed_line(path: Path, *, max_bytes: int = 80) -> str:
    """Read one root-provisioned regular config file, without symlinks."""
    fd = None
    try:
        if not path.is_absolute():
            raise NativeHostPlanDenied("native_host_plan_denied")
        for part in (path, *path.parents):
            if part.is_symlink():
                raise NativeHostPlanDenied("native_host_plan_denied")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if (not (st.st_mode & 0o170000) == 0o100000
            or st.st_uid != 0 or st.st_nlink != 1
            or st.st_mode & 0o022
            or not 0 < st.st_size <= max_bytes):
            raise NativeHostPlanDenied("native_host_plan_denied")
        raw = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        if (len(raw) != st.st_size
            or (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns,
                st.st_mode) !=
               (after.st_dev, after.st_ino, after.st_mtime_ns,
                after.st_ctime_ns, after.st_mode)):
            raise NativeHostPlanDenied("native_host_plan_denied")
        value = raw.decode("ascii")
        if value.endswith("\n"):
            value = value[:-1]
        if not value or "\r" in value or "\n" in value:
            raise NativeHostPlanDenied("native_host_plan_denied")
        return value
    except (OSError, ValueError, UnicodeError, AttributeError):
        raise NativeHostPlanDenied("native_host_plan_denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def inspect_request(command: str, *, host_target: str,
                    installed_source_sha: str,
                    manifest_bytes: bytes) -> dict[str, object]:
    """Pure plan evaluation; caller must verify actual host pins first."""
    if type(command) is not str or type(host_target) is not str:
        raise NativeHostPlanDenied("native_host_plan_denied")
    if host_target not in ALLOWED_TARGETS:
        raise NativeHostPlanDenied("native_host_plan_denied")
    if command == PROOF:
        return {"status": "FORCED_COMMAND_PROOF_READONLY",
                "schema": 1, "changes_applied": False,
                "install_authorized": False}
    parsed = PLAN.fullmatch(command)
    if parsed is None:
        raise NativeHostPlanDenied("native_host_plan_denied")
    target, release_sha, expected_manifest_sha = parsed.groups()
    if (target != host_target or installed_source_sha != release_sha
        or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha):
        raise NativeHostPlanDenied("native_host_plan_denied")
    try:
        candidate = parse_candidate(
            manifest_bytes, expected_release=release_sha,
            expected_target=target)
        local = inspect_linux_roots(candidate)
    except (InstallPlanDenied, OSError, ValueError, TypeError):
        raise NativeHostPlanDenied("native_host_plan_denied") from None
    if local.get("status") != "LOCAL_DIRECTORY_HANDLES_PASS":
        raise NativeHostPlanDenied("native_host_plan_denied")
    return {
        "schema": 1,
        "status": "READONLY_NATIVE_HOST_PLAN_VERIFIED",
        "target": target,
        "release_sha": release_sha,
        "manifest_sha256": expected_manifest_sha,
        "artifact_sha256": candidate.artifact_sha256,
        "roots_checked": len(candidate.roots),
        "changes_applied": False,
        "install_authorized": False,
        "owner_approved": False,
        "host_service_installed": False,
        "native_device_activated": False,
    }


def run_forced_command(command: str | None, *,
                       target_file: Path = TARGET_FILE,
                       manifest_file: Path = MANIFEST_FILE,
                       release_file: Path = INSTALLED_SOURCE_SHA_FILE) -> dict[str, object]:
    """Only PROOF or PLAN. Never accepts caller-provided filesystem paths."""
    _uid_ready()
    if type(command) is not str or len(command) > 180:
        raise NativeHostPlanDenied("native_host_plan_denied")
    target = _read_fixed_line(target_file)
    if target not in ALLOWED_TARGETS:
        raise NativeHostPlanDenied("native_host_plan_denied")
    if command == PROOF:
        return inspect_request(command, host_target=target,
                               installed_source_sha="", manifest_bytes=b"")
    if PLAN.fullmatch(command) is None:
        raise NativeHostPlanDenied("native_host_plan_denied")
    try:
        source_sha = _read_fixed_line(release_file)
        raw = _private_manifest(manifest_file)
    except (InstallPlanDenied, OSError, ValueError):
        raise NativeHostPlanDenied("native_host_plan_denied") from None
    return inspect_request(
        command, host_target=target,
        installed_source_sha=source_sha, manifest_bytes=raw)


def main() -> int:
    """SSH authorized_keys forced command entrypoint. No other CLI modes."""
    try:
        report = run_forced_command(os.environ.get("SSH_ORIGINAL_COMMAND"))
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (NativeHostPlanDenied, OSError, ValueError, TypeError):
        print(json.dumps({"status": "REFUSED", "reason": "NATIVE_PLAN_NO_GO",
                          "changes_applied": False,
                          "install_authorized": False},
                         sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
