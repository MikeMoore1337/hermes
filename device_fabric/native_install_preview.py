"""Hermes #454 native installation *preflight*, not installation or authorization.

Validate a candidate's exact release/artifact identity and user-reviewed
original workspace roots without creating a service, OS account, ACL, key,
process, socket, or mount. No production mutations, no native agent activation.

This portable contract is an input to a FUTURE independently owner-approved
Windows GUI installer or Linux forced-command operator; a valid candidate
is NOT an authenticated owner consent or permission to execute anything.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import unicodedata

SCHEMA = "h454-native-install-candidate-v1"
MAX_MANIFEST_BYTES = 8192
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = frozenset({"windows", "hermes-vps", "yfc-vps"})
PINNED_PROJECTS = frozenset({
    "hermes", "your-fitness-coach", "ai-development-toolkit",
    "financial-horizon", "second-brain",
})
WINDOWS_ROOTS = {
    "hermes": r"D:\Pet-projects\hermes",
    "your-fitness-coach": r"D:\Pet-projects\your-fitness-coach",
    "ai-development-toolkit": r"D:\Pet-projects\ai-development-toolkit",
    "financial-horizon": r"D:\Pet-projects\financial-horizon",
    "second-brain": r"D:\Pet-projects\second-brain-workspace\second-brain",
}
SERVICE = {
    "windows": ("HermesCommanderNative", r"NT SERVICE\HermesCommanderNative"),
    "hermes-vps": ("hermes-commander-native.service", "hermes-commander-native"),
    "yfc-vps": ("hermes-commander-native.service", "hermes-commander-native"),
}
BLOCKED_LINUX_ANCESTORS = frozenset({
    "/etc", "/root", "/proc", "/sys", "/dev", "/run",
    "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/lib",
})
BLOCKED_COMPONENTS = frozenset({
    ".git", ".ssh", ".aws", ".gnupg", "node_modules",
    ".env", ".secrets", "secrets", "credentials", "vault",
    "private-vault", ".vault", "docker.sock",
})
TOP_KEYS = frozenset({
    "schema", "target", "release_sha", "artifact_sha256", "service_name",
    "service_identity", "start_state", "access_mode", "roots",
})
ROOT_KEYS = frozenset({"project", "path"})


class InstallPlanDenied(ValueError):
    """No untrusted paths, requested commands, secret values or OS errors."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for name, value in pairs:
        if name in output:
            raise InstallPlanDenied("native_install_plan_denied")
        output[name] = value
    return output


def _linux_root(value: str) -> bool:
    if (type(value) is not str or not value.startswith("/")
        or value.startswith("//") or value == "/"
        or value.endswith("/") or "\\" in value
        or unicodedata.normalize("NFC", value) != value):
        return False
    try:
        if len(value.encode("utf-8")) > 1024:
            return False
    except UnicodeError:
        return False
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        return False
    parts = value.split("/")[1:]
    if (not parts or any(not part or part in (".", "..")
                         or part.casefold() in BLOCKED_COMPONENTS
                         or part.endswith((" ", ".")) for part in parts)):
        return False
    if any(value == denied or value.startswith(denied + "/")
           for denied in BLOCKED_LINUX_ANCESTORS):
        return False
    return True


@dataclass(frozen=True, slots=True)
class InstallCandidate:
    """Immutable, syntactic only. NEVER a host install or privilege permit."""

    target: str
    release_sha: str
    artifact_sha256: str
    service_name: str
    service_identity: str
    roots: tuple[tuple[str, str], ...]
    manifest_sha256: str


def parse_candidate(raw: bytes, *, expected_release: str,
                    expected_target: str) -> InstallCandidate:
    """Fail closed on JSON ambiguity and any wider Windows/Linux scope.

    expected_release and expected_target come from the trusted local
    operator/manual workflow, NEVER from the candidate itself.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST_BYTES
        or type(expected_release) is not str
        or SHA40.fullmatch(expected_release) is None
        or type(expected_target) is not str or expected_target not in TARGETS):
        raise InstallPlanDenied("native_install_plan_denied")
    try:
        data = json.loads(raw.decode("ascii"),
                          object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(data) is not dict or set(data) != TOP_KEYS
            or data["schema"] != SCHEMA
            or type(data["target"]) is not str or data["target"] != expected_target
            or type(data["release_sha"]) is not str
            or data["release_sha"] != expected_release
            or type(data["artifact_sha256"]) is not str
            or SHA64.fullmatch(data["artifact_sha256"]) is None
            or data["artifact_sha256"] == "0" * 64
            or data["release_sha"] == "0" * 40
            or type(data["service_name"]) is not str
            or type(data["service_identity"]) is not str
            or (data["service_name"], data["service_identity"]) != SERVICE[expected_target]
            or data["start_state"] != "DISABLED"
            or data["access_mode"] != "READ_ONLY"
            or type(data["roots"]) is not list
            or not 1 <= len(data["roots"]) <= 5):
            raise InstallPlanDenied("native_install_plan_denied")
        roots: list[tuple[str, str]] = []
        for root in data["roots"]:
            if (type(root) is not dict or set(root) != ROOT_KEYS
                or type(root["project"]) is not str
                or root["project"] not in PINNED_PROJECTS
                or type(root["path"]) is not str):
                raise InstallPlanDenied("native_install_plan_denied")
            roots.append((root["project"], root["path"]))
        if (len(set(project for project, _ in roots)) != len(roots)
            or len(set(path for _, path in roots)) != len(roots)):
            raise InstallPlanDenied("native_install_plan_denied")
        if expected_target == "windows":
            if (len(roots) != len(WINDOWS_ROOTS)
                or dict(roots) != WINDOWS_ROOTS):
                raise InstallPlanDenied("native_install_plan_denied")
        else:
            if any(not _linux_root(path) for _, path in roots):
                raise InstallPlanDenied("native_install_plan_denied")
            normalized = tuple(sorted(path for _, path in roots))
            if any(b.startswith(a + "/") for a, b in zip(normalized, normalized[1:])):
                raise InstallPlanDenied("native_install_plan_denied")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False).encode("ascii")
        if raw != canonical:
            raise InstallPlanDenied("native_install_plan_denied")
    except (ValueError, TypeError, KeyError, RecursionError,
            UnicodeError, OverflowError):
        raise InstallPlanDenied("native_install_plan_denied") from None
    return InstallCandidate(
        target=expected_target,
        release_sha=expected_release,
        artifact_sha256=data["artifact_sha256"],
        service_name=data["service_name"],
        service_identity=data["service_identity"],
        roots=tuple(sorted(roots)),
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )


def inspect_linux_roots(candidate: InstallCandidate) -> dict[str, object]:
    """Read only directory metadata and pinned kernel handles, no file data.

    A PASS proves only the *paths currently resolve* under this process.
    It does NOT attest the original owner's approval, systemd ACLs,
    cgroups, egress, service identity, or a real VPS.
    """
    if (type(candidate) is not InstallCandidate
        or candidate.target not in {"hermes-vps", "yfc-vps"}
        or sys.platform != "linux" or not hasattr(os, "geteuid")
        or os.geteuid() == 0
        or platform.machine().lower() not in {"x86_64", "aarch64"}):
        raise InstallPlanDenied("native_install_plan_denied")
    from device_fabric.linux_native_files import LinuxNativeFiles, NativeLinuxDenied

    try:
        for project, path in candidate.roots:
            with LinuxNativeFiles(root=Path(path), project=project):
                pass
    except (NativeLinuxDenied, OSError, ValueError, TypeError):
        raise InstallPlanDenied("native_install_plan_denied") from None
    return {
        "status": "LOCAL_DIRECTORY_HANDLES_PASS",
        "roots_checked": len(candidate.roots),
        "native_host_proven": False,
        "install_authorized": False,
        "changes_applied": False,
    }


def preview(candidate: InstallCandidate) -> dict[str, object]:
    """Sanitized preview. Nothing here establishes owner/host readiness."""
    if type(candidate) is not InstallCandidate:
        raise InstallPlanDenied("native_install_plan_denied")
    return {
        "schema": SCHEMA,
        "status": "CANDIDATE_SYNTAX_VALID",
        "target": candidate.target,
        "release_sha": candidate.release_sha,
        "artifact_sha256": candidate.artifact_sha256,
        "manifest_sha256": candidate.manifest_sha256,
        "service_name": candidate.service_name,
        "start_state": "DISABLED",
        "access_mode": "READ_ONLY",
        "roots_count": len(candidate.roots),
        "projects": [name for name, _ in candidate.roots],
        "original_paths": "REDACTED",
        "os_isolation_verified": False,
        "owner_operation_approved": False,
        "release_deploy_approved": False,
        "install_authorized": False,
        "changes_applied": False,
    }
