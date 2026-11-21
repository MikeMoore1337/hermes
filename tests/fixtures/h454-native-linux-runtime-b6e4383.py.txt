"""Hermes #454 Stage 2A: dormant Linux ORIGINAL-host native read runtime.

Bridges a protected LOCAL, owner-reviewed manifest and device configuration
to the existing read-only Linux kernel FD adapter and BRC outbound WSS wire.
No service, installer, new MCP endpoint, key enrollment, privileged SSH,
network call or host mutation happens on import or in --preflight.

An actual live invocation is deliberately only an INJECTED Python API that
requires separately verified OS isolation and a live revocation provider.
A CLI capable of activating a resident agent is NOT provided here.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable, Protocol, Any

try:
    import pwd
except ImportError:
    pwd = None  # Windows can import portable parser tests.

from device_fabric.linux_native_files import LinuxNativeFiles, NativeLinuxDenied
from device_fabric.linux_native_outbound import (
    ENDPOINT, LocalLinuxDeviceConfig, LinuxOutboundDenied,
    local_config, run_session,
)
from device_fabric.linux_native_read_dispatch import (
    LinuxOriginalReadDispatcher, NativeLinuxReadDenied,
)
from device_fabric.native_install_preview import (
    InstallCandidate, InstallPlanDenied, TARGETS,
    parse_candidate,
)
from scripts.h454_native_install_preflight import _private_manifest

SCHEMA = "h454-native-linux-runtime-config-v1"
EXPECTED_KEYS = frozenset({
    "schema", "target", "device_id", "token", "url",
    "release_sha", "manifest_sha256", "roots",
})
ROOT_KEYS = frozenset({"project", "path"})
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_CONFIG_BYTES = 8192


class RuntimeDenied(ValueError):
    """One sanitized denial. Never include tokens, host paths or exceptions."""


class Connector(Protocol):
    def __call__(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True, repr=False)
class PreparedRuntime:
    """Trusted local config snapshot, with deliberately redacted repr."""

    device: LocalLinuxDeviceConfig
    project_roots: tuple[tuple[str, str], ...]
    candidate: InstallCandidate

    def __repr__(self) -> str:
        return "PreparedRuntime(device=[REDACTED], project_roots=[REDACTED])"


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeDenied("native_linux_runtime_denied")
        result[key] = value
    return result


def _parse_config(raw: bytes, candidate: InstallCandidate) -> LocalLinuxDeviceConfig:
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_CONFIG_BYTES
        or type(candidate) is not InstallCandidate
        or candidate.target not in {"hermes-vps", "yfc-vps"}):
        raise RuntimeDenied("native_linux_runtime_denied")
    try:
        data = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(data) is not dict or set(data) != EXPECTED_KEYS
            or data["schema"] != SCHEMA
            or data["target"] != candidate.target
            or data["release_sha"] != candidate.release_sha
            or data["manifest_sha256"] != candidate.manifest_sha256
            or type(data["roots"]) is not list
            or not 1 <= len(data["roots"]) <= 5):
            raise RuntimeDenied("native_linux_runtime_denied")
        roots = []
        for root in data["roots"]:
            if (type(root) is not dict or set(root) != ROOT_KEYS
                or type(root["project"]) is not str
                or type(root["path"]) is not str):
                raise RuntimeDenied("native_linux_runtime_denied")
            roots.append((root["project"], root["path"]))
        if tuple(sorted(roots)) != candidate.roots:
            raise RuntimeDenied("native_linux_runtime_denied")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False).encode("ascii")
        if canonical != raw:
            raise RuntimeDenied("native_linux_runtime_denied")
        return local_config(
            target=data["target"], device_id=data["device_id"],
            token=data["token"], url=data["url"])
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError,
            UnicodeError, LinuxOutboundDenied):
        raise RuntimeDenied("native_linux_runtime_denied") from None


def _private_directory(directory: Path) -> None:
    """Enforce only a private *service-owned* config directory.

    Never infer ownership from the manifest. The future systemd unit and
    OS ACL/mount sandbox must independently protect the ancestor hierarchy.
    """
    try:
        if not isinstance(directory, Path) or not directory.is_absolute():
            raise RuntimeDenied("native_linux_runtime_denied")
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
            raise RuntimeDenied("native_linux_runtime_denied")
        for ancestor in directory.parents:
            st = ancestor.lstat()
            if (stat.S_ISLNK(st.st_mode)
                or not stat.S_ISDIR(st.st_mode)
                or st.st_mode & 0o022):
                raise RuntimeDenied("native_linux_runtime_denied")
    except (OSError, ValueError, TypeError):
        raise RuntimeDenied("native_linux_runtime_denied") from None


def _service_identity(target: str) -> None:
    """Require a dedicated unprivileged account, never root or Docker root.

    Actual systemd isolation, namespace and cgroup rules are NOT established
    by this test. A nonroot UID is necessary but not sufficient.
    """
    if (sys.platform != "linux" or pwd is None or not hasattr(os, "geteuid")
        or os.geteuid() == 0 or os.getegid() == 0
        or target not in {"hermes-vps", "yfc-vps"}):
        raise RuntimeDenied("native_linux_runtime_denied")
    try:
        expected = pwd.getpwnam("hermes-commander-native")
        if (expected.pw_uid != os.geteuid()
            or expected.pw_gid != os.getegid()
            or expected.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")):
            raise RuntimeDenied("native_linux_runtime_denied")
    except (KeyError, OSError, AttributeError, ValueError):
        raise RuntimeDenied("native_linux_runtime_denied") from None


def load_local_runtime(*, target: str, expected_release: str,
                       expected_manifest_sha256: str,
                       manifest_path: Path,
                       config_path: Path) -> PreparedRuntime:
    """Inspect LOCAL private files; never network or inspect file contents.

    Both file paths and manifest digest MUST originate from protected owner
    installation state, not from an MCP call or an arbitrary model prompt.
    A source-only successful check is NOT authorization to install/activate.
    """
    try:
        _service_identity(target)
        if (not isinstance(manifest_path, Path)
            or not isinstance(config_path, Path)
            or manifest_path == config_path
            or manifest_path.parent != config_path.parent
            or type(expected_manifest_sha256) is not str
            or SHA64.fullmatch(expected_manifest_sha256) is None):
            raise RuntimeDenied("native_linux_runtime_denied")
        _private_directory(manifest_path.parent)
        raw_manifest = _private_manifest(manifest_path)
        digest = hashlib.sha256(raw_manifest).hexdigest()
        if digest != expected_manifest_sha256:
            raise RuntimeDenied("native_linux_runtime_denied")
        candidate = parse_candidate(
            raw_manifest, expected_release=expected_release,
            expected_target=target)
        device = _parse_config(_private_manifest(config_path), candidate)
        return PreparedRuntime(device, candidate.roots, candidate)
    except Exception:
        # Filesystem / parsing / account providers can include the private
        # paths or credentials in error arguments. Never surface them.
        raise RuntimeDenied("native_linux_runtime_denied") from None


def local_preflight(prepared: PreparedRuntime) -> dict[str, object]:
    """Open and close only pinned original-root DIRECTORY handles.

    This is an optional read-only LOCAL preflight after owner approved
    explicit host paths. It never reads project file content.
    """
    if type(prepared) is not PreparedRuntime:
        raise RuntimeDenied("native_linux_runtime_denied")
    try:
        with ExitStack() as stack:
            for project, path in prepared.project_roots:
                stack.enter_context(LinuxNativeFiles(root=Path(path),
                                                    project=project))
        return {
            "status": "LOCAL_ROOT_HANDLES_PASS",
            "target": prepared.device.target,
            "roots_checked": len(prepared.project_roots),
            "original_paths": "REDACTED",
            "owner_authenticated": False,
            "os_isolation_verified": False,
            "native_host_pass": False,
            "connected": False,
            "changes_applied": False,
        }
    except (NativeLinuxDenied, OSError, ValueError, TypeError):
        raise RuntimeDenied("native_linux_runtime_denied") from None


def run_once(prepared: PreparedRuntime, *, connector: Connector,
             is_device_revoked: Callable[[], bool],
             is_os_isolation_verified: Callable[[], bool]) -> str:
    """Source-only injectable one-shot runner. NOT exposed as a CLI/service.

    The trusted host installer is responsible for actual OS enforcement,
    authenticated pairing and connection lifecycle. This code explicitly
    refuses missing, failing or ambiguous revocation/isolation providers.
    It does not install the network dependency or mint a device credential.
    """
    if (type(prepared) is not PreparedRuntime
        or not callable(connector) or not callable(is_device_revoked)
        or not callable(is_os_isolation_verified)):
        raise RuntimeDenied("native_linux_runtime_denied")
    try:
        _service_identity(prepared.device.target)
        if (is_os_isolation_verified() is not True
            or is_device_revoked() is not False):
            raise RuntimeDenied("native_linux_runtime_denied")
        with ExitStack() as stack:
            roots: dict[str, LinuxNativeFiles] = {}
            for project, path in prepared.project_roots:
                roots[project] = stack.enter_context(
                    LinuxNativeFiles(root=Path(path), project=project))
            dispatcher = LinuxOriginalReadDispatcher(
                device_id=prepared.device.device_id, local_roots=roots,
                is_device_revoked=is_device_revoked)
            return run_session(prepared.device, dispatcher, connector)
    except Exception:
        # A failing trusted revocation or OS-isolation callback may contain
        # private server names/paths in its exception. Deny without leaking.
        raise RuntimeDenied("native_linux_runtime_denied") from None


def _preview(prepared: PreparedRuntime) -> dict[str, object]:
    return {
        "status": "PRIVATE_CONFIG_CONTRACT_VALID",
        "target": prepared.device.target,
        "device_id": "REDACTED",
        "original_paths": "REDACTED",
        "root_count": len(prepared.project_roots),
        "artifact_sha256": prepared.candidate.artifact_sha256,
        "manifest_sha256": prepared.candidate.manifest_sha256,
        "owner_authenticated": False,
        "os_isolation_verified": False,
        "native_host_pass": False,
        "connected": False,
        "changes_applied": False,
    }


def main(argv: list[str] | None = None) -> int:
    """Only preflight; never a hidden host activation command."""
    parser = argparse.ArgumentParser(
        description="H454 source-only native Linux private-config preflight")
    parser.add_argument("--target", choices=("hermes-vps", "yfc-vps"),
                        required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--inspect-root-handles", action="store_true")
    args = parser.parse_args(argv)
    try:
        prepared = load_local_runtime(
            target=args.target, expected_release=args.release_sha,
            expected_manifest_sha256=args.manifest_sha256,
            manifest_path=args.manifest, config_path=args.config)
        report = _preview(prepared)
        if args.inspect_root_handles:
            report["local_roots"] = local_preflight(prepared)
        else:
            report["local_roots"] = "NOT_RUN"
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        # The CLI never emits tracebacks, source paths or owner bearers.
        print(json.dumps({
            "status": "HOLD", "reason": "NATIVE_LINUX_RUNTIME_DENIED",
            "connected": False, "changes_applied": False,
        }, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
