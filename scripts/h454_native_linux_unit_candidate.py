"""H454: render an inert Linux systemd ONESHOT PREFLIGHT unit, never install it.

This is only an immutable source candidate for a future owner-reviewed,
restricted SSH installation operator. It DOES NOT create a service account,
write a unit, run systemctl, register a native device or start an agent.
It cannot certify effective systemd/OS permissions on an owner VPS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Final

from device_fabric.native_install_preview import (
    InstallPlanDenied, parse_candidate,
)
from scripts.h454_native_install_preflight import _private_manifest

SHA64: Final = re.compile(r"[0-9a-f]{64}\Z")
SERVICE_NAME: Final = "hermes-commander-native-preflight.service"
SERVICE_USER: Final = "hermes-commander-native"
STATE_DIR: Final = "/var/lib/hermes-commander-native"
MANIFEST_PATH: Final = STATE_DIR + "/manifest.json"
CONFIG_PATH: Final = STATE_DIR + "/device.json"


class NativeUnitDenied(ValueError):
    """Deny without echoing candidate manifest, original paths or secrets."""


def render_preflight_unit(manifest: bytes, *, target: str,
                          release_sha: str,
                          manifest_sha256: str) -> str:
    """Return SOURCE ONLY. No unit install, launch, credentials or networking.

    Inputs must be selected by an independently trusted operator; this
    parser is not an owner-authenticated installation approval.
    """
    try:
        if (type(manifest_sha256) is not str
            or SHA64.fullmatch(manifest_sha256) is None
            or hashlib.sha256(manifest).hexdigest() != manifest_sha256):
            raise NativeUnitDenied("native_unit_denied")
        candidate = parse_candidate(
            manifest, expected_release=release_sha, expected_target=target)
        if (candidate.target not in {"hermes-vps", "yfc-vps"}
            or candidate.manifest_sha256 != manifest_sha256
            or candidate.service_identity != SERVICE_USER
            or candidate.service_name != "hermes-commander-native.service"):
            raise NativeUnitDenied("native_unit_denied")
        # All interpolated values are strictly pinned hex hashes / fixed
        # known target enums; original project roots never enter this unit.
        source_dir = ("/opt/hermes-commander-native/releases/main-"
                      + candidate.release_sha)
        command = (
            "/usr/bin/python3 -B -m scripts.h454_native_linux_runtime"
            + " --target " + candidate.target
            + " --release-sha " + candidate.release_sha
            + " --manifest-sha256 " + candidate.manifest_sha256
            + " --manifest " + MANIFEST_PATH
            + " --config " + CONFIG_PATH
            + " --inspect-root-handles"
        )
        return "\n".join([
            "# H454 SOURCE ONLY - never install/start without per-host approval.",
            "# This is a disabled ONESHOT PRE-FLIGHT, NOT the native agent.",
            "# No [Install] section, no network, no service auto-start.",
            "[Unit]",
            "Description=Hermes Commander original-Linux native READ preflight (INERT)",
            "After=local-fs.target",
            "AssertPathExists=" + MANIFEST_PATH,
            "AssertPathExists=" + CONFIG_PATH,
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=no",
            "Restart=no",
            "User=" + SERVICE_USER,
            "Group=" + SERVICE_USER,
            "WorkingDirectory=" + source_dir,
            "ExecStart=" + command,
            "UMask=0077",
            "Environment=PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ProtectControlGroups=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "RestrictAddressFamilies=AF_UNIX",
            # The READ-only --inspect-root-handles path calls openat2(2).
            # On the original Hermes VPS, RestrictSUIDSGID=yes installs a
            # seccomp filter returning ENOSYS for openat2, even for O_PATH.
            # Fixed unprivileged identity, NoNewPrivileges, empty capabilities
            # and all other offline isolation remain mandatory.
            "RestrictSUIDSGID=no",
            "RestrictRealtime=yes",
            "RestrictNamespaces=yes",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "SystemCallArchitectures=native",
            "SystemCallFilter=~@mount @reboot @swap",
            "IPAddressDeny=any",
            "KillMode=control-group",
            "TimeoutStartSec=30s",
            "CPUQuota=25%",
            "MemoryMax=256M",
            "TasksMax=24",
            "ReadOnlyPaths=" + STATE_DIR,
            "StandardOutput=journal",
            "StandardError=journal",
            "",
        ])
    except (NativeUnitDenied, InstallPlanDenied, ValueError, TypeError,
            UnicodeError, AttributeError):
        raise NativeUnitDenied("native_unit_denied") from None


def main(argv: list[str] | None = None) -> int:
    """Print inert text only; deliberately no --install/--start/--apply."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", choices=("hermes-vps", "yfc-vps"),
                        required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        data = _private_manifest(args.manifest)
        unit = render_preflight_unit(
            data, target=args.target, release_sha=args.release_sha,
            manifest_sha256=args.manifest_sha256)
        print(unit, end="")
        return 0
    except Exception:
        print("H454_NATIVE_PREFLIGHT_UNIT=HOLD")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
