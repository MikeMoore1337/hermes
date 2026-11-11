"""H454: render the actual original-Linux native READ systemd service unit.

Source-only until the owner approves exact root paths, public egress IP,
service account, TLS trust, pairing, boot enable and rollback. This module
never writes a host unit, grants filesystem access or launches a process.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re

from device_fabric.native_install_preview import parse_candidate, InstallPlanDenied
from scripts.h454_native_linux_unit_candidate import (
    SERVICE_USER, MANIFEST_PATH, CONFIG_PATH,
)

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
SAFE_UNIT_PATH = re.compile(r"/[A-Za-z0-9_./-]{2,1024}\Z")
UNIT_NAME = "hermes-commander-native.service"
MAX_EGRESS_IPS = 3


class LinuxActiveUnitDenied(ValueError):
    """Never report source paths or private owner information."""


def render_active_unit(
    manifest: bytes, *,
    target: str, release_sha: str, manifest_sha256: str,
    relay_ipv4: str, dns_ipv4: str,
) -> str:
    """Render an OS-constrained service, but never install/enable it."""
    try:
        if (type(manifest) is not bytes
            or type(manifest_sha256) is not str
            or SHA64.fullmatch(manifest_sha256) is None
            or hashlib.sha256(manifest).hexdigest() != manifest_sha256
            or type(release_sha) is not str
            or SHA40.fullmatch(release_sha) is None
            or type(relay_ipv4) is not str
            or type(dns_ipv4) is not str):
            raise LinuxActiveUnitDenied("native_linux_active_unit_denied")
        candidate = parse_candidate(
            manifest, expected_release=release_sha, expected_target=target)
        if (target not in {"hermes-vps", "yfc-vps"}
            or candidate.service_name != UNIT_NAME
            or candidate.service_identity != SERVICE_USER
            or candidate.manifest_sha256 != manifest_sha256
            or not 1 <= len(candidate.roots) <= 5
            or any(SAFE_UNIT_PATH.fullmatch(root) is None for _, root in candidate.roots)):
            raise LinuxActiveUnitDenied("native_linux_active_unit_denied")
        relay = ipaddress.IPv4Address(relay_ipv4)
        dns = ipaddress.IPv4Address(dns_ipv4)
        # No attacker-controlled loopback/local/cloud metadata endpoint in
        # installer-supplied EGRESS addresses. Real owner must independently
        # verify target public TLS A-record and DNS resolver identity.
        if any(ip.is_loopback or ip.is_link_local or ip.is_multicast
               or ip.is_reserved or ip.is_unspecified or ip.is_private
               for ip in (relay, dns)) or relay == dns:
            raise LinuxActiveUnitDenied("native_linux_active_unit_denied")
        source = "/opt/hermes-commander-native/releases/main-" + release_sha
        deps = "/opt/hermes-commander-native/deps/main-" + release_sha
        exec_start = (
            "/usr/bin/python3 -B -m scripts.h454_native_linux_service"
            + " --run-once"
            + " --target " + target
            + " --release-sha " + release_sha
            + " --manifest-sha256 " + manifest_sha256
        )
        lines = [
            "# H454 SOURCE ONLY. Install/enable only with owner-reviewed VPS approval.",
            "# A running native service always requires matching OS + current BRC bearer.",
            "[Unit]",
            "Description=Hermes Commander original-host native READ (owner paired)",
            "Wants=network-online.target",
            "After=network-online.target local-fs.target",
            "AssertPathExists=" + MANIFEST_PATH,
            "AssertPathExists=" + CONFIG_PATH,
            "AssertPathExists=" + deps + "/websockets/sync/client.py",
            "StartLimitIntervalSec=300",
            "StartLimitBurst=3",
            "",
            "[Service]",
            "Type=exec",
            "User=" + SERVICE_USER,
            "Group=" + SERVICE_USER,
            "WorkingDirectory=" + source,
            "ExecStart=" + exec_start,
            "Environment=PYTHONPATH=" + deps
            + " PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1",
            "UMask=0077",
            "Restart=on-success",
            "RestartSec=90s",
            "RuntimeMaxSec=300s",
            "TimeoutStopSec=10s",
            "KillMode=control-group",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=no",
            "ProtectProc=invisible",
            "ProcSubset=all",
            "ProtectControlGroups=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectHostname=yes",
            "ProtectClock=yes",
            "RestrictSUIDSGID=yes",
            "RestrictNamespaces=yes",
            "RestrictRealtime=yes",
            "MemoryDenyWriteExecute=yes",
            "LockPersonality=yes",
            "SystemCallArchitectures=native",
            "SystemCallFilter=~@mount @reboot @swap",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "IPAddressDeny=any",
            "IPAddressAllow=" + str(relay) + "/32",
            "IPAddressAllow=" + str(dns) + "/32",
            "IPAccounting=yes",
            "MemoryMax=256M",
            "CPUQuota=25%",
            "TasksMax=24",
            "ReadOnlyPaths=" + source,
            "ReadOnlyPaths=" + deps,
            "ReadOnlyPaths=/var/lib/hermes-commander-native",
        ]
        lines.extend("ReadOnlyPaths=" + root for _, root in candidate.roots)
        lines.extend([
            "StandardOutput=journal",
            "StandardError=journal",
            "",
            "# A separate owner permission is required before enable/start.",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ])
        return "\n".join(lines)
    except Exception:
        raise LinuxActiveUnitDenied("native_linux_active_unit_denied") from None
