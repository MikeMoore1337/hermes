"""Hermes #454: real ONE-session Linux native READ worker for systemd.

No new MCP endpoint. Reuses existing owner-paired BRC WSS read-only transport,
original-root openat2 descriptors and authoritative current-bearer revocation.
Only an approved systemd unit under dedicated nonroot identity can enter the
network phase. Failure of any owner/OS/relay proof is fatal and sanitized.
The CLI does not install, start, enable, pair or provision any service.
"""
from __future__ import annotations

import argparse
import ipaddress
import importlib
import os
import stat
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

from device_fabric.native_brc_status import revoked_provider, PUBLIC, StatusDenied
from scripts.h454_native_linux_runtime import (
    load_local_runtime, run_once, RuntimeDenied, _service_identity,
)
from scripts.h454_native_linux_unit_candidate import (
    MANIFEST_PATH, CONFIG_PATH, SERVICE_USER,
)

UNIT = "hermes-commander-native.service"
STATUS = Path("/proc/self/status")
CGROUP = Path("/proc/self/cgroup")
EXPECTED_SHA = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_INVOCATION = re.compile(r"[0-9a-f]{32}\Z")
EXPECTED_HARDENING = {
    "User": SERVICE_USER,
    "Group": SERVICE_USER,
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "PrivateNetwork": "no",
    "RestrictSUIDSGID": "yes",
    "RestrictNamespaces": "yes",
    "MemoryDenyWriteExecute": "yes",
}
PROC_CAPS = ("CapEff", "CapPrm", "CapBnd", "CapAmb")


class NativeLinuxServiceDenied(ValueError):
    """No private path, bearer, network or OS error details."""


def _deny() -> None:
    raise NativeLinuxServiceDenied("native_linux_service_denied")


def _kernel_evidence(status: str, cgroup: str, invocation: str,
                     *, uid: int, gid: int) -> bool:
    """Kernel-side evidence; fake systemctl text alone cannot authorize."""
    try:
        if (type(status) is not str or type(cgroup) is not str
            or type(invocation) is not str
            or EXPECTED_INVOCATION.fullmatch(invocation) is None
            or type(uid) is not int or type(gid) is not int
            or uid <= 0 or gid <= 0):
            return False
        lines = {}
        for line in status.splitlines():
            key, sep, val = line.partition(":")
            if sep:
                if key in lines: return False
                lines[key] = val.strip()
        if (lines.get("NoNewPrivs") != "1" or
            lines.get("Seccomp") != "2" or
            any(lines.get(cap) != "0000000000000000" for cap in PROC_CAPS)):
            return False
        if lines.get("Uid") != "\t".join([str(uid)] * 4) and (
            lines.get("Uid") != " ".join([str(uid)] * 4)):
            return False
        if lines.get("Gid") != "\t".join([str(gid)] * 4) and (
            lines.get("Gid") != " ".join([str(gid)] * 4)):
            return False
        records = [item.split("::", 1) for item in cgroup.splitlines()]
        if len(records) != 1 or len(records[0]) != 2 or records[0][0] != "0":
            return False
        path = records[0][1]
        return path.startswith("/") and path.endswith("/" + UNIT) and (
            ".." not in path and "\x00" not in path)
    except Exception:
        return False


def _properties_are_hardened(text: str) -> bool:
    try:
        if type(text) is not str or not 0 < len(text) <= 16384:
            return False
        values = {}
        for item in text.splitlines():
            key, sep, value = item.partition("=")
            if not sep or key in values:
                return False
            values[key] = value
        if any(values.get(k) != v for k, v in EXPECTED_HARDENING.items()):
            return False
        if values.get("IPAddressDeny") != "any":
            return False
        ip_words = values.get("IPAddressAllow", "").split()
        if len(ip_words) not in (2, 3) or len(set(ip_words)) != len(ip_words):
            return False
        stub = ipaddress.IPv4Address("127.0.0.53")
        for word in ip_words:
            network = ipaddress.ip_network(word, strict=True)
            if network.version != 4 or network.prefixlen != 32:
                return False
            if network.network_address == stub:
                # This single exact loopback destination is the host DNS
                # stub; no generic localhost or private egress is allowed.
                continue
            if (network.network_address.is_loopback
                or network.network_address.is_private
                or network.network_address.is_link_local
                or network.network_address.is_multicast
                or network.network_address.is_reserved
                or network.network_address.is_unspecified):
                return False
        if values.get("CapabilityBoundingSet") not in ("", "~"):
            return False
        return True
    except Exception:
        return False



def _pinned_websocket_dependency(release_sha: str) -> bool:
    """Deny the global/pip/user-installed websockets module at live startup.

    A PATH or PYTHONPATH override must not select an unpinned implementation.
    Owner root must have staged the exact hashed pure-Python wheel under the
    fixed release-scoped immutable directory before activating systemd.
    """
    try:
        if type(release_sha) is not str or EXPECTED_SHA.fullmatch(release_sha) is None:
            return False
        expected = Path("/opt/hermes-commander-native/deps") / ("main-" + release_sha)
        info = expected.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
            return False
        package = importlib.import_module("websockets")
        client = importlib.import_module("websockets.sync.client")
        if getattr(package, "__version__", None) != "17.2":
            return False
        for loaded, name in (
            (package, "websockets/__init__.py"),
            (client, "websockets/sync/client.py"),
        ):
            file = Path(loaded.__file__)
            if (file.is_symlink() or not file.is_file()
                or file.resolve(strict=True) != expected / name):
                return False
            st = file.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                return False
        return True
    except Exception:
        return False


def real_os_isolation_verified() -> bool:
    """Every call rechecks actual process capabilities and manager policy."""
    try:
        if sys.platform != "linux" or os.name != "posix":
            return False
        _service_identity("hermes-vps")
        if EXPECTED_INVOCATION.fullmatch(os.environ.get("INVOCATION_ID", "")) is None:
            return False
        status = STATUS.read_text(encoding="ascii")
        cgroup = CGROUP.read_text(encoding="ascii")
        if not _kernel_evidence(
            status, cgroup, os.environ["INVOCATION_ID"],
            uid=os.geteuid(), gid=os.getegid(),
        ):
            return False
        keys = [*EXPECTED_HARDENING, "IPAddressDeny",
                "IPAddressAllow", "CapabilityBoundingSet"]
        command = ["/usr/bin/systemctl", "show", UNIT, "--no-pager",
                   "--property=" + ",".join(keys)]
        proc = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=5, check=False, env={
                "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            },
        )
        if proc.returncode != 0 or len(proc.stdout) > 16384:
            return False
        return _properties_are_hardened(proc.stdout.decode("ascii"))
    except Exception:
        return False


def run_trusted_once(*, target: str, release_sha: str,
                     manifest_sha256: str,
                     connector: Callable | None = None,
                     os_gate: Callable[[], bool] | None = None,
                     status_factory: Callable = revoked_provider) -> str:
    """Actual BRC session, no command from MCP or trusted bool in argv.

    Dependency injection exists only for disposable offline unit tests.
    Production CLI always uses real_os_isolation_verified/revoked_provider.
    """
    if os_gate is None:
        os_gate = real_os_isolation_verified
    if (target not in {"hermes-vps", "yfc-vps"}
        or type(release_sha) is not str
        or EXPECTED_SHA.fullmatch(release_sha) is None
        or type(manifest_sha256) is not str
        or EXPECTED_DIGEST.fullmatch(manifest_sha256) is None
        or not callable(os_gate) or not callable(status_factory)
        or (connector is not None and not callable(connector))):
        _deny()
    try:
        _service_identity(target)
        if os_gate() is not True:
            _deny()
        prepared = load_local_runtime(
            target=target, expected_release=release_sha,
            expected_manifest_sha256=manifest_sha256,
            manifest_path=Path(MANIFEST_PATH),
            config_path=Path(CONFIG_PATH),
        )
        if os_gate() is not True:
            _deny()
        revoked = status_factory(
            target=target, device_id=prepared.device.device_id,
            bearer=prepared.device.token, base_url=PUBLIC,
        )
        if not callable(revoked) or revoked() is not False:
            _deny()
        if connector is None:
            # Never inherit an arbitrary system pip package. This fixed
            # release's dependency must be the exact offline-hash-staged
            # universal wheel, root-owned and unmodifiable by the service.
            if not _pinned_websocket_dependency(release_sha):
                _deny()
            from websockets.sync.client import connect
            connector = connect
        if os_gate() is not True:
            _deny()
        return run_once(
            prepared, connector=connector, is_device_revoked=revoked,
            is_os_isolation_verified=os_gate,
        )
    except Exception:
        raise NativeLinuxServiceDenied("native_linux_service_denied") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 owner-paired READ-only systemd service")
    parser.add_argument("--run-once", action="store_true")
    parser.add_argument("--target", choices=("hermes-vps", "yfc-vps"), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    if not args.run_once:
        return 2
    try:
        # Never accept root paths, bearer values, device IDs, URL or bypass
        # switches from command line. All live state is service-private.
        run_trusted_once(
            target=args.target, release_sha=args.release_sha,
            manifest_sha256=args.manifest_sha256,
        )
        return 0
    except NativeLinuxServiceDenied:
        print("H454_NATIVE_LINUX_SERVICE=DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
