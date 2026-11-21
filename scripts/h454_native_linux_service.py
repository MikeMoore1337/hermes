"""Hermes #454: real ONE-session Linux native READ worker for systemd.

No new MCP endpoint. Reuses existing owner-paired BRC WSS read-only transport,
original-root openat2 descriptors and authoritative current-bearer revocation.
Only an approved systemd unit under dedicated nonroot identity can enter the
network phase. Failure of any owner/OS/relay proof is fatal and sanitized.
The CLI does not install, start, enable, pair or provision any service.
"""
from __future__ import annotations

import argparse
import errno
import ipaddress
import importlib
import os
import stat
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
from typing import Callable

from device_fabric.linux_native_async_transport import sync_adapter
from device_fabric.native_brc_status import revoked_provider, PUBLIC, StatusDenied
from device_fabric.native_private_tls import (
    _private_ip, UNIX_ENDPOINT, UNIX_DIRECTORY, AUDIT_DIRECTORY, AUDIT_SOCKET, load_private_relay, private_revoked_provider,
    private_websocket_connector,
)
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
    # RestrictSUIDSGID=yes blocks openat2 at the seccomp layer (ENOSYS).
    # Keep NoNewPrivileges=yes, no capabilities, fixed nonroot UID/GID,
    # and read-only filesystem; native original-file handlers require
    # openat2 to enforce no-follow kernel path confinement.
    "RestrictSUIDSGID": "no",
    "RestrictNamespaces": "yes",
    "MemoryDenyWriteExecute": "yes",
}
PROC_CAPS = ("CapEff", "CapPrm", "CapBnd", "CapAmb")
SHOW_KEYS = (*EXPECTED_HARDENING, "LimitNOFILE", "StandardInput", "StandardOutput", "StandardError",
             "RestrictAddressFamilies", "TemporaryFileSystem",
             "BindPaths", "BindReadOnlyPaths", "IPAddressDeny", "IPAddressAllow",
             "CapabilityBoundingSet", "InaccessiblePaths")


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


def _properties_are_hardened(text: str, *, private_relay_ip: str | None = None,
                             git_roots: tuple[str, ...] = (), target: str | None = None) -> bool:
    try:
        if type(text) is not str or not 0 < len(text) <= 16384:
            return False
        values = {}
        for item in text.splitlines():
            key, sep, value = item.partition("=")
            if not sep or key in values:
                return False
            values[key] = value
        unix_relay = target == 'yfc-vps' and private_relay_ip == UNIX_ENDPOINT
        expected = dict(EXPECTED_HARDENING)
        if target in ('hermes-vps', 'yfc-vps'):
            expected['LimitNOFILE'] = '32768'
            expected['StandardInput'] = 'null'
            expected['StandardOutput'] = 'journal'
            expected['StandardError'] = 'journal'
            expected['TemporaryFileSystem'] = '/run:ro'
            expected['BindPaths'] = ''
        if unix_relay:
            expected['PrivateNetwork'] = 'yes'
            expected['RestrictAddressFamilies'] = 'AF_UNIX'
            expected['TemporaryFileSystem'] = '/run:ro'
            expected['BindPaths'] = ''
        if any(values.get(k) != v for k, v in expected.items()):
            return False
        if target in ('hermes-vps', 'yfc-vps') and not unix_relay:
            families = values.get('RestrictAddressFamilies', '').split()
            if len(families) != 3 or set(families) != {'AF_UNIX', 'AF_INET', 'AF_INET6'}:
                return False
        if (type(git_roots) is not tuple or len(git_roots) > 5
            or any(type(root) is not str or not root.startswith("/")
                   or ".." in root.split("/") for root in git_roots)):
            return False
        masks = values.get("InaccessiblePaths", "").split()
        if any("-" + root + "/.git" not in masks for root in git_roots):
            return False
        deny = values.get("IPAddressDeny", "").split()
        if deny != ["any"] and not (
            len(deny) == 2 and set(deny) == {"0.0.0.0/0", "::/0"}
        ):
            return False
        ip_words = values.get("IPAddressAllow", "").split()
        if target in ('hermes-vps', 'yfc-vps') and not unix_relay:
            if values.get('BindReadOnlyPaths', '').split() != [
                    AUDIT_DIRECTORY + ':' + AUDIT_DIRECTORY + ':rbind']:
                return False
        if unix_relay:
            binds = values.get('BindReadOnlyPaths', '').split()
            allowed = (UNIX_DIRECTORY, AUDIT_DIRECTORY)
            return (not ip_words and values.get("CapabilityBoundingSet") in ("", "~") and
                    len(binds) == len(allowed) and
                    set(binds) == {path + ':' + path + ':rbind' for path in allowed})
        if private_relay_ip is not None:
            return (_private_ip(private_relay_ip) and
                    ip_words == [private_relay_ip + "/32"] and
                    values.get("CapabilityBoundingSet") in ("", "~"))
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



def _pinned_websocket_dependency(release_sha: str, target: str = 'hermes-vps') -> bool:
    """Deny the global/pip/user-installed websockets module at live startup.

    A PATH or PYTHONPATH override must not select an unpinned implementation.
    Owner root must have staged the exact hashed pure-Python wheel under the
    fixed release-scoped immutable directory before activating systemd.
    """
    try:
        if (type(release_sha) is not str or EXPECTED_SHA.fullmatch(release_sha) is None
            or target not in ('hermes-vps', 'yfc-vps')):
            return False
        expected = Path("/opt/hermes-commander-native/deps") / ("main-" + release_sha)
        info = expected.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
            return False
        package = importlib.import_module("websockets")
        client_name = 'asyncio'
        client = importlib.import_module('websockets.' + client_name + '.client')
        if getattr(package, "__version__", None) != "17.2":
            return False
        for loaded, name in (
            (package, "websockets/__init__.py"),
            (client, 'websockets/' + client_name + '/client.py'),
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


def _inet_socket_creation_denied() -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            try:
                sock = socket.socket(family, kind)
            except OSError as exc:
                if exc.errno not in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES):
                    return False
            else:
                sock.close()
                return False
    return True


def _private_run_mount(text: str) -> bool:
    try:
        mounts = []
        for line in text.splitlines():
            left, right = line.split(' - ', 1)
            fields, filesystem = left.split(), right.split()
            if fields[4] == '/run':
                mounts.append(filesystem[0] == 'tmpfs' and 'ro' in fields[5].split(','))
        return mounts == [True]
    except (ValueError, IndexError):
        return False


def _audit_properties() -> str:
    folder = Path(AUDIT_DIRECTORY).lstat()
    endpoint = Path(AUDIT_SOCKET).lstat()
    if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != 0 or
        stat.S_IMODE(folder.st_mode) != 0o755 or
        not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or
        endpoint.st_gid != os.getegid() or stat.S_IMODE(endpoint.st_mode) != 0o660):
        raise NativeLinuxServiceDenied('native_linux_service_denied')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(AUDIT_SOCKET)
        pid, uid, gid = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if (pid, uid, gid) != (1, 0, 0):
            raise NativeLinuxServiceDenied('native_linux_service_denied')
        data = bytearray()
        while len(data) <= 16384:
            part = client.recv(16385 - len(data))
            if not part:
                break
            data.extend(part)
        if not data or len(data) > 16384:
            raise NativeLinuxServiceDenied('native_linux_service_denied')
        return data.decode('ascii')


def real_os_isolation_verified(*, private_relay_ip: str | None = None,
                               git_roots: tuple[str, ...] = (), target: str | None = None,
                               expected_identity: tuple[int, int] | None = None) -> bool:
    """Every call rechecks actual process capabilities and manager policy."""
    try:
        if sys.platform != "linux" or os.name != "posix":
            return False
        if target in ('hermes-vps', 'yfc-vps'):
            if (type(expected_identity) is not tuple or len(expected_identity) != 2 or
                any(type(value) is not int or value <= 0 for value in expected_identity) or
                expected_identity != (os.geteuid(), os.getegid())):
                return False
        else:
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
        if target == 'yfc-vps' and private_relay_ip == UNIX_ENDPOINT:
            if not _inet_socket_creation_denied():
                return False
        if target in ('hermes-vps', 'yfc-vps'):
            if not _private_run_mount(Path('/proc/self/mountinfo').read_text(encoding='ascii')):
                return False
        if target in ('hermes-vps', 'yfc-vps'):
            properties = _audit_properties()
        else:
            command = ["/usr/bin/systemctl", "show", UNIT, "--no-pager",
                       "--property=" + ",".join(SHOW_KEYS)]
            proc = subprocess.run(
                command, stdin=subprocess.DEVNULL, capture_output=True,
                timeout=5, check=False, env={
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                },
            )
            if proc.returncode != 0 or len(proc.stdout) > 16384:
                return False
            properties = proc.stdout.decode('ascii')
        if not _properties_are_hardened(properties,
                                        private_relay_ip=private_relay_ip,
                                        git_roots=git_roots, target=target):
            return False
        for root in git_roots:
            git = Path(root) / ".git"
            try:
                git.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                return False
            if os.access(git, os.R_OK) or os.access(git, os.X_OK):
                return False
        return True
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
    if (target not in {"hermes-vps", "yfc-vps"}
        or type(release_sha) is not str
        or EXPECTED_SHA.fullmatch(release_sha) is None
        or type(manifest_sha256) is not str
        or EXPECTED_DIGEST.fullmatch(manifest_sha256) is None
        or (os_gate is not None and not callable(os_gate)) or not callable(status_factory)
        or (connector is not None and not callable(connector))):
        _deny()
    try:
        private = None
        landlock_read = connector is None
        git_roots: tuple[str, ...] = ()
        enforce_git_mask = connector is None and os_gate is None
        _service_identity(target)
        if connector is None:
            # CLI production path is always private, even if the public
            # BRC endpoint appears to work. Never allow an implicit fallback.
            private = load_private_relay(target, release_sha)
            if os_gate is None:
                identity = {'expected_identity': (os.geteuid(), os.getegid())}
                os_gate = lambda: real_os_isolation_verified(
                    private_relay_ip=private.relay_ipv4, git_roots=git_roots, target=target, **identity)
            if status_factory is not revoked_provider:
                _deny()
            status_factory = lambda **kwargs: private_revoked_provider(
                private, **kwargs)
        elif os_gate is None:
            os_gate = real_os_isolation_verified
        if os_gate() is not True:
            _deny()
        prepared = load_local_runtime(
            target=target, expected_release=release_sha,
            expected_manifest_sha256=manifest_sha256,
            manifest_path=Path(MANIFEST_PATH),
            config_path=Path(CONFIG_PATH),
        )
        if enforce_git_mask:
            git_roots = tuple(root for _, root in prepared.project_roots)
            if not git_roots:
                _deny()
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
            if not _pinned_websocket_dependency(release_sha, target):
                _deny()
            from websockets.asyncio.client import connect
            connector = private_websocket_connector(private, sync_adapter(connect))
        if os_gate() is not True:
            _deny()
        return run_once(
            prepared, connector=connector,
            is_device_revoked=lambda: os_gate() is not True or revoked() is not False,
            is_os_isolation_verified=os_gate,
            **({'landlock_read': True} if landlock_read else {}),
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
