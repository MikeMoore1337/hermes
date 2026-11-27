"""Run one personal Linux session from root-owned configuration and state.

This entry point does not install, enable, pair or provision a service.
The systemd unit must separately grant only the selected project and the
existing private relay channel to an unprivileged service identity.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from device_fabric import linux_personal_config, linux_personal_runtime
from device_fabric.native_brc_enrollment import TOKEN
from device_fabric.windows_personal_commander_bundle import MAX_ENTRIES, MAX_MANIFEST

CONFIG_ROOT = Path('/etc/hermes-commander-personal')
STATE_ROOT = Path('/var/lib/hermes-commander-personal')
UNITS = {'hermes-vps': 'hermes-commander-personal-hermes.service',
         'yfc-vps': 'hermes-commander-personal-yfc.service'}


class ServiceDenied(ValueError):
    """Do not report paths, credentials or OS errors."""


def kernel_authorized(status: str, cgroup: str, target: str, uid: int) -> bool:
    """Require the dedicated unit, a non-root UID and no Linux capabilities."""
    try:
        if target not in UNITS or type(uid) is not int or uid <= 0:
            return False
        fields = {}
        for line in status.splitlines():
            key, sep, value = line.partition(':')
            if sep:
                if key in fields:
                    return False
                fields[key] = value.strip()
        if (fields.get('NoNewPrivs') != '1' or
            fields.get('Uid', '').split() != [str(uid)] * 4 or
            any(fields.get(name) != '0000000000000000' for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))):
            return False
        lines = cgroup.splitlines()
        return len(lines) == 1 and lines[0].startswith('0::/') and lines[0].endswith('/' + UNITS[target])
    except Exception:
        return False


def _read(path: Path, *, owner: int, modes: tuple[int, ...], maximum: int) -> bytes:
    """Read a regular pinned-owner file once without following its final link."""
    fd = -1
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) not in modes or not 0 < before.st_size <= maximum):
            raise ValueError()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(fd)
        blocks = []
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1024 * 1024))
            if not block:
                raise ValueError()
            blocks.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, name) != getattr(opened, name) or
               getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError()
        return b''.join(blocks)
    except Exception:
        raise ServiceDenied('personal_linux_service_denied') from None
    finally:
        if fd >= 0:
            os.close(fd)


def _root_chain(directory: Path) -> None:
    for path in (directory, *directory.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ServiceDenied('personal_linux_service_denied')


def _root_bundle(directory: Path) -> None:
    """The service account must not be able to swap verified runtime files."""
    _root_chain(directory)
    pending = [directory]
    count = 0
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                count += 1
                if count > MAX_ENTRIES:
                    raise ServiceDenied('personal_linux_service_denied')
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != 0:
                    raise ServiceDenied('personal_linux_service_denied')
                if stat.S_ISLNK(info.st_mode):
                    continue  # The pinned manifest separately checks link targets.
                if info.st_mode & 0o022:
                    raise ServiceDenied('personal_linux_service_denied')
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ServiceDenied('personal_linux_service_denied')


def run(target: str) -> str:
    try:
        if target not in UNITS or os.geteuid() <= 0 or os.getuid() != os.geteuid():
            raise ValueError()
        if not kernel_authorized(Path('/proc/self/status').read_text(), Path('/proc/self/cgroup').read_text(),
                                 target, os.geteuid()):
            raise ValueError()
        _root_chain(CONFIG_ROOT)
        raw = _read(CONFIG_ROOT / (target + '.json'), owner=0, modes=(0o444, 0o644), maximum=8192)
        config = linux_personal_config.parse(raw, target=target)
        _root_bundle(Path(config.bundle))
        manifest = _read(CONFIG_ROOT / (target + '.manifest.json'), owner=0,
                         modes=(0o444, 0o644), maximum=MAX_MANIFEST)
        state = STATE_ROOT / target
        _root_chain(STATE_ROOT)
        info = state.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError()
        bearer = _read(state / 'bearer', owner=os.geteuid(), modes=(0o600,), maximum=512).decode('ascii')
        if TOKEN.fullmatch(bearer) is None:
            raise ValueError()
        from websockets.asyncio.client import connect
        from device_fabric.linux_native_async_transport import sync_adapter
        return linux_personal_runtime.run_once(target=target, device_id=config.device_id, bearer=bearer,
            project=config.project, bundle=config.bundle, expected_manifest=manifest,
            bundle_sha256=config.bundle_sha256, trust_release_sha=config.trust_release_sha,
            journal=state / 'claims', websocket_connect=sync_adapter(connect))
    except Exception:
        raise ServiceDenied('personal_linux_service_denied') from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', choices=tuple(UNITS), required=True)
    args = parser.parse_args()
    try:
        result = run(args.target)
        if result not in ('idle_timeout', 'call_budget_exhausted'):
            raise ValueError()
        print('H454_PERSONAL_SESSION=' + result.upper())
        return 0
    except Exception:
        print('H454_PERSONAL_SESSION=DENIED', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
