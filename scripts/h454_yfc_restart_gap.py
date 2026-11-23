"""Pinned YFC restart-delay change; no credentials or service restart."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

try:
    import fcntl
except ImportError:
    fcntl = None

UNIT = Path('/etc/systemd/system/hermes-commander-native.service')
RECEIPT = Path('/opt/hermes-commander-native/receipts/h454-yfc-restart-gap-2s')
LOCK = Path('/run/lock/h454-native-private-version-upgrade.lock')
HOST_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
HOST_HASH = 'bd6d9675cc868f14e97c8ef24f58c560cf41930f6bc2dcb7eedc93e6262ff595'
OLD = 'bcba4c34ed1210589634713790c9b2f4beb46c725a4dfc1c97b0fced4bf43b18'
NEW = '0c36b90b65443ef005671c18fd882a1ed376d8997c560ac668730e1b00bdffab'
OLD_LINE = b'Restart=always\nRestartSec=10s\n'
NEW_LINE = b'Restart=always\nRestartSec=2s\n'


class Hold(ValueError):
    pass


def demand(ok: bool) -> None:
    if not ok:
        raise Hold('yfc_restart_gap_denied')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def candidate(raw: bytes) -> bytes:
    demand(type(raw) is bytes and digest(raw) == OLD and raw.count(OLD_LINE) == 1
           and raw.count(b'StartLimitIntervalSec=60\n') == 1
           and raw.count(b'StartLimitBurst=3\n') == 1)
    result = raw.replace(OLD_LINE, NEW_LINE)
    demand(digest(result) == NEW)
    return result


def checked(path: Path, *, mode: int, limit: int = 16384) -> bytes:
    before = path.lstat()
    demand(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
           and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        demand(all(getattr(before, f) == getattr(current, f) == getattr(after, f) for f in fields)
               and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def root_directory(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        demand(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def create(path: Path, raw: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(raw); out.flush(); os.fsync(fd)
    finally: os.close(fd)


def run(*args: str) -> bytes:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=30, check=False,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    demand(result.returncode == 0 and len(result.stdout) < 16384)
    return result.stdout


def service_state(expected_delay: str) -> None:
    props = ('ActiveState', 'LoadState', 'UnitFileState', 'FragmentPath', 'DropInPaths',
             'NeedDaemonReload', 'Restart', 'RestartUSec', 'StartLimitIntervalUSec', 'StartLimitBurst')
    raw = run('/usr/bin/systemctl', 'show', UNIT.name, '--no-pager',
              '--property=' + ','.join(props)).decode('ascii').splitlines()
    demand(len(raw) == len(props) and all('=' in line for line in raw))
    values = dict(line.split('=', 1) for line in raw)
    demand(len(values) == len(props) and values == {
        'ActiveState': 'active', 'LoadState': 'loaded', 'UnitFileState': 'enabled',
        'FragmentPath': str(UNIT), 'DropInPaths': '', 'NeedDaemonReload': 'no',
        'Restart': 'always', 'RestartUSec': expected_delay,
        'StartLimitIntervalUSec': '1min', 'StartLimitBurst': '3'})


def preflight() -> None:
    demand(os.geteuid() == 0 and sys.platform == 'linux' and fcntl is not None)
    for directory in (UNIT.parent, RECEIPT.parent, HOST_KEY.parent): root_directory(directory)
    demand(digest(checked(HOST_KEY, mode=0o644, limit=1024)) == HOST_HASH)


def swap(raw: bytes) -> None:
    side = UNIT.with_name('.h454-yfc-restart-gap.service')
    demand(not side.exists() and not side.is_symlink())
    create(side, raw, 0o644)
    os.replace(side, UNIT)
    sync_dir(UNIT.parent)


def install() -> None:
    preflight(); service_state('10s')
    old = checked(UNIT, mode=0o644)
    new = candidate(old)
    demand(not RECEIPT.exists() and not RECEIPT.is_symlink())
    os.mkdir(RECEIPT, 0o700); os.chmod(RECEIPT, 0o700)
    create(RECEIPT / 'original.unit', old, 0o600)
    staged = RECEIPT / UNIT.name
    create(staged, new, 0o600)
    create(RECEIPT / 'receipt.json', json.dumps({'old': OLD, 'new': NEW}, sort_keys=True).encode('ascii'), 0o600)
    sync_dir(RECEIPT); sync_dir(RECEIPT.parent)
    run('/usr/bin/systemd-analyze', 'verify', str(staged))
    try:
        demand(digest(checked(UNIT, mode=0o644)) == OLD)
        swap(new)
        run('/usr/bin/systemctl', 'daemon-reload')
        demand(digest(checked(UNIT, mode=0o644)) == NEW)
        service_state('2s')
    except Exception:
        current = digest(checked(UNIT, mode=0o644))
        demand(current in (OLD, NEW))
        if current == NEW:
            swap(old)
            run('/usr/bin/systemctl', 'daemon-reload')
            service_state('10s')
        raise


def rollback() -> None:
    preflight(); service_state('2s'); root_directory(RECEIPT)
    old = checked(RECEIPT / 'original.unit', mode=0o600)
    receipt = json.loads(checked(RECEIPT / 'receipt.json', mode=0o600))
    demand(digest(old) == OLD and receipt == {'old': OLD, 'new': NEW}
           and digest(checked(UNIT, mode=0o644)) == NEW)
    new = checked(RECEIPT / UNIT.name, mode=0o600)
    demand(digest(new) == NEW)
    try:
        swap(old)
        run('/usr/bin/systemctl', 'daemon-reload')
        demand(digest(checked(UNIT, mode=0o644)) == OLD)
        service_state('10s')
    except Exception:
        current = digest(checked(UNIT, mode=0o644))
        demand(current in (OLD, NEW))
        if current == OLD:
            swap(new)
            run('/usr/bin/systemctl', 'daemon-reload')
            service_state('2s')
        raise


def main() -> int:
    try:
        demand(len(sys.argv) == 2 and sys.argv[1] in ('check', 'install', 'rollback'))
        preflight()
        fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            demand(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                   and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = LOCK.lstat()
            demand((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino))
            if sys.argv[1] == 'check':
                service_state('10s'); candidate(checked(UNIT, mode=0o644))
                demand(not RECEIPT.exists() and not RECEIPT.is_symlink())
            elif sys.argv[1] == 'install': install()
            else: rollback()
        finally: os.close(fd)
        print('H454_YFC_RESTART_GAP_' + sys.argv[1].upper() + '=PASS')
        return 0
    except Exception:
        print('H454_YFC_RESTART_GAP=HOLD', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
