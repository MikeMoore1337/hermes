"""Pinned YFC unit update with a durable, credential-free rollback checkpoint."""
from __future__ import annotations

try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

UNITS = Path('/etc/systemd/system')
CHECKPOINT = Path('/opt/hermes-commander-native/receipts/h454-yfc-readiness-c5586096')
LOCK = Path('/run/lock/h454-native-private-version-upgrade.lock')
HOST_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
HOST_HASH = 'bd6d9675cc868f14e97c8ef24f58c560cf41930f6bc2dcb7eedc93e6262ff595'
MANIFEST = Path('/var/lib/hermes-commander-native/manifest.json')
MANIFEST_HASH = '0b1235c6d56d460c83ba45405c831bc08b4001d6207a3aeff04f80ff1a8ea8b4'
NATIVE = 'hermes-commander-native.service'
TUNNEL = 'hermes-commander-tunnel.service'
AUDIT = 'hermes-commander-audit.socket'
OLD = {NATIVE:'487ce0184ad6d7b3cbf63c9cc9078320508ad2715d4bf94a3a8e35366f1d38db',
       TUNNEL:'8932bc2e3fc2886ed3a48abf3b45c648a391ed8df2e11a22fce59be1f6f43708'}
NEW = {NATIVE:'961339018259eab16ff5bdc0c67cdc9865734cbd8c95c7bad027f356f3e4bb0f',
       TUNNEL:'dc2c70294f992827c76ac32c9135f0bd3c626401c5831b9e7d632b65c77e31c4'}
POST = (b"ExecStartPost=/usr/bin/timeout 25 /bin/sh -c 'until /usr/bin/timeout 3 "
        b"/usr/bin/openssl s_client -unix /run/hermes-commander-tunnel/relay.sock "
        b"-servername brc-agent.internal -verify_hostname brc-agent.internal "
        b"-verify_return_error -CAfile /opt/hermes-commander-native/trust/ca.crt "
        b"</dev/null >/dev/null 2>&1; do sleep 1; done'\n")


class Hold(Exception):
    pass


def demand(ok: bool) -> None:
    if not ok:
        raise Hold()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def checked(path: Path, *, uid: int = 0, mode: int = 0o644, limit: int = 16384) -> bytes:
    info = path.lstat()
    demand(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
           and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        inside = os.fstat(fd)
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        demand((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
               (inside.st_dev, inside.st_ino, inside.st_size, inside.st_mtime_ns, inside.st_ctime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
               and len(data) == info.st_size)
        return data
    finally:
        os.close(fd)


def root_directory(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        demand(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def replace_unit(path: Path, data: bytes) -> None:
    side = path.with_name('.h454-readiness-' + path.name)
    create(side, data, 0o644)
    os.replace(side, path)
    sync_dir(path.parent)


def no_pending_replacements() -> None:
    for name in OLD:
        side = UNITS/('.h454-readiness-' + name)
        demand(not side.exists() and not side.is_symlink())


def candidates(old: dict[str, bytes]) -> dict[str, bytes]:
    demand(set(old) == set(OLD) and all(digest(old[k]) == OLD[k] for k in OLD))
    marker = b'After=network-online.target local-fs.target hermes-commander-audit.socket\n'
    line = b'NoNewPrivileges=yes\n'
    demand(old[NATIVE].count(marker) == 1 and old[TUNNEL].count(line) == 1)
    new = {
        NATIVE: old[NATIVE].replace(marker, marker + b'Requires=hermes-commander-tunnel.service\n'
                                    b'After=hermes-commander-tunnel.service\n'),
        TUNNEL: old[TUNNEL].replace(line, POST + line),
    }
    demand(all(digest(new[k]) == NEW[k] for k in NEW))
    return new


def run(*args: str, timeout: int = 40) -> bytes:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    demand(result.returncode == 0 and len(result.stdout) < 16384)
    return result.stdout


def service_state(name: str, expected: str) -> None:
    value = run('/usr/bin/systemctl', 'show', name, '--no-pager',
                '--property=ActiveState,UnitFileState,LoadState,FragmentPath,DropInPaths,NeedDaemonReload')
    lines = value.decode('ascii').splitlines()
    demand(len(lines) == 6 and len({line.split('=', 1)[0] for line in lines}) == 6)
    state = dict(line.split('=', 1) for line in lines)
    demand(state == {'ActiveState':expected, 'UnitFileState':'disabled', 'LoadState':'loaded',
                     'FragmentPath':str(UNITS/name), 'DropInPaths':'', 'NeedDaemonReload':'no'})


def tls_ready() -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            run('/usr/sbin/runuser','-u','hermes-commander-tunnel','-g','hermes-commander-native',
                '--','/usr/bin/timeout','3','/usr/bin/openssl','s_client','-unix',
                '/run/hermes-commander-tunnel/relay.sock','-servername','brc-agent.internal',
                '-verify_hostname','brc-agent.internal','-verify_return_error','-CAfile',
                '/opt/hermes-commander-native/trust/ca.crt', timeout=5)
            return
        except (Hold, subprocess.TimeoutExpired):
            time.sleep(1)
    raise Hold()


def start_services() -> None:
    run('/usr/bin/systemctl','daemon-reload')
    # Controlled stop/start and rollback must not exhaust systemd's restart budget.
    run('/usr/bin/systemctl','reset-failed',TUNNEL,NATIVE)
    run('/usr/bin/systemctl','start',TUNNEL)
    tls_ready()
    run('/usr/bin/systemctl','start',NATIVE)
    service_state(TUNNEL, 'active')
    service_state(NATIVE, 'active')
    service_state(AUDIT, 'active')


def stop_services() -> None:
    run('/usr/bin/systemctl','stop',NATIVE)
    run('/usr/bin/systemctl','stop',TUNNEL)


def preflight() -> None:
    demand(os.geteuid() == 0 and sys.platform == 'linux')
    root_directory(UNITS)
    root_directory(CHECKPOINT.parent)
    root_directory(HOST_KEY.parent)
    root_directory(MANIFEST.parent.parent)
    demand(digest(checked(HOST_KEY, limit=1024)) == HOST_HASH)
    identity = pwd.getpwnam('hermes-commander-native')
    info = MANIFEST.parent.lstat()
    demand(stat.S_ISDIR(info.st_mode) and info.st_uid == identity.pw_uid and
           info.st_gid == identity.pw_gid and stat.S_IMODE(info.st_mode) == 0o700)
    demand(digest(checked(MANIFEST,uid=identity.pw_uid,mode=0o600)) == MANIFEST_HASH)
    bearer = (MANIFEST.parent/'device.json').lstat()
    demand(stat.S_ISREG(bearer.st_mode) and bearer.st_uid == identity.pw_uid and
           bearer.st_gid == identity.pw_gid and bearer.st_nlink == 1 and
           stat.S_IMODE(bearer.st_mode) == 0o600)


def checkpoint(old: dict[str, bytes]) -> None:
    os.mkdir(CHECKPOINT, 0o700)
    os.chmod(CHECKPOINT, 0o700)
    for name in (NATIVE, TUNNEL):
        create(CHECKPOINT/name, old[name], 0o600)
    create(CHECKPOINT/'receipt.json', json.dumps({'schema':'h454-yfc-readiness-v1',
           'old':OLD,'new':NEW},sort_keys=True).encode('ascii'), 0o600)
    sync_dir(CHECKPOINT)
    sync_dir(CHECKPOINT.parent)


def saved() -> dict[str, bytes]:
    root_directory(CHECKPOINT)
    demand(stat.S_IMODE(CHECKPOINT.lstat().st_mode) == 0o700)
    data = {name:checked(CHECKPOINT/name,mode=0o600) for name in OLD}
    demand(all(digest(data[name]) == OLD[name] for name in OLD))
    receipt = json.loads(checked(CHECKPOINT/'receipt.json',mode=0o600))
    demand(receipt == {'schema':'h454-yfc-readiness-v1','old':OLD,'new':NEW})
    return data


def restore(old: dict[str, bytes]) -> None:
    no_pending_replacements()
    for name in OLD:
        current = checked(UNITS/name)
        demand(digest(current) in (OLD[name], NEW[name]))
    stop_services()
    for name in OLD:
        if digest(checked(UNITS/name)) != OLD[name]:
            replace_unit(UNITS/name, old[name])
    start_services()


def plan() -> tuple[dict[str, bytes], dict[str, bytes]]:
    preflight()
    for name in (NATIVE,TUNNEL,AUDIT):
        service_state(name,'active')
    old = {name:checked(UNITS/name) for name in OLD}
    new = candidates(old)
    no_pending_replacements()
    if CHECKPOINT.exists() or CHECKPOINT.is_symlink():
        demand(saved() == old)
    return old, new


def execute() -> None:
    old, new = plan()
    if not CHECKPOINT.exists():
        checkpoint(old)
    try:
        stop_services()
        for name in (TUNNEL,NATIVE):
            demand(digest(checked(UNITS/name)) == OLD[name])
            replace_unit(UNITS/name,new[name])
        start_services()
    except Exception:
        restore(old)
        raise


def main() -> int:
    try:
        demand(fcntl is not None and len(sys.argv)==2 and sys.argv[1] in ('check','install','rollback'))
        lock = os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(lock)
            demand(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                   and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==0)
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            demand((LOCK.lstat().st_dev,LOCK.lstat().st_ino)==(info.st_dev,info.st_ino))
            if sys.argv[1] == 'check':
                plan()
            elif sys.argv[1] == 'install':
                execute()
            else:
                preflight()
                restore(saved())
        finally:
            os.close(lock)
        print('H454_YFC_READINESS_' + sys.argv[1].upper() + '=PASS')
        return 0
    except Exception:
        print('H454_YFC_READINESS=HOLD',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
