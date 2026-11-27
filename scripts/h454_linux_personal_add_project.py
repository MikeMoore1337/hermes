"""Local root operator for one explicitly selected existing Linux project.

No remote argument supplies a config, unit, executable or service identity.
It never changes ownership, groups, project ACLs, or the existing bearer.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

from device_fabric import linux_personal_config as config
from device_fabric import linux_personal_project_registration as registration
from scripts.h454_linux_personal_service import CONFIG_ROOT, STATE_ROOT, UNITS, _read, _root_chain

UNIT_ROOT = Path('/etc/systemd/system')
LOCK = Path('/run/lock/hermes-commander-project-registration.lock')
ACCESS_CHECK = '''import os,sys
p=sys.argv[1]; flags=os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
fd=os.open('/',flags)
try:
 for part in p.split('/')[1:]:
  child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
 if not os.access('/proc/self/fd/'+str(fd),os.W_OK|os.X_OK,effective_ids=True):raise ValueError()
finally:os.close(fd)
'''


def _command(*args: str, timeout: int = 35) -> bytes:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError()
    return result.stdout


def _task(target: str, mode: str) -> None:
    if mode not in ('stop', 'start'):
        raise ValueError()
    _command('/usr/bin/systemctl', mode, UNITS[target])


def _active(target: str) -> bool:
    try:
        _command('/usr/bin/systemctl', 'is-active', '--quiet', UNITS[target])
        return True
    except Exception:
        return False


def _check_unit(target: str, path: Path) -> None:
    out = _command('/usr/bin/systemctl', 'show', UNITS[target], '-p', 'User', '-p', 'Group',
                   '-p', 'FragmentPath', '-p', 'NeedDaemonReload').decode('utf-8')
    data = dict(line.split('=', 1) for line in out.splitlines())
    if (data != {'User':'hermes-commander-personal', 'Group':'hermes-commander-personal',
                 'FragmentPath':str(path), 'NeedDaemonReload':'no'} or not _active(target)):
        raise ValueError()


def _check_access(project: str) -> None:
    # Run the actual no-symlink traversal and effective-access check as the
    # existing unprivileged service identity, never as root.
    _command('/usr/sbin/runuser', '-u', 'hermes-commander-personal', '--',
             '/usr/bin/python3', '-I', '-B', '-c', ACCESS_CHECK, project)


def _write_once(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _replace(path: Path, before: bytes, after: bytes, limit: int) -> None:
    info = path.lstat()
    if _read(path, owner=0, modes=(0o444, 0o644), maximum=limit) != before:
        raise ValueError()
    temporary = path.with_name('.' + path.name + '.h454-' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        if _read(path, owner=0, modes=(0o444, 0o644), maximum=limit) != before:
            raise ValueError()
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if fd >= 0: os.close(fd)
        try:
            item = temporary.lstat()
            if (item.st_dev, item.st_ino) == (created.st_dev, created.st_ino): temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', choices=tuple(UNITS), required=True)
    parser.add_argument('--name')
    parser.add_argument('--project')
    parser.add_argument('--rollback')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    lock = -1
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError()
        _root_chain(CONFIG_ROOT)
        _root_chain(STATE_ROOT)
        _root_chain(UNIT_ROOT)
        config_path = CONFIG_ROOT / (args.target + '.json')
        unit_path = UNIT_ROOT / UNITS[args.target]
        def read():
            return (_read(config_path, owner=0, modes=(0o444, 0o644), maximum=8192),
                    _read(unit_path, owner=0, modes=(0o444, 0o644), maximum=65536))
        old_config, old_unit = read()
        if args.rollback:
            if args.name is not None or args.project is not None or not re.fullmatch(
                    r'project-registration-[a-f0-9]{32}', args.rollback):
                raise ValueError()
            previous = STATE_ROOT / args.rollback
            _root_chain(previous)
            if stat.S_IMODE(previous.lstat().st_mode) != 0o700:
                raise ValueError()
            prior_config, prior_unit, applied_config, applied_unit = tuple(
                _read(previous / name, owner=0, modes=(0o600,), maximum=maximum)
                for name, maximum in (('old-config',8192), ('old-unit',65536),
                                      ('new-config',8192), ('new-unit',65536)))
            if (old_config, old_unit) != (applied_config, applied_unit):
                raise ValueError()
            prior = config.parse(prior_config, target=args.target)
            applied = config.parse(applied_config, target=args.target)
            added = set(applied.additional_projects) - set(prior.additional_projects)
            if len(added) != 1 or not set(prior.additional_projects).issubset(applied.additional_projects):
                raise ValueError()
            name, path = next(iter(added))
            if registration.prepare(prior_config, prior_unit, target=args.target,
                                    name=name, project=path) != (applied_config, applied_unit):
                raise ValueError()
            new_config, new_unit = prior_config, prior_unit
        else:
            if args.name is None or args.project is None:
                raise ValueError()
            new_config, new_unit = registration.prepare(old_config, old_unit, target=args.target,
                                                         name=args.name, project=args.project)
        _check_unit(args.target, unit_path)
        if args.project is not None:
            _check_access(args.project)
        if old_config == new_config:
            print('H454_LINUX_PROJECT=ALREADY_CONFIGURED')
            return 0
        if not args.execute:
            print('H454_LINUX_PROJECT=PLAN_PASS')
            return 0
        lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError()
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if read() != (old_config, old_unit):
            raise ValueError()
        _check_unit(args.target, unit_path)
        if args.project is not None:
            _check_access(args.project)
        backup_dir = STATE_ROOT / ('project-registration-' + uuid.uuid4().hex)
        def backup(*items):
            backup_dir.mkdir(mode=0o700)
            for name, data in zip(('old-config', 'old-unit', 'new-config', 'new-unit'), items):
                _write_once(backup_dir / name, data)
        def healthy():
            for _ in range(5):
                if not _active(args.target): return False
                time.sleep(2)
            return _active(args.target)
        registration.apply(old_config, old_unit, new_config, new_unit, backup=backup, read=read,
            replace_config=lambda old,new: _replace(config_path, old, new, 8192),
            replace_unit=lambda old,new: _replace(unit_path, old, new, 65536),
            stop=lambda: _task(args.target, 'stop'),
            reload=lambda: _command('/usr/bin/systemctl', 'daemon-reload'),
            start=lambda: _task(args.target, 'start'), healthy=healthy)
        print('H454_LINUX_PROJECT=TASK_STARTED REMOTE_ACCESS=NOT_VERIFIED BACKUP=' + backup_dir.name)
        return 0
    except registration.ProjectRollbackFailed:
        print('H454_LINUX_PROJECT=HOLD ROLLBACK=FAILED', file=sys.stderr)
        return 2
    except Exception:
        print('H454_LINUX_PROJECT=HOLD ROLLBACK=IF_CHANGED', file=sys.stderr)
        return 2
    finally:
        if lock >= 0:
            os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())
