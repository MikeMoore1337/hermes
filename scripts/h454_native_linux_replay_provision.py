"""One-time provisioning for a new native read replay journal.

Never replaces, resets, truncates or deletes an existing journal. Existing
state, even if empty or incomplete, requires operator inspection.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import stat

from device_fabric.linux_native_replay import _MAGIC

SERVICE_USER = 'hermes-commander-native'
PARENT = Path('/var/lib')
DIRECTORY = 'hermes-commander-replay'
FILE = 'claims'


def provision(*, parent: Path, uid: int, gid: int) -> None:
    if (os.geteuid() != 0 or not isinstance(parent, Path) or not parent.is_absolute()
            or type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0):
        raise ValueError('replay_provision_denied')
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('replay_provision_denied')
        os.mkdir(DIRECTORY, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        directory_fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=parent_fd)
        try:
            info = os.fstat(directory_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_nlink < 2:
                raise ValueError('replay_provision_denied')
            os.fchmod(directory_fd, 0o700)
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            file_fd = os.open(FILE, flags, 0o600, dir_fd=directory_fd)
            try:
                os.fchmod(file_fd, 0o600)
                os.fchown(file_fd, uid, gid)
                if os.write(file_fd, _MAGIC) != len(_MAGIC):
                    raise ValueError('replay_provision_denied')
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            os.fchown(directory_fd, uid, gid)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', action='store_true', required=True)
    parser.parse_args()
    try:
        user = pwd.getpwnam(SERVICE_USER)
        provision(parent=PARENT, uid=user.pw_uid, gid=user.pw_gid)
        print('H454_LINUX_REPLAY_PROVISION=PASS')
        return 0
    except Exception:
        print('H454_LINUX_REPLAY_PROVISION=HOLD')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
