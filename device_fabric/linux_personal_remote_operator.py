"""Fixed root-side entry for an explicitly selected personal VPS project.

The request arrives over the existing key-authenticated SSH connection on
stdin. This entry does not accept a command, executable, config or unit path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys

RELEASE = 'efc34636626765f0274422f18651daa38e358af1'
MANIFEST_SHA256 = 'da5af6f2dcb593680c891c97e2e766ebb45ee23914550f5d631c736b3f324b60'
ROOT = Path('/opt/hermes-commander-personal/admin-releases') / ('main-' + RELEASE)
NAME = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')


def _read(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444 or not 0 < before.st_size <= maximum):
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(value) != before.st_size or any(getattr(before, k) != getattr(opened, k)
                                           or getattr(opened, k) != getattr(after, k) for k in keys):
        raise ValueError()
    return value


def _verify_operator() -> None:
    for directory in (ROOT, *ROOT.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError()
    raw = _read(ROOT / 'manifest.json', 2_000_000)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError()
    manifest = json.loads(raw)
    files = manifest.get('files')
    if (manifest.get('release') != RELEASE or type(files) is not dict or not 0 < len(files) <= 3000
            or 'scripts/h454_linux_personal_add_project.py' not in files):
        raise ValueError()
    for name, expected in files.items():
        path = PurePosixPath(name)
        if (type(name) is not str or path.is_absolute() or '..' in path.parts
                or not path.parts or path.parts[0] not in ('scripts', 'device_fabric')
                or type(expected) is not str or re.fullmatch(r'[0-9a-f]{64}', expected) is None):
            raise ValueError()
        directory = ROOT
        for part in path.parts[:-1]:
            directory = directory / part
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError()
        if hashlib.sha256(_read(ROOT.joinpath(*path.parts), 2_000_000)).hexdigest() != expected:
            raise ValueError()


def main() -> None:
    try:
        if os.geteuid() != 0:
            raise ValueError()
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError()
        request = json.loads(raw)
        if (type(request) is not dict or set(request) != {'target', 'name', 'path', 'mode'}
                or request['target'] not in ('hermes-vps', 'yfc-vps')
                or type(request['name']) is not str or NAME.fullmatch(request['name']) is None
                or type(request['path']) is not str or not 1 <= len(request['path']) <= 2048
                or request['mode'] not in ('plan', 'execute')):
            raise ValueError()
        _verify_operator()
        sys.path.insert(0, str(ROOT))
        sys.argv = ['h454_linux_personal_add_project', '--target', request['target'],
                    '--name', request['name'], '--project', request['path']]
        if request['mode'] == 'execute':
            sys.argv.append('--execute')
        runpy.run_module('scripts.h454_linux_personal_add_project', run_name='__main__')
    except Exception:
        print('H454_REMOTE_PROJECT=HOLD', file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
