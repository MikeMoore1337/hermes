"""Install the owner-approved public YFC dev source snapshot, never a service."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

from device_fabric.linux_native_files import MAX_READ_BYTES, READ_EXTENSIONS, _relative
from device_fabric.linux_native_landlock import PRIVATE_DIRECTORIES

COMMIT = '17c5f29921f379d1f5229eede40c88d5183ddcf9'
ARCHIVE_SHA256 = '6ae46df006ad321238761b900b64cd1e410a53ff09561da0e16d491ed67201a2'
SNAPSHOT_ROOT = Path('/opt/hermes-commander-yfc-snapshots')
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_TOTAL = 40 * 1024 * 1024
MAX_FILES = 3000


class SnapshotDenied(ValueError):
    pass


def read_archive(raw: bytes, expected_sha: str) -> dict[str, bytes]:
    """Check every entry before creating anything on the target host."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_ARCHIVE
                or hashlib.sha256(raw).hexdigest() != expected_sha):
            raise SnapshotDenied('snapshot_denied')
        result: dict[str, bytes] = {}
        total = 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            for item in archive:
                name = item.name
                _relative(name)
                parts = PurePosixPath(name).parts
                if (not item.isfile() or name in result or len(parts) > 64
                        or any(p.casefold() in PRIVATE_DIRECTORIES for p in parts)
                        or PurePosixPath(name).suffix.lower() not in READ_EXTENSIONS
                        or not 0 <= item.size <= MAX_READ_BYTES
                        or len(result) >= MAX_FILES):
                    raise SnapshotDenied('snapshot_denied')
                total += item.size
                if total > MAX_TOTAL:
                    raise SnapshotDenied('snapshot_denied')
                stream = archive.extractfile(item)
                if stream is None:
                    raise SnapshotDenied('snapshot_denied')
                data = stream.read(MAX_READ_BYTES + 1)
                if len(data) != item.size:
                    raise SnapshotDenied('snapshot_denied')
                result[name] = data
        if not result or 'README.md' not in result:
            raise SnapshotDenied('snapshot_denied')
        return result
    except Exception:
        raise SnapshotDenied('snapshot_denied') from None


def _trusted_directory(path: Path) -> None:
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SnapshotDenied('snapshot_denied')


def _publish_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        raise SnapshotDenied('snapshot_denied')


def install(files: dict[str, bytes], root: Path = SNAPSHOT_ROOT) -> Path:
    """Create one root-owned tree and publish without replacing an existing tree."""
    if os.geteuid() != 0 or root != SNAPSHOT_ROOT:
        raise SnapshotDenied('snapshot_denied')
    _trusted_directory(root.parent)
    try:
        root.mkdir(mode=0o755)
    except FileExistsError:
        pass
    _trusted_directory(root)
    if stat.S_IMODE(root.stat().st_mode) != 0o755:
        raise SnapshotDenied('snapshot_denied')
    target = root / ('dev-' + COMMIT)
    temp = Path(tempfile.mkdtemp(prefix='.h454-stage-', dir=root))
    try:
        for name, data in files.items():
            dest = temp.joinpath(*PurePosixPath(name).parts)
            dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o644)
        os.chmod(temp, 0o755)
        _publish_noreplace(temp, target)
        return target
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    try:
        os.umask(0o022)
        with args.archive.open('rb') as stream:
            raw = stream.read(MAX_ARCHIVE + 1)
        files = read_archive(raw, ARCHIVE_SHA256)
        if len(files) != 2671:
            raise SnapshotDenied('snapshot_denied')
        install(files)
        print('YFC_DEV_SNAPSHOT_INSTALLED_READ_ONLY_SOURCE_ONLY')
    except Exception:
        raise SystemExit('YFC_DEV_SNAPSHOT_DENIED') from None


if __name__ == '__main__':
    main()
