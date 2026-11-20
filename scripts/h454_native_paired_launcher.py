"""Pinned archive launcher for the disabled, paired native upgrade.

The caller must obtain the archive digest independently from the reviewed Git
revision and execute this launcher from a verified source. No pairing or start.
"""
from __future__ import annotations

import hashlib
import importlib
import os
from pathlib import Path
import re
import socket
import stat
import sys
import zipfile

ARCHIVE_ROOT = Path("/root")
MAX_ARCHIVE = 16 * 1024 * 1024


def verified_archive(release: str, digest: str, *, owner: int) -> Path:
    """Verify one private archive before adding it to Python's import path."""
    root_fd = file_fd = None
    try:
        if (type(owner) is not int or owner != os.geteuid()
            or re.fullmatch(r"[0-9a-f]{40}", release) is None
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise ValueError()
        root_fd = os.open(ARCHIVE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root = os.fstat(root_fd)
        if root.st_uid != owner or stat.S_IMODE(root.st_mode) != 0o700:
            raise ValueError()
        name = "h454-paired-operator-" + release + ".zip"
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        before = os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o400
            or not 0 < before.st_size <= MAX_ARCHIVE):
            raise ValueError()
        checksum, remaining = hashlib.sha256(), before.st_size
        while remaining:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                raise ValueError()
            checksum.update(chunk)
            remaining -= len(chunk)
        with os.fdopen(os.dup(file_fd), "rb") as stream, zipfile.ZipFile(stream) as package:
            if package.comment != release.encode("ascii"):
                raise ValueError()
            if not {"scripts/h454_native_paired_apply.py", "device_fabric/__init__.py"}.issubset(package.namelist()):
                raise ValueError()
        after = os.fstat(file_fd)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_size", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        if (checksum.hexdigest() != digest or any(
            getattr(before, k) != getattr(after, k) or getattr(before, k) != getattr(current, k)
            for k in fields
        )):
            raise ValueError()
        return ARCHIVE_ROOT / name
    except Exception:
        raise ValueError("native_paired_archive_denied") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if root_fd is not None:
            os.close(root_fd)


def main(argv: list[str]) -> int:
    try:
        if (len(argv) != 3 or argv[0] not in ("plan", "install-off", "recover-off", "rollback-off")
            or os.geteuid() != 0 or socket.gethostname() != "vps1777112993"
            or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode
            or any(name == prefix or name.startswith(prefix + ".")
                   for name in sys.modules for prefix in ("scripts", "device_fabric"))):
            raise ValueError()
        mode, release, digest = argv
        archive = verified_archive(release, digest, owner=0)
        sys.path.insert(0, str(archive))
        operator = importlib.import_module("scripts.h454_native_paired_apply")
        if mode == "plan":
            with operator.host_lock():
                operator.host.inspect()
            status = "PLAN_PASS_NO_MUTATION"
        else:
            status = operator.operate(mode)
        print("H454_PAIRED_UPGRADE=" + status)
        return 0
    except Exception:
        print("H454_PAIRED_UPGRADE=HOLD")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
