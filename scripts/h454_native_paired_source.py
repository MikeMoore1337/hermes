"""Stage a verified paired-upgrade source bundle without changing active state."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from scripts.h454_native_paired_rebind import RebindDenied, verified_sources


def stage(releases: Path, bundle: bytes, receipt: bytes, *, release: str,
          bundle_sha256: str, trusted_uid: int) -> None:
    """Create one immutable source tree; retain partial output on failure.

    The host operator must pin all ancestors and hold the lifecycle lock.
    This function never installs a unit, reads a token or starts a process.
    """
    parent_fd = leaf_fd = None
    try:
        if (not releases.is_absolute() or type(trusted_uid) is not int
            or trusted_uid != os.geteuid() or type(release) is not str
            or re.fullmatch(r"[0-9a-f]{40}", release) is None or release == "0" * 40):
            raise RebindDenied()
        sources = verified_sources(bundle, receipt, release=release,
                                   expected_bundle_sha256=bundle_sha256)
        parent_fd = os.open(releases, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.fstat(parent_fd)
        if parent.st_uid != trusted_uid or parent.st_mode & 0o022:
            raise RebindDenied()
        leaf = "main-" + release
        os.mkdir(leaf, 0o755, dir_fd=parent_fd)
        leaf_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        os.fchmod(leaf_fd, 0o755)
        for folder in ("device_fabric", "scripts"):
            os.mkdir(folder, 0o755, dir_fd=leaf_fd)
            folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=leaf_fd)
            try:
                os.fchmod(folder_fd, 0o755)
                for name, data in sources.items():
                    prefix = folder + "/"
                    if not name.startswith(prefix):
                        continue
                    filename = name[len(prefix):]
                    if "/" in filename or not filename or type(data) is not bytes:
                        raise RebindDenied()
                    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=folder_fd)
                    try:
                        view = memoryview(data)
                        while view:
                            n = os.write(fd, view)
                            if n <= 0:
                                raise RebindDenied()
                            view = view[n:]
                        os.fchmod(fd, 0o444)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    verify_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=folder_fd)
                    try:
                        verified = os.fstat(verify_fd)
                        if (not stat.S_ISREG(verified.st_mode) or verified.st_uid != trusted_uid
                            or verified.st_nlink != 1 or stat.S_IMODE(verified.st_mode) != 0o444
                            or os.read(verify_fd, len(data) + 1) != data):
                            raise RebindDenied()
                    finally:
                        os.close(verify_fd)
                os.fsync(folder_fd)
            finally:
                os.close(folder_fd)
        os.fsync(leaf_fd)
        os.fsync(parent_fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        if parent_fd is not None:
            os.close(parent_fd)
