"""Bounded metadata snapshot for an owner-selected project directory.

This inspects no file contents. A successful snapshot is not a filesystem
lock: an existing process can change the tree immediately after the scan.
It must not be used by itself to attest an ongoing isolation boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import ntpath
from pathlib import Path
import stat
import time

REPARSE = 0x400
MAX_ENTRIES = 250_000
MAX_SECONDS = 45.0


class ProjectScanDenied(ValueError):
    """Refusal that does not disclose project paths or filenames."""


@dataclass(frozen=True, slots=True)
class ProjectSnapshot:
    directories: int
    files: int
    device: int
    root_id: int


def scan(root: Path, *, limit: int = MAX_ENTRIES, seconds: float = MAX_SECONDS,
         excluded: tuple[Path, ...] = ()) -> ProjectSnapshot:
    """Reject links, reparse points, inaccessible entries and incomplete scans."""
    try:
        if (not isinstance(root, Path) or not root.is_absolute()
            or type(limit) is not int or not 1 <= limit <= MAX_ENTRIES
            or type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS
            or type(excluded) is not tuple or excluded not in ((), (root / '.artifacts',))):
            raise ValueError()
        if os.name == "nt":
            drive, _ = ntpath.splitdrive(str(root))
            if len(drive) != 2 or drive[1] != ":" or not drive[0].isascii() or not drive[0].isalpha():
                raise ValueError()
        initial = root.lstat()
        if (not stat.S_ISDIR(initial.st_mode) or getattr(initial, "st_file_attributes", 0) & REPARSE
            or (os.name == "nt" and not initial.st_ino)
            or os.path.normcase(str(root.resolve(strict=True))) != os.path.normcase(str(root))):
            raise ValueError()
        deadline = time.monotonic() + seconds
        pending = [root]
        directories = files = entries_seen = 0
        while pending:
            if time.monotonic() >= deadline:
                raise ValueError()
            directory = pending.pop()
            # Re-check before opening because it might have changed since listing.
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_dev != initial.st_dev
                or getattr(info, "st_file_attributes", 0) & REPARSE):
                raise ValueError()
            with os.scandir(directory) as items:
                directories += 1
                for entry in items:
                    entries_seen += 1
                    if entries_seen > limit or time.monotonic() >= deadline:
                        raise ValueError()
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
                        raise ValueError()
                    if excluded and Path(entry.path) == excluded[0]:
                        actual = Path(entry.path).lstat()
                        if (not stat.S_ISDIR(actual.st_mode) or actual.st_dev != initial.st_dev
                                or getattr(actual, 'st_file_attributes', 0) & REPARSE):
                            raise ValueError()
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(info.st_mode):
                        # On Windows DirEntry.stat may report st_nlink=0 even for
                        # hardlinks. os.stat(path) performs the required query.
                        actual = os.stat(entry.path, follow_symlinks=False)
                        if (not stat.S_ISREG(actual.st_mode) or actual.st_dev != initial.st_dev
                            or getattr(actual, "st_file_attributes", 0) & REPARSE or actual.st_nlink != 1):
                            raise ValueError()
                        files += 1
                    else:
                        raise ValueError()
        final = root.lstat()
        if ((initial.st_dev, initial.st_ino) != (final.st_dev, final.st_ino)
            or getattr(final, "st_file_attributes", 0) & REPARSE or not stat.S_ISDIR(final.st_mode)):
            raise ValueError()
        return ProjectSnapshot(directories, files, initial.st_dev, initial.st_ino)
    except Exception:
        raise ProjectScanDenied("personal_project_scan_denied") from None
