"""Verify the pinned release before importing its personal YFC worker.

The task scheduler must authenticate this bootstrap and supply both pinned
digests. This bootstrap neither installs nor provisions a personal device.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import runpy
import stat
import sys

MAX_MANIFEST = 32 * 1024 * 1024
MAX_VERIFIER = 128 * 1024
REPARSE = 0x400
APP_NAME = "HermesCommanderPersonalPsec"


def _digest(value: str) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _read(path: Path, limit: int) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
        or getattr(before, "st_file_attributes", 0) & REPARSE or not 0 < before.st_size <= limit):
        raise ValueError()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
    if (len(data) != before.st_size or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(after.st_mode) or any(
            getattr(before, key) != getattr(opened, key) or
            getattr(opened, key) != getattr(after, key) for key in fields)):
        raise ValueError()
    return data


def _directory(path: Path) -> None:
    if not path.is_absolute() or os.path.normcase(str(path.resolve(strict=True))) != os.path.normcase(str(path)):
        raise ValueError()
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise ValueError()


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    try:
        if len(args) != 2 or not all(_digest(item) for item in args):
            raise ValueError()
        root = Path(os.environ.get("LOCALAPPDATA", "")) / APP_NAME
        if not root.is_absolute():
            raise ValueError()
        release = root / "release"
        for directory in (root / "worker-private", release / "code" / "device_fabric",
                          release / "code" / "scripts"):
            _directory(directory)
        manifest = _read(root / "worker-private" / "release-manifest.json", MAX_MANIFEST)
        if hashlib.sha256(manifest).hexdigest() != args[0]:
            raise ValueError()
        verifier = release / "code" / "device_fabric" / "windows_personal_commander_bundle.py"
        source = _read(verifier, MAX_VERIFIER)
        if hashlib.sha256(source).hexdigest() != args[1]:
            raise ValueError()
        namespace = {"__name__": "_h454_pinned_bundle", "__file__": str(verifier)}
        exec(compile(source, str(verifier), "exec"), namespace)
        namespace["verify"](release, manifest, args[0])
        entry = release / "code" / "scripts" / "h454_windows_personal_yfc_entry.py"
        sys.path.insert(0, str(release / "code"))
        sys.argv = [str(entry), "--run"]
        runpy.run_path(str(entry), run_name="__main__")
        return 0
    except SystemExit as result:
        return result.code if type(result.code) is int else 2
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
