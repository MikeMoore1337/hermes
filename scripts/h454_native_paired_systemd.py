"""Synthetic-testable trust/unit file replacement; never reload or start systemd."""
from __future__ import annotations

import os
from pathlib import Path
import hashlib
import json
import stat

from scripts.h454_native_paired_rebind import RebindDenied, _canonical
from scripts.h454_native_paired_state import _create, _directory, _read

MODES = {"private-relay.json": 0o444, "hermes-commander-native.service": 0o644,
         "hermes-commander-native-preflight.service": 0o644}
FILES = {"trust": "private-relay.json", "preflight": "hermes-commander-native-preflight.service",
         "active": "hermes-commander-native.service"}


def replace_trusted_file(directory: Path, name: str, *, expected: bytes,
                         replacement: bytes, trusted_uid: int) -> None:
    """Replace one root-controlled nonsecret file; preserve a failed stage.

    The host operator must pin ancestors, hold its lock and keep the service
    inactive. It must journal both snapshots before calling this function.
    """
    dfd = fd = None
    try:
        if (name not in MODES or not directory.is_absolute()
            or type(trusted_uid) is not int or trusted_uid != os.geteuid()
            or type(expected) is not bytes or not 0 < len(expected) <= 16384
            or type(replacement) is not bytes or not 0 < len(replacement) <= 16384):
            raise RebindDenied()
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.fstat(dfd)
        if parent.st_uid != trusted_uid or parent.st_mode & 0o022:
            raise RebindDenied()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != trusted_uid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != MODES[name]
            or os.read(fd, 16385) != expected):
            raise RebindDenied()
        os.close(fd)
        fd = None
        staged = ".h454-paired-" + name + ".pending"
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dfd)
        os.fchown(fd, before.st_uid, before.st_gid)
        os.fchmod(fd, MODES[name])
        view = memoryview(replacement)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise RebindDenied()
            view = view[n:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_size, current.st_ctime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns
        ):
            raise RebindDenied()
        os.replace(staged, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
            or (after.st_uid, after.st_gid) != (before.st_uid, before.st_gid)
            or stat.S_IMODE(after.st_mode) != MODES[name]
            or os.read(fd, 16385) != replacement):
            raise RebindDenied()
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if fd is not None:
            os.close(fd)
        if dfd is not None:
            os.close(dfd)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _target(directory: Path, name: str, trusted_uid: int) -> bytes:
    dfd = fd = None
    try:
        if not directory.is_absolute() or name not in MODES:
            raise RebindDenied()
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.fstat(dfd)
        if parent.st_uid != trusted_uid or parent.st_mode & 0o022:
            raise RebindDenied()
        try:
            os.stat(".h454-paired-" + name + ".pending", dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RebindDenied()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        before = os.fstat(fd)
        raw = os.read(fd, 8193)
        after = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != trusted_uid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != MODES[name]
            or not 0 < len(raw) <= 8192 or len(raw) != before.st_size
            or (before.st_dev, before.st_ino, before.st_ctime_ns) !=
               (after.st_dev, after.st_ino, after.st_ctime_ns)):
            raise RebindDenied()
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        if dfd is not None:
            os.close(dfd)


def prepare(journal: Path, snapshots: dict[str, tuple[bytes, bytes]], *, trusted_uid: int) -> None:
    """Seal vetted nonsecret snapshots before a switch; no systemd action."""
    fd = None
    try:
        fd = _directory(journal, trusted_uid)
        if os.listdir(fd) or type(snapshots) is not dict or set(snapshots) != set(FILES):
            raise RebindDenied()
        record = {"schema": "h454-paired-systemd-journal-v1"}
        for key in FILES:
            pair = snapshots[key]
            if type(pair) is not tuple or len(pair) != 2:
                raise RebindDenied()
            for label, data in zip(("old", "new"), pair):
                if (type(data) is not bytes or not 0 < len(data) <= 8192
                    or b"brc_dev_" in data):
                    raise RebindDenied()
                _create(fd, label + "-" + key, data)
                record[label + "_" + key] = _digest(data)
        _create(fd, "journal.json", _canonical(record))
        os.fsync(fd)
        _create(fd, "prepared", b"PREPARED\n")
        os.fsync(fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def _load(fd: int, trusted_uid: int) -> dict[str, tuple[bytes, bytes]]:
    allowed = {"journal.json", "prepared", "started", "complete"} | {
        label + "-" + key for key in FILES for label in ("old", "new")
    }
    if set(os.listdir(fd)) - allowed or _read(fd, "prepared", owner=trusted_uid) != b"PREPARED\n":
        raise RebindDenied()
    raw = _read(fd, "journal.json", owner=trusted_uid)
    record = json.loads(raw)
    if (type(record) is not dict or _canonical(record) != raw
        or set(record) != {"schema"} | {label + "_" + key for key in FILES for label in ("old", "new")}
        or record["schema"] != "h454-paired-systemd-journal-v1"):
        raise RebindDenied()
    snapshots = {}
    for key in FILES:
        old = _read(fd, "old-" + key, owner=trusted_uid)
        new = _read(fd, "new-" + key, owner=trusted_uid)
        if _digest(old) != record["old_" + key] or _digest(new) != record["new_" + key]:
            raise RebindDenied()
        snapshots[key] = (old, new)
    return snapshots


def switch(directories: dict[str, Path], journal: Path, *, trusted_uid: int) -> None:
    """Switch vetted files once while the host service stays stopped."""
    fd = None
    try:
        if type(directories) is not dict or set(directories) != set(FILES):
            raise RebindDenied()
        fd = _directory(journal, trusted_uid)
        snapshots = _load(fd, trusted_uid)
        if any(_target(directories[k], FILES[k], trusted_uid) != snapshots[k][0] for k in FILES):
            raise RebindDenied()
        _create(fd, "started", b"STARTED\n")
        os.fsync(fd)
        for key, name in FILES.items():
            replace_trusted_file(directories[key], name, expected=snapshots[key][0],
                                 replacement=snapshots[key][1], trusted_uid=trusted_uid)
        _create(fd, "complete", b"COMPLETE\n")
        os.fsync(fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def recover(directories: dict[str, Path], journal: Path, *, trusted_uid: int) -> None:
    """Restore only known old/new file versions; never reload systemd."""
    fd = None
    try:
        if type(directories) is not dict or set(directories) != set(FILES):
            raise RebindDenied()
        fd = _directory(journal, trusted_uid)
        snapshots = _load(fd, trusted_uid)
        current = {key: _target(directories[key], name, trusted_uid) for key, name in FILES.items()}
        if any(current[k] not in snapshots[k] for k in FILES):
            raise RebindDenied()
        for key, name in reversed(tuple(FILES.items())):
            if current[key] != snapshots[key][0]:
                replace_trusted_file(directories[key], name, expected=current[key],
                                     replacement=snapshots[key][0], trusted_uid=trusted_uid)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if fd is not None:
            os.close(fd)
