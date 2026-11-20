"""Offline, journaled paired state transition; not a host installer or service gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from scripts.h454_native_paired_rebind import (
    RebindDenied, _canonical, rebind, recover_device, replace_frozen_state,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _directory(path: Path, trusted_uid: int) -> int:
    if not path.is_absolute() or trusted_uid != os.geteuid():
        raise RebindDenied()
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if st.st_uid != trusted_uid or stat.S_IMODE(st.st_mode) != 0o700:
        os.close(fd)
        raise RebindDenied()
    return fd


def _read(fd: int, name: str, *, owner: int | None = None) -> bytes:
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        st = os.fstat(child)
        raw = os.read(child, 8193)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) != 0o600 or not 0 < len(raw) <= 8192
            or len(raw) != st.st_size or (owner is not None and st.st_uid != owner)):
            raise RebindDenied()
        return raw
    finally:
        os.close(child)


def _distinct(first: int, second: int) -> None:
    a, b = os.fstat(first), os.fstat(second)
    if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
        raise RebindDenied()


def _no_pending(state_fd: int) -> None:
    for name in (".h454-paired-manifest.json.pending", ".h454-paired-device.json.pending"):
        try:
            os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise RebindDenied()


def _create(fd: int, name: str, data: bytes) -> None:
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd)
    try:
        view = memoryview(data)
        while view:
            n = os.write(child, view)
            if n <= 0:
                raise RebindDenied()
            view = view[n:]
        os.fchmod(child, 0o600)
        os.fsync(child)
    finally:
        os.close(child)


def prepare(state: Path, journal: Path, *, trusted_uid: int,
            old_release: str, new_release: str, bundle_sha256: str) -> None:
    """Seal recovery metadata before modifying state; never back up the bearer.

    The host operator must independently pin every ancestor, stop the service,
    exclude service-UID processes, freeze state under root, and hold its lock.
    An incomplete journal is retained and must never authorize a switch.
    """
    state_fd = journal_fd = None
    try:
        state_fd = _directory(state, trusted_uid)
        journal_fd = _directory(journal, trusted_uid)
        _distinct(state_fd, journal_fd)
        _no_pending(state_fd)
        if os.listdir(journal_fd):
            raise RebindDenied()
        manifest = _read(state_fd, "manifest.json")
        device = _read(state_fd, "device.json")
        new = rebind(manifest, device, old_release=old_release,
                     new_release=new_release, bundle_sha256=bundle_sha256)
        record = _canonical({
            "schema": "h454-paired-state-journal-v1", "old_release": old_release,
            "new_release": new_release, "old_manifest_sha256": _digest(manifest),
            "new_manifest_sha256": _digest(new.manifest),
            "old_device_sha256": _digest(device), "new_device_sha256": _digest(new.device),
        })
        _create(journal_fd, "old-manifest.json", manifest)
        _create(journal_fd, "new-manifest.json", new.manifest)
        _create(journal_fd, "journal.json", record)
        os.fsync(journal_fd)
        _create(journal_fd, "prepared", b"PREPARED\n")
        os.fsync(journal_fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if journal_fd is not None:
            os.close(journal_fd)


def _load(journal_fd: int, trusted_uid: int) -> tuple[dict, bytes, bytes]:
    if set(os.listdir(journal_fd)) - {
        "old-manifest.json", "new-manifest.json", "journal.json",
        "prepared", "started", "complete",
    }:
        raise RebindDenied()
    if _read(journal_fd, "prepared", owner=trusted_uid) != b"PREPARED\n":
        raise RebindDenied()
    raw = _read(journal_fd, "journal.json", owner=trusted_uid)
    record = json.loads(raw)
    if (type(record) is not dict or raw != _canonical(record) or set(record) != {
        "schema", "old_release", "new_release", "old_manifest_sha256",
        "new_manifest_sha256", "old_device_sha256", "new_device_sha256",
    } or record["schema"] != "h454-paired-state-journal-v1"):
        raise RebindDenied()
    old = _read(journal_fd, "old-manifest.json", owner=trusted_uid)
    new = _read(journal_fd, "new-manifest.json", owner=trusted_uid)
    if _digest(old) != record["old_manifest_sha256"] or _digest(new) != record["new_manifest_sha256"]:
        raise RebindDenied()
    return record, old, new


def switch(state: Path, journal: Path, *, trusted_uid: int) -> None:
    """Switch only an unchanged frozen pair; caller keeps the service disabled."""
    state_fd = journal_fd = None
    try:
        state_fd = _directory(state, trusted_uid)
        journal_fd = _directory(journal, trusted_uid)
        _distinct(state_fd, journal_fd)
        _no_pending(state_fd)
        record, old, new = _load(journal_fd, trusted_uid)
        manifest, device = _read(state_fd, "manifest.json"), _read(state_fd, "device.json")
        if manifest != old or _digest(device) != record["old_device_sha256"]:
            raise RebindDenied()
        candidate = rebind(old, device, old_release=record["old_release"],
                           new_release=record["new_release"],
                           bundle_sha256=json.loads(new)["artifact_sha256"])
        if candidate.manifest != new or _digest(candidate.device) != record["new_device_sha256"]:
            raise RebindDenied()
        _create(journal_fd, "started", b"STARTED\n")
        os.fsync(journal_fd)
        replace_frozen_state(state, "manifest.json", expected=old,
                             replacement=new, trusted_uid=trusted_uid)
        replace_frozen_state(state, "device.json", expected=device,
                             replacement=candidate.device, trusted_uid=trusted_uid)
        _create(journal_fd, "complete", b"COMPLETE\n")
        os.fsync(journal_fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if journal_fd is not None:
            os.close(journal_fd)


def recover(state: Path, journal: Path, *, trusted_uid: int) -> None:
    """Restore a known old pair from either side of an interrupted switch."""
    state_fd = journal_fd = None
    try:
        state_fd = _directory(state, trusted_uid)
        journal_fd = _directory(journal, trusted_uid)
        _distinct(state_fd, journal_fd)
        _no_pending(state_fd)
        record, old, new = _load(journal_fd, trusted_uid)
        manifest, device = _read(state_fd, "manifest.json"), _read(state_fd, "device.json")
        if manifest not in (old, new) or _digest(device) not in (
            record["old_device_sha256"], record["new_device_sha256"]
        ):
            raise RebindDenied()
        restored = recover_device(device, old, new, old_release=record["old_release"],
                                  new_release=record["new_release"])
        if _digest(restored) != record["old_device_sha256"]:
            raise RebindDenied()
        if manifest != old:
            replace_frozen_state(state, "manifest.json", expected=manifest,
                                 replacement=old, trusted_uid=trusted_uid)
        if device != restored:
            replace_frozen_state(state, "device.json", expected=device,
                                 replacement=restored, trusted_uid=trusted_uid)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if journal_fd is not None:
            os.close(journal_fd)
