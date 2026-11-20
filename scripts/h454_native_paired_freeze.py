"""Journal a private state-directory ownership freeze; no service operations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from scripts.h454_native_paired_rebind import RebindDenied, _canonical
from scripts.h454_native_paired_state import _create, _directory, _distinct, _read


def freeze(state: Path, journal: Path, *, trusted_uid: int,
           service_uid: int, service_gid: int) -> None:
    """Record original ownership and freeze one directory under the trusted UID.

    Before calling, an owner-host operator must pin ancestors, hold an
    exclusive lock, prove the service stopped, and exclude service-UID
    processes. A partial journal or freeze remains for explicit recovery.
    """
    state_fd = journal_fd = None
    try:
        if (type(trusted_uid) is not int or trusted_uid != os.geteuid()
            or type(service_uid) is not int
            or type(service_gid) is not int or service_uid <= 0 or service_gid <= 0
            or service_uid == trusted_uid or not state.is_absolute()):
            raise RebindDenied()
        journal_fd = _directory(journal, trusted_uid)
        state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        _distinct(state_fd, journal_fd)
        before = os.fstat(state_fd)
        if (os.listdir(journal_fd) or (before.st_uid, before.st_gid) != (service_uid, service_gid)
            or stat.S_IMODE(before.st_mode) != 0o700):
            raise RebindDenied()
        record = _canonical({"schema": "h454-paired-freeze-v1", "uid": service_uid,
                             "gid": service_gid, "dev": before.st_dev, "ino": before.st_ino})
        _create(journal_fd, "directory.json", record)
        os.fsync(journal_fd)
        os.fchown(state_fd, trusted_uid, os.getegid())
        os.fsync(state_fd)
        after = os.fstat(state_fd)
        if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or after.st_uid != trusted_uid or stat.S_IMODE(after.st_mode) != 0o700):
            raise RebindDenied()
        _create(journal_fd, "frozen", b"FROZEN\n")
        os.fsync(journal_fd)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if journal_fd is not None:
            os.close(journal_fd)


def restore_owner(state: Path, journal: Path, *, trusted_uid: int,
                  service_uid: int, service_gid: int) -> None:
    """Restore ownership after independent full-transition verification.

    The host operator must establish that state, trust, units and staged
    files are consistent before calling this function. It does not do so.
    """
    state_fd = journal_fd = None
    try:
        if type(trusted_uid) is not int or not state.is_absolute():
            raise RebindDenied()
        journal_fd = _directory(journal, trusted_uid)
        names = set(os.listdir(journal_fd))
        if names - {"directory.json", "frozen"}:
            raise RebindDenied()
        if "frozen" in names and _read(journal_fd, "frozen", owner=trusted_uid) != b"FROZEN\n":
            raise RebindDenied()
        raw = _read(journal_fd, "directory.json", owner=trusted_uid)
        record = json.loads(raw)
        if (type(record) is not dict or _canonical(record) != raw
            or set(record) != {"schema", "uid", "gid", "dev", "ino"}
            or record["schema"] != "h454-paired-freeze-v1"
            or (record["uid"], record["gid"]) != (service_uid, service_gid)
            or any(type(record[k]) is not int for k in ("uid", "gid", "dev", "ino"))
            or type(service_uid) is not int or type(service_gid) is not int
            or service_uid <= 0 or service_gid <= 0 or service_uid == trusted_uid):
            raise RebindDenied()
        state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        _distinct(state_fd, journal_fd)
        current = os.fstat(state_fd)
        if ((current.st_dev, current.st_ino) != (record["dev"], record["ino"])
            or current.st_uid != trusted_uid or stat.S_IMODE(current.st_mode) != 0o700):
            raise RebindDenied()
        os.fchown(state_fd, service_uid, service_gid)
        os.fsync(state_fd)
        after = os.fstat(state_fd)
        if ((after.st_uid, after.st_gid) != (service_uid, service_gid)
            or stat.S_IMODE(after.st_mode) != 0o700):
            raise RebindDenied()
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if journal_fd is not None:
            os.close(journal_fd)
