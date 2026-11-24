"""Durable at-most-once READ request IDs on a pre-provisioned private file.

The caller opens the ledger before applying Landlock and retains only the
already-open file descriptor. The containing directory must be installed by
the service operator; this module never creates or repairs a missing ledger.
"""
from __future__ import annotations

try:
    import fcntl
except ImportError:  # Only Linux workers may open a replay journal.
    fcntl = None
import hashlib
import os
from pathlib import Path
import re
import stat

_MAGIC = b'H454-READ-REPLAY-v1\n'
_RECORD = 32
_MAX_RECORDS = 50_000
_REQUEST_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')


class ReplayDenied(ValueError):
    """Fail closed without returning paths or request identifiers."""


class LinuxReadReplay:
    """Durably append a request digest before executing its read operation."""

    def __init__(self, path: Path):
        self._fd = -1
        try:
            if fcntl is None or not isinstance(path, Path) or not path.is_absolute():
                raise ValueError()
            parent = path.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise ValueError()
            flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
            self._fd = os.open(path, flags)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                self._check_file()
                self._records()
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except Exception:
            self.close()
            raise ReplayDenied('linux_replay_denied') from None

    @property
    def fd(self) -> int:
        return self._fd

    def _check_file(self) -> None:
        info = os.fstat(self._fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size < len(_MAGIC)
                or info.st_size > len(_MAGIC) + _RECORD * _MAX_RECORDS
                or (info.st_size - len(_MAGIC)) % _RECORD):
            raise ReplayDenied('linux_replay_denied')

    def _records(self) -> set[bytes]:
        self._check_file()
        size = os.fstat(self._fd).st_size
        raw = bytearray()
        while len(raw) < size:
            chunk = os.pread(self._fd, min(65536, size - len(raw)), len(raw))
            if not chunk:
                raise ReplayDenied('linux_replay_denied')
            raw.extend(chunk)
        if not raw.startswith(_MAGIC):
            raise ReplayDenied('linux_replay_denied')
        records = [bytes(raw[i:i + _RECORD]) for i in range(len(_MAGIC), size, _RECORD)]
        if len(records) != len(set(records)):
            raise ReplayDenied('linux_replay_denied')
        return set(records)

    def claim(self, request_id: str) -> bool:
        try:
            if type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None:
                raise ValueError()
            digest = hashlib.sha256(request_id.encode('ascii')).digest()
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                records = self._records()
                if digest in records:
                    return False
                if len(records) >= _MAX_RECORDS:
                    raise ValueError()
                if os.write(self._fd, digest) != _RECORD:
                    raise ValueError()
                os.fsync(self._fd)
                self._check_file()
                return True
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except Exception:
            raise ReplayDenied('linux_replay_denied') from None

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> 'LinuxReadReplay':
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
