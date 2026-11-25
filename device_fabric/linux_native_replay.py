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
import threading

_MAGIC = b'H454-READ-REPLAY-v1\n'
_RECORD = 32
_MAX_BYTES = len(_MAGIC) + 16 * 1024 * 1024
_CHUNK = 64 * 1024
_REQUEST_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')


class ReplayDenied(ValueError):
    """Fail closed without returning paths or request identifiers."""


class LinuxReadReplay:
    """Durably append a request digest before executing its read operation."""

    def __init__(self, path: Path):
        self._fd = -1
        self._lock = threading.Lock()
        self._seen: set[bytes] = set()
        self._offset = len(_MAGIC)
        self._prefix = hashlib.sha256(_MAGIC)
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
                self._synchronize()
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except Exception:
            self.close()
            raise ReplayDenied('linux_replay_denied') from None

    @property
    def fd(self) -> int:
        return self._fd

    def _check_file(self) -> int:
        info = os.fstat(self._fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size < len(_MAGIC)
                or info.st_size > _MAX_BYTES
                or (info.st_size - len(_MAGIC)) % _RECORD):
            raise ReplayDenied('linux_replay_denied')
        return info.st_size

    def _synchronize(self) -> None:
        """Recheck the trusted prefix and ingest only newly appended records.

        The byte cap bounds memory and disk. Rehashing the prefix detects
        same-size modifications; the set detects duplicate log records. The
        caller holds the shared file lock for the complete check and append.
        """
        size = self._check_file()
        if size < self._offset:
            raise ReplayDenied('linux_replay_denied')
        checked = hashlib.sha256()
        position = 0
        while position < self._offset:
            length = min(_CHUNK, self._offset - position)
            data = os.pread(self._fd, length, position)
            if len(data) != length:
                raise ReplayDenied('linux_replay_denied')
            checked.update(data)
            position += length
        if checked.digest() != self._prefix.digest():
            raise ReplayDenied('linux_replay_denied')
        while self._offset < size:
            length = min(_CHUNK, size - self._offset)
            data = os.pread(self._fd, length, self._offset)
            if len(data) != length or length % _RECORD:
                raise ReplayDenied('linux_replay_denied')
            for index in range(0, length, _RECORD):
                item = data[index:index + _RECORD]
                if item in self._seen:
                    raise ReplayDenied('linux_replay_denied')
                self._seen.add(item)
            self._prefix.update(data)
            self._offset += length
        if self._check_file() != size:
            raise ReplayDenied('linux_replay_denied')

    def claim(self, request_id: str) -> bool:
        try:
            if type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None:
                raise ValueError()
            digest = hashlib.sha256(request_id.encode('ascii')).digest()
            with self._lock:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
                try:
                    self._synchronize()
                    if digest in self._seen:
                        return False
                    if self._offset + _RECORD > _MAX_BYTES:
                        raise ValueError()
                    if os.write(self._fd, digest) != _RECORD:
                        raise ValueError()
                    os.fsync(self._fd)
                    self._synchronize()
                    return True
                finally:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
        except Exception:
            raise ReplayDenied('linux_replay_denied') from None

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1

    def __enter__(self) -> 'LinuxReadReplay':
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
