"""Fail-closed NCBI pacing shared by manually started Hermes processes.

A fixed host file coordinates ESearch and ESummary. Minimum 400 ms between
requests. External applications on the same public IP are NOT covered.
"""
from __future__ import annotations

import fcntl
import os
import re
import stat
import time
from pathlib import Path
from typing import Callable

RATE_FILE = Path("/run/lock/hermes-ncbi-eutils.rate")
MIN_GAP_NS = 400_000_000


class NCBIRateGateError(ValueError):
    """Fixed sanitized error code without local paths or external data."""


def reserve_request(
    *,
    path: Path = RATE_FILE,
    clock_ns: Callable[[], int] = time.monotonic_ns,
) -> None:
    """Reserve a slot across Hermes processes or reject without I/O to NCBI.

    /run is a tmpfs: its state and monotonic clock reset together on reboot.
    No wait, retry or automatic removal on corruption or permission errors.
    """
    try:
        fd = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
    except OSError as exc:
        raise NCBIRateGateError("ncbi_rate_storage_unavailable") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise NCBIRateGateError("ncbi_rate_state_unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise NCBIRateGateError("ncbi_rate_lock_busy") from exc
        now = clock_ns()
        if type(now) is not int or now <= 0:
            raise NCBIRateGateError("ncbi_rate_clock_invalid")
        os.lseek(fd, 0, os.SEEK_SET)
        state = os.read(fd, 64)
        if state and re.fullmatch(rb"[1-9][0-9]{0,20}", state) is None:
            raise NCBIRateGateError("ncbi_rate_state_invalid")
        if state:
            last = int(state)
            if now < last:
                raise NCBIRateGateError("ncbi_rate_clock_invalid")
            if now - last < MIN_GAP_NS:
                raise NCBIRateGateError("ncbi_rate_limited")
        value = str(now).encode("ascii")
        os.lseek(fd, 0, os.SEEK_SET)
        if os.write(fd, value) != len(value):
            raise NCBIRateGateError("ncbi_rate_storage_unavailable")
        os.ftruncate(fd, len(value))
        os.fsync(fd)
    except OSError as exc:
        raise NCBIRateGateError("ncbi_rate_storage_unavailable") from exc
    finally:
        os.close(fd)
