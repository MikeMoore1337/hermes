"""H809: opt-in bounded Engineering Control refresh within the existing QA tick.

This module introduces no timer, subprocess, persistent agent, credentials or
model calls. It only requests public metadata for fixed approved sources and
saves the pre-existing strictly sanitized Engineering Inbox feed.

The production QA watcher must opt in explicitly; its original CI/Observe
checks run first and remain authoritative. A failure here never upgrades them.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import os
from pathlib import Path
import re
import signal
import stat
import threading
from typing import Callable

try:
    import fcntl  # POSIX-only file locking; automated watcher runs on Linux.
except ImportError:  # Windows imports remain supported for offline QA.
    fcntl = None

from qa_advisor.engineering_feed import EngineeringFeedRefused, save
from qa_advisor.engineering_once import collect
from qa_advisor.engineering_public import PublicGithub, SourceUnavailable
from qa_advisor.signal_store import DIR, _dir

# These are reviewed public sources, not dynamic Issue/README instructions.
REPOSITORY = "MikeMoore1337/hermes"
UPSTREAM = "NousResearch/hermes-agent"
# The same public lockfile shipped in the pinned Hermes owner checkout.
# This is NOT the user's original Windows repository or a private registry.
LOCKFILE = Path("/opt/hermes-control-center/current/control_center/frontend/package-lock.json")
RUNTIME = "22.0.0"  # CI Node 22 toolchain target, not measured host Node.
PACKAGES = ("react",)
MAX_AUTO_SECONDS = 38
AUTO_TICK_SECONDS = 15 * 60
AUTO_EVERY_TICKS = 3
AUTO_COOLDOWN_SECONDS = AUTO_TICK_SECONDS * AUTO_EVERY_TICKS
# One tiny root-owned lease in the existing QA StateDirectory; not a new DB.
AUTO_BUDGET_FILE = "engineering-auto-attempt"
MAX_AUTO_STATE_BYTES = 32
MAX_AUTO_GITHUB_GET = 26
AUTO_PR_SAMPLE = 3


class AutoUnavailable(ValueError):
    """Only constant diagnostic codes, never external source payloads."""


class BudgetedGithub:
    """One fixed public API request limit shared across the four modules."""

    def __init__(self, *, reader=None):
        self._reader = reader if reader is not None else PublicGithub()
        self.calls = 0

    def get(self, path: str):
        if self.calls >= MAX_AUTO_GITHUB_GET:
            raise SourceUnavailable("automatic_github_budget_exceeded")
        self.calls += 1
        return self._reader.get(path)


@contextmanager
def deadline(seconds: int = MAX_AUTO_SECONDS):
    """Cap end-to-end collection with SIGALRM. Requires Linux main thread.

    Never replace an alarm already owned by another host component.
    """
    if (os.name != "posix" or threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "setitimer")):
        raise AutoUnavailable("posix_main_thread_required")
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining or interval:
        raise AutoUnavailable("existing_alarm_refused")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise AutoUnavailable("engineering_deadline_exceeded")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@contextmanager
def reserve_budget(instant: datetime, *, directory: Path = DIR):
    """Reserve a durable 45-minute public API budget BEFORE any network GET.

    The same root-owned QA StateDirectory already exists for CI and Inbox.
    A persistent attempt marker (not just a successful report) prevents manual
    reruns, crashes and overlapping service starts from bypassing the quota.
    Corrupt state, unsafe files, unavailable locking and clock rollback fail
    closed. No new timer, external credential or source-of-truth database.
    """
    if os.name != "posix" or fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        raise AutoUnavailable("posix_budget_required")
    try:
        _dir(directory)
        fd = os.open(
            directory / AUTO_BUDGET_FILE,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
        )
    except (OSError, ValueError):
        raise AutoUnavailable("engineering_budget_unavailable") from None
    try:
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or info.st_size > MAX_AUTO_STATE_BYTES):
                raise AutoUnavailable("engineering_budget_unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                permitted = False
            else:
                raw = os.read(fd, MAX_AUTO_STATE_BYTES + 1)
                if raw and re.fullmatch(rb"[0-9]{1,15}\\n", raw) is None:
                    raise AutoUnavailable("engineering_budget_unsafe")
                current = int(instant.timestamp())
                last = int(raw[:-1]) if raw else None
                permitted = (last is None or
                             current - last >= AUTO_COOLDOWN_SECONDS)
                if permitted:
                    # Commit an attempt before contacting GitHub. A failed or
                    # interrupted sweep still consumes its bounded allowance.
                    payload = f"{current}\\n".encode("ascii")
                    os.lseek(fd, 0, os.SEEK_SET)
                    if os.write(fd, payload) != len(payload):
                        raise AutoUnavailable("engineering_budget_write_failed")
                    os.ftruncate(fd, len(payload))
                    os.fsync(fd)
                    parent = os.open(
                        directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    )
                    try:
                        os.fsync(parent)
                    finally:
                        os.close(parent)
        except AutoUnavailable:
            raise
        except (OSError, ValueError):
            raise AutoUnavailable("engineering_budget_unavailable") from None
        # Keep the lock until this sweep finishes or fails. Other invocations
        # cannot run concurrently and will not consume an extra public budget.
        yield permitted
    finally:
        os.close(fd)


def refresh(
    *, now: datetime | None = None,
    collector: Callable[..., dict] = collect,
    saver: Callable[[dict], str] = save,
    time_limit: Callable[[], object] = deadline,
    lockfile: Path = LOCKFILE,
    reader_factory: Callable[[], object] = BudgetedGithub,
    budget: Callable[[datetime], object] = reserve_budget,
) -> str:
    """One best-effort bounded cycle, returning a fixed, public-safe status."""
    instant = now if now is not None else datetime.now(UTC)
    if type(instant) is not datetime or instant.tzinfo is None:
        raise AutoUnavailable("clock_invalid")
    # The 15m QA schedule is independent from the 45m public API cooldown.
    # Check the root-only persistent reservation even after restart or failure.
    with time_limit():
        with budget(instant) as permitted:
            if not permitted:
                return "SKIPPED_COOLDOWN"
            report = collector(
                repo=REPOSITORY,
                source_repo=UPSTREAM,
                lockfile=lockfile,
                runtime=RUNTIME,
                packages=list(PACKAGES),
                now=instant,
                github_client=reader_factory(),
                max_open_prs=AUTO_PR_SAMPLE,
            )
            # The hard 38s deadline covers saving as well as collection.
            # Only a sanitized envelope enters the existing root-owned Inbox.
            result = saver(report)
    if result != "STORED_SANITIZED_ENGINEERING":
        raise AutoUnavailable("sanitized_save_unavailable")
    available = sum(row["status"] != "NOT_AVAILABLE"
                    for row in report["sources"].values())
    return "STORED" if available == 4 else "PARTIAL"
