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
import signal
import threading
from typing import Callable

from qa_advisor.engineering_feed import EngineeringFeedRefused, save
from qa_advisor.engineering_once import collect

# These are reviewed public sources, not dynamic Issue/README instructions.
REPOSITORY = "MikeMoore1337/hermes"
UPSTREAM = "NousResearch/hermes-agent"
# The same public lockfile shipped in the pinned Hermes owner checkout.
# This is NOT the user's original Windows repository or a private registry.
LOCKFILE = Path("/opt/hermes-agent-owner/control_center/frontend/package-lock.json")
RUNTIME = "22.0.0"  # CI Node 22 toolchain target, not measured host Node.
PACKAGES = ("react",)
MAX_AUTO_SECONDS = 38


class AutoUnavailable(ValueError):
    """Only constant diagnostic codes, never external source payloads."""


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


def refresh(
    *, now: datetime | None = None,
    collector: Callable[..., dict] = collect,
    saver: Callable[[dict], str] = save,
    time_limit: Callable[[], object] = deadline,
    lockfile: Path = LOCKFILE,
) -> str:
    """One best-effort bounded cycle, returning a fixed, public-safe status."""
    instant = now if now is not None else datetime.now(UTC)
    if type(instant) is not datetime or instant.tzinfo is None:
        raise AutoUnavailable("clock_invalid")
    with time_limit():
        report = collector(
            repo=REPOSITORY,
            source_repo=UPSTREAM,
            lockfile=lockfile,
            runtime=RUNTIME,
            packages=list(PACKAGES),
            now=instant,
        )
    # Never store raw per-PR data. The existing writer checks all enums,
    # authority flags and timestamps before atomic root-owned replacement.
    result = saver(report)
    if result != "STORED_SANITIZED_ENGINEERING":
        raise AutoUnavailable("sanitized_save_unavailable")
    available = sum(row["status"] != "NOT_AVAILABLE"
                    for row in report["sources"].values())
    return "STORED" if available == 4 else "PARTIAL"
