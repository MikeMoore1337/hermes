"""#455 owner-side, sanitized BRC snapshot publisher. No MCP or OAuth here.

A separately authorized owner-scoped collector must supply BOTH live MCP
list_devices and list_workspaces payloads. Never synthesize online status
from a database last_seen timestamp, or reuse a ChatGPT OAuth token.
This module has no scheduler, service, network or CLI side effects.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import time

from control_center.brc_snapshot import (
    DEFAULT_OUTPUT, MAX_SNAPSHOT_BYTES, SnapshotRejected, normalize,
)


def publish_snapshot(devices: object, catalog: object, *,
                     path: Path = DEFAULT_OUTPUT, now_ms: int | None = None) -> dict:
    """Validate raw owner MCP observations, then atomically store public fields.

    Caller must already have permissions to the pre-created trusted directory.
    Never create/rename arbitrary directories or change permissions on an
    existing observation. An invalid input leaves an earlier snapshot intact.
    """
    if now_ms is None:
        now_ms = time.time_ns() // 1_000_000
    observation = normalize(devices, catalog, now_ms=now_ms)
    payload = (json.dumps(observation, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise SnapshotRejected("observation_too_large")
    if os.geteuid() == 0:
        raise SnapshotRejected("nonroot_publisher_required")
    target = Path(path)
    parent = target.parent
    if target.name != "status.json":
        raise SnapshotRejected("unexpected_snapshot_name")
    try:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise SnapshotRejected("untrusted_snapshot_directory")
        try:
            existing = target.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode) or
            existing.st_uid != os.geteuid() or
            existing.st_mode & 0o022
        ):
            raise SnapshotRejected("untrusted_existing_snapshot")
    except OSError as exc:
        raise SnapshotRejected("snapshot_directory_unavailable") from exc

    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".brc-snapshot-", dir=parent
        )
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o640)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        # The process identity and trust of the directory are fixed at
        # deployment; deny replacing a symlink from a concurrent actor.
        if target.is_symlink():
            raise SnapshotRejected("untrusted_existing_snapshot")
        os.replace(temporary, target)
        temporary = None
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise SnapshotRejected("snapshot_publish_failed") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return observation
