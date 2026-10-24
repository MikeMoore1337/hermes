"""#455: local, credential-free, non-root relay -> Control Center observer bridge.

No network, OAuth, shell, Docker or devices. Runs only under service UID with
the preexisting Hermes Control Center group. Copies strictly validated public
snapshot metadata from the existing private relay state directory.
"""
from __future__ import annotations
import datetime as dt
import grp
import json
import os
from pathlib import Path
import stat
import tempfile

from control_center.brc_snapshot import SnapshotRejected, read_snapshot, MAX_SNAPSHOT_BYTES

SOURCE = Path("/var/lib/hermes-brc-relay/hermes-brc-observation.json")
MARKER = Path("/var/lib/hermes-brc-relay/.hermes-brc-observer-enable")
TARGET = Path("/var/lib/hermes-brc-observer/status.json")
CONTROL_GROUP = "hermes-control"


def _reject(message: str):
    raise SnapshotRejected(message)


def _trusted_directory(path: Path, uid: int, gid: int | None, mode: int):
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotRejected("observer_directory_unavailable") from exc
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid or (gid is not None and info.st_gid != gid)
        or stat.S_IMODE(info.st_mode) != mode):
        _reject("observer_directory_untrusted")


def _trusted_file(path: Path, uid: int, *, expected_mode: int, max_bytes: int):
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotRejected("observer_source_unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != expected_mode
        or info.st_size > max_bytes):
        _reject("observer_file_untrusted")


def bridge_once(*, source: Path = SOURCE, marker: Path = MARKER,
                target: Path = TARGET, shared_gid: int | None = None,
                now: dt.datetime | None = None) -> dict:
    uid = os.geteuid()
    if uid == 0:
        _reject("observer_root_forbidden")
    if shared_gid is None:
        shared_gid = grp.getgrnam(CONTROL_GROUP).gr_gid
    if os.getegid() != shared_gid:
        _reject("observer_unexpected_primary_group")
    if source.parent != marker.parent or source.name != "hermes-brc-observation.json" \
            or marker.name != ".hermes-brc-observer-enable" or target.name != "status.json":
        _reject("observer_unexpected_paths")
    _trusted_directory(source.parent, uid, None, 0o700)
    _trusted_file(marker, uid, expected_mode=0o600, max_bytes=8)
    if marker.read_bytes() != b"enabled\n":
        _reject("observer_not_enabled")
    _trusted_file(source, uid, expected_mode=0o640, max_bytes=MAX_SNAPSHOT_BYTES)
    # read_snapshot rejects stale/future/oversized/foreign schemas and private data.
    snapshot = read_snapshot(source, now=now)
    serialized = (json.dumps(snapshot, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")) + "\n").encode("utf-8")
    if len(serialized) > MAX_SNAPSHOT_BYTES:
        _reject("observer_output_oversize")
    _trusted_directory(target.parent, uid, shared_gid, 0o750)
    try:
        existing = target.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode) or existing.st_uid != uid
        or existing.st_gid != shared_gid or stat.S_IMODE(existing.st_mode) != 0o640
    ):
        _reject("observer_existing_target_untrusted")
    name = None
    try:
        fd, name = tempfile.mkstemp(prefix=".brc-status-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), uid, shared_gid)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink():
            _reject("observer_target_symlink")
        os.replace(name, target)
        name = None
        dir_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise SnapshotRejected("observer_publish_failed") from exc
    finally:
        if name is not None:
            try: os.unlink(name)
            except FileNotFoundError: pass
    return {"status": "PUBLISHED", "devices": len(snapshot["devices"]),
            "workspaces": len(snapshot["workspaces"]),
            "fresh_observation": True}


def main() -> int:
    try:
        result = bridge_once()
    except (SnapshotRejected, KeyError, OSError) as exc:
        # No untrusted paths/content or secret-bearing tool output in logs.
        print("H455_OBSERVER_BRIDGE=REFUSED")
        return 2
    print("H455_OBSERVER_BRIDGE=PASS")
    print("DEVICE_COUNT=" + str(result["devices"]))
    print("WORKSPACE_COUNT=" + str(result["workspaces"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
