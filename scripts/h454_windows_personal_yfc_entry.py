"""Entry point for a separately provisioned owner-scoped YFC device.

The caller must first authenticate the entry point and provision the fixed
release, DPAPI config and replay database. This file installs and pairs nothing.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from device_fabric import native_private_tls as private_tls
from device_fabric import windows_personal_commander_bundle as bundle
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_commander_status as status
from device_fabric.personal_replay import PersonalReplay
from device_fabric.windows_personal_job import attach_current_worker
from device_fabric.windows_personal_yfc_psec import APP_NAME, _real_directory
from device_fabric.windows_personal_yfc_runner import run
from scripts.h454_windows_personal_worker import current_sid, load_ca

REPARSE = 0x400
WHEEL = "websockets-17.2-py3-none-any.whl"


def _read_private(directory: Path, name: str, maximum: int) -> bytes:
    """Read only a bounded fixed file from a canonical, non-reparse directory."""
    try:
        if (not isinstance(directory, Path) or not directory.is_absolute()
            or name not in ("device.json", "release-manifest.json")
            or type(maximum) is not int or maximum <= 0):
            raise ValueError()
        _real_directory(directory)
        path = directory / name
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & REPARSE or not 0 < before.st_size <= maximum):
            raise ValueError()
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
        if (len(raw) != before.st_size or not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after.st_mode)
            or any(getattr(before, key) != getattr(opened, key) or
                   getattr(opened, key) != getattr(after, key) for key in keys)):
            raise ValueError()
        return raw
    except Exception:
        raise ValueError("yfc_entry_denied") from None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--run"] or os.name != "nt":
        return 2
    try:
        app_data = os.environ.get("LOCALAPPDATA", "")
        if not os.path.isabs(app_data):
            raise ValueError()
        base = Path(app_data) / APP_NAME
        private, release = base / "worker-private", base / "release"
        raw = _read_private(private, "device.json", config.MAX_CONFIG_BYTES)
        candidate = config.parse_config(raw)
        if candidate.profile != "yfc-dev":
            raise ValueError()
        expected = _read_private(private, "release-manifest.json", bundle.MAX_MANIFEST)
        ca = load_ca(candidate.ca_sha256)
        # Verify the complete release before importing the bundled dependency.
        bundle.verify(release, expected, candidate.bundle_sha256)
        wheel = release / "deps" / WHEEL
        if not wheel.is_file():
            raise ValueError()
        sys.path.insert(0, str(wheel))
        from websockets.sync.client import connect
        relay = private_tls.PrivateRelay("windows", candidate.release_sha,
                                         private_tls.WINDOWS_LOOPBACK, ca)
        connector = private_tls.private_websocket_connector(relay, connect)
        replay = PersonalReplay(private)
        def status_factory(device_id: str, bearer: str):
            return lambda: status.bearer_state(relay, device_id=device_id, bearer=bearer)
        # The process must be dedicated: closing its job terminates all members.
        attach_current_worker()
        while True:
            outcome = run(raw, ca=ca, expected_manifest=expected, current_sid=current_sid,
                connector=connector, status_factory=status_factory, claim_call=replay.claim,
                attach_job=lambda: None)
            if outcome != "reconnect_exhausted":
                return 0
            time.sleep(60)
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
