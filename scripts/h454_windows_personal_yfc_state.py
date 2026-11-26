"""Provision private state for an already paired personal YFC device.

This does not enroll a device, install a release, or start a worker.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time

from device_fabric import native_private_tls as private_tls
from device_fabric import windows_personal_commander_bundle as bundle
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_commander_status as status
from device_fabric.personal_replay import PersonalReplay
from device_fabric.windows_personal_yfc_psec import APP_NAME, _real_directory
from scripts.h454_windows_personal_state import _create_private_directory
from scripts.h454_windows_personal_worker import current_sid, load_ca


class YfcStateDenied(ValueError):
    """No local paths, bearer tokens, or platform errors leave this boundary."""


def _write_once(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def persist_new(paired, *, release_sha: str, ca: bytes,
                expected_manifest: bytes, expected_sha256: str) -> None:
    """Seal one current owner grant only after verifying the selected release.

    Interrupted provisioning is preserved and cannot be silently overwritten.
    """
    try:
        app_data = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(app_data):
            raise ValueError()
        base = Path(app_data) / APP_NAME
        release, private = base / "release", base / "worker-private"
        _real_directory(base)
        _real_directory(release)
        if private.exists() or private.is_symlink():
            raise ValueError()
        if type(ca) is not bytes or load_ca(hashlib.sha256(ca).hexdigest()) != ca:
            raise ValueError()
        bundle.verify(release, expected_manifest, expected_sha256)
        sid = current_sid()
        relay = private_tls.PrivateRelay("windows", release_sha, private_tls.WINDOWS_LOOPBACK, ca)
        if status.bearer_state(relay, device_id=paired.device_id, bearer=paired.token) is not True:
            raise ValueError()
        raw = config.prepare_config(paired, owner_sid=sid, release_sha=release_sha,
            ca=ca, bundle_sha256=expected_sha256, now=int(time.time()), profile="yfc-dev")
        _create_private_directory(private, sid)
        _write_once(private / "release-manifest.json", expected_manifest)
        PersonalReplay(private, create=True)
        # Device config is written last so a partially provisioned directory
        # cannot be mistaken for a fully provisioned device.
        _write_once(private / "device.json", raw)
    except Exception:
        raise YfcStateDenied("yfc_state_denied") from None
