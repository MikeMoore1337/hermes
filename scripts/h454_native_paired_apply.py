"""Paired native upgrade coordinator; no CLI, staging or service start."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from device_fabric.native_private_tls import load_private_relay
from scripts import h454_native_paired_freeze as freeze
from scripts import h454_native_paired_host as host
from scripts import h454_native_paired_state as state_tx
from scripts import h454_native_paired_systemd as systemd_tx
from scripts.h454_native_paired_rebind import RebindDenied, _canonical
from scripts.h454_native_private_versioned_upgrade import checked_file, create_file

STATE = Path("/var/lib/hermes-commander-native")
BASE = Path("/opt/hermes-commander-native")
UNIT_DIRS = {"trust": BASE / "trust", "preflight": Path("/etc/systemd/system"),
             "active": Path("/etc/systemd/system")}
PHASES = frozenset({"RECHECK", "RECEIPT", "UNIT_JOURNAL", "FREEZE", "STATE_JOURNAL",
                    "STATE_SWITCH", "UNIT_SWITCH", "RELOAD", "VERIFY", "THAW", "RECEIPT_FINISH"})


class ApplyHold(RebindDenied):
    def __init__(self, phase: str):
        self.phase = phase if phase in PHASES else "RECHECK"
        super().__init__("native_paired_apply_hold")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _receipt(plan: host.HostPlan) -> Path:
    """Create one private, exclusive journal root; store fingerprints, not bearer."""
    root = BASE / "receipts" / ("h454-paired-upgrade-" + host.NEW)
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for name in ("freeze", "state", "systemd"):
        (root / name).mkdir(mode=0o700)
        (root / name).chmod(0o700)
    metadata = {
        "schema": "h454-paired-upgrade-v1", "target": "hermes-vps",
        "old_release": host.OLD, "new_release": host.NEW, "bundle_sha256": host.BUNDLE_SHA,
        "old_manifest_sha256": _sha(plan.old_manifest),
        "new_manifest_sha256": _sha(plan.transition.manifest),
        "old_device_sha256": _sha(plan.old_device),
        "new_device_sha256": _sha(plan.transition.device),
        "old_trust_sha256": _sha(plan.old_trust), "new_trust_sha256": _sha(plan.transition.trust),
        "old_active_sha256": _sha(plan.old_units["hermes-commander-native.service"]),
        "new_active_sha256": _sha(plan.transition.active_unit),
        "old_preflight_sha256": _sha(plan.old_units["hermes-commander-native-preflight.service"]),
        "new_preflight_sha256": _sha(plan.transition.preflight_unit),
        "uid": plan.uid, "gid": plan.gid,
    }
    create_file(root / "plan.json", _canonical(metadata), 0o600)
    for directory in (root, root.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return root


def _reload() -> None:
    result = subprocess.run(["/usr/bin/systemctl", "daemon-reload"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=15, check=False)
    if result.returncode != 0:
        raise RebindDenied()


def _no_service_process(uid: int) -> None:
    result = subprocess.run(["/usr/bin/pgrep", "-u", str(uid)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=5, check=False)
    if result.returncode != 1:
        raise RebindDenied()


def _stopped(plan: host.HostPlan) -> None:
    relay = json.loads(plan.old_trust)["relay_ipv4"]
    for name in host.UNIT_SHA:
        host._check_unit(name, relay)
    _no_service_process(plan.uid)


def _frozen_matches(plan: host.HostPlan) -> None:
    for name, expected in (("manifest.json", plan.old_manifest), ("device.json", plan.old_device)):
        if checked_file(STATE / name, 8192, owner=plan.uid, private=True, modes={0o600}) != expected:
            raise RebindDenied()
        if (STATE / name).lstat().st_gid != plan.gid:
            raise RebindDenied()


def _finish(receipt: Path) -> None:
    create_file(receipt / "success", b"INSTALLED_DISABLED_PAIRED\n", 0o600)
    fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def apply_staged(plan: host.HostPlan) -> None:
    """Switch a staged paired release under a caller-held root lifecycle lock.

    On any error the receipt and any frozen state are retained; never retry,
    unfreeze or start a service without a separately verified recovery.
    """
    phase = "RECHECK"
    try:
        if type(plan) is not host.HostPlan or host.inspect(staged=True) != plan:
            raise RebindDenied()
        phase = "RECEIPT"
        receipt = _receipt(plan)
        phase = "UNIT_JOURNAL"
        systemd_tx.prepare(receipt / "systemd", {
            "trust": (plan.old_trust, plan.transition.trust),
            "active": (plan.old_units["hermes-commander-native.service"], plan.transition.active_unit),
            "preflight": (plan.old_units["hermes-commander-native-preflight.service"], plan.transition.preflight_unit),
        }, trusted_uid=0)
        phase = "FREEZE"
        _stopped(plan)
        freeze.freeze(STATE, receipt / "freeze", trusted_uid=0,
                      service_uid=plan.uid, service_gid=plan.gid)
        phase = "STATE_JOURNAL"
        _frozen_matches(plan)
        state_tx.prepare(STATE, receipt / "state", trusted_uid=0, old_release=host.OLD,
                         new_release=host.NEW, bundle_sha256=host.BUNDLE_SHA)
        phase = "STATE_SWITCH"
        _stopped(plan)
        state_tx.switch(STATE, receipt / "state", trusted_uid=0)
        phase = "UNIT_SWITCH"
        _stopped(plan)
        systemd_tx.switch(UNIT_DIRS, receipt / "systemd", trusted_uid=0)
        phase = "RELOAD"
        _reload()
        phase = "VERIFY"
        state_tx.verify_new(STATE, receipt / "state", trusted_uid=0)
        systemd_tx.verify_new(UNIT_DIRS, receipt / "systemd", trusted_uid=0)
        relay = load_private_relay("hermes-vps", host.NEW)
        for name in host.UNIT_SHA:
            host._check_unit(name, relay.relay_ipv4)
        _no_service_process(plan.uid)
        phase = "THAW"
        freeze.restore_owner(STATE, receipt / "freeze", trusted_uid=0,
                             service_uid=plan.uid, service_gid=plan.gid)
        phase = "RECEIPT_FINISH"
        _finish(receipt)
    except Exception:
        raise ApplyHold(phase) from None
