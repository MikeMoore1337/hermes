"""Paired native upgrade coordinator; no CLI, staging or service start."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from contextlib import contextmanager
import fcntl
import pwd
import re
import socket
import stat
import subprocess

from device_fabric.native_private_tls import load_private_relay
from scripts import h454_native_paired_freeze as freeze
from scripts import h454_native_paired_host as host
from scripts import h454_native_paired_staging as staging
from scripts import h454_native_paired_state as state_tx
from scripts import h454_native_paired_systemd as systemd_tx
from scripts.h454_native_paired_rebind import RebindDenied, _canonical
from scripts.h454_native_private_versioned_upgrade import checked_file, create_file, owned_directory

STATE = Path("/var/lib/hermes-commander-native")
BASE = Path("/opt/hermes-commander-native")
UNIT_DIRS = {"trust": BASE / "trust", "preflight": Path("/etc/systemd/system"),
             "active": Path("/etc/systemd/system")}
LOCK = Path("/run/lock/h454-native-private-version-upgrade.lock")
PHASES = frozenset({"RECHECK", "RECEIPT", "UNIT_JOURNAL", "FREEZE", "STATE_JOURNAL",
                    "STATE_SWITCH", "UNIT_SWITCH", "RELOAD", "VERIFY", "THAW", "RECEIPT_FINISH"})


class ApplyHold(RebindDenied):
    def __init__(self, phase: str):
        self.phase = phase if phase in PHASES else "RECHECK"
        super().__init__("native_paired_apply_hold")


@contextmanager
def host_lock():
    """Coordinate with the existing native upgrader and enrollment writer."""
    lock_fd = state_fd = None
    try:
        if os.geteuid() != 0 or socket.gethostname() != "vps1777112993":
            raise RebindDenied()
        owned_directory(LOCK.parent.parent)
        owned_directory(STATE.parent)
        parent = LOCK.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) != 0o1777):
            raise RebindDenied()
        lock_fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        lock = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0 or lock.st_nlink != 1
            or stat.S_IMODE(lock.st_mode) != 0o600 or lock.st_size != 0):
            raise RebindDenied()
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = LOCK.lstat()
        if (current.st_dev, current.st_ino) != (lock.st_dev, lock.st_ino):
            raise RebindDenied()
        state_fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        state = os.fstat(state_fd)
        identity = pwd.getpwnam("hermes-commander-native")
        if (state.st_uid not in (0, identity.pw_uid) or stat.S_IMODE(state.st_mode) != 0o700):
            raise RebindDenied()
        fcntl.flock(state_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = STATE.lstat()
        if (current.st_dev, current.st_ino) != (state.st_dev, state.st_ino):
            raise RebindDenied()
        yield
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if lock_fd is not None:
            os.close(lock_fd)


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


def _mark(receipt: Path, name: str, content: bytes) -> None:
    create_file(receipt / name, content, 0o600)
    fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _record(receipt: Path) -> dict:
    """Read only pinned, nonsecret recovery metadata from the root receipt."""
    owned_directory(receipt, mode=0o700)
    raw = checked_file(receipt / "plan.json", 8192, private=True, modes={0o600})
    data = json.loads(raw)
    keys = {"schema", "target", "old_release", "new_release", "bundle_sha256", "uid", "gid",
            "old_manifest_sha256", "new_manifest_sha256", "old_device_sha256", "new_device_sha256",
            "old_trust_sha256", "new_trust_sha256", "old_active_sha256", "new_active_sha256",
            "old_preflight_sha256", "new_preflight_sha256"}
    if (type(data) is not dict or _canonical(data) != raw or set(data) != keys
        or data["schema"] != "h454-paired-upgrade-v1" or data["target"] != "hermes-vps"
        or data["old_release"] != host.OLD or data["new_release"] != host.NEW
        or data["bundle_sha256"] != host.BUNDLE_SHA
        or data["old_manifest_sha256"] != host.MANIFEST_SHA
        or data["old_trust_sha256"] != host.TRUST_SHA
        or data["old_active_sha256"] != host.UNIT_SHA["hermes-commander-native.service"]
        or data["old_preflight_sha256"] != host.UNIT_SHA["hermes-commander-native-preflight.service"]):
        raise RebindDenied()
    identity = pwd.getpwnam("hermes-commander-native")
    if (type(data["uid"]) is not int or type(data["gid"]) is not int
        or (data["uid"], data["gid"]) != (identity.pw_uid, identity.pw_gid)
        or identity.pw_uid <= 0 or identity.pw_gid <= 0
        or identity.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")
        or any(type(data[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", data[key]) is None
               for key in keys if key.endswith("_sha256"))):
        raise RebindDenied()
    return data


def _inert(uid: int) -> None:
    """Deny active, activating, enabled or running native units during recovery."""
    for name in host.UNIT_SHA:
        status = subprocess.run(["/usr/bin/systemctl", "show", name, "--no-pager",
                                 "--property=ActiveState,SubState,MainPID,UnitFileState"],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=5, check=False)
        if status.returncode != 0 or len(status.stdout) > 1024:
            raise RebindDenied()
        lines = status.stdout.decode("ascii").splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line)
        if (len(lines) != 4 or set(values) != {"ActiveState", "SubState", "MainPID", "UnitFileState"}
            or values["MainPID"] != "0" or values["SubState"] not in {"dead", "failed"}
            or values["ActiveState"] not in {"inactive", "failed"}
            or values["UnitFileState"] != ("static" if "preflight" in name else "disabled")):
            raise RebindDenied()
    _no_service_process(uid)


def _old_pair_matches(record: dict) -> None:
    for name, key in (("manifest.json", "old_manifest_sha256"), ("device.json", "old_device_sha256")):
        raw = checked_file(STATE / name, 8192, owner=record["uid"], private=True, modes={0o600})
        if _sha(raw) != record[key] or (STATE / name).lstat().st_gid != record["gid"]:
            raise RebindDenied()


def recover_frozen() -> None:
    """Recover an interrupted frozen switch under the caller-held host lock.

    Any unrecognized file, pending stage or malformed journal remains in
    place and keeps the directory frozen. A completed install can be recovered
    only after a separately initiated and journaled rollback freeze.
    """
    try:
        if os.geteuid() != 0 or socket.gethostname() != "vps1777112993":
            raise RebindDenied()
        receipt = BASE / "receipts" / ("h454-paired-upgrade-" + host.NEW)
        record = _record(receipt)
        success = receipt / "success"
        completed = success.exists() or success.is_symlink()
        if completed and checked_file(success, 128, private=True, modes={0o600}) != b"INSTALLED_DISABLED_PAIRED\n":
            raise RebindDenied()
        rollback_freeze = receipt / "rollback-freeze"
        rollback_started = rollback_freeze.exists() or rollback_freeze.is_symlink()
        if completed and not rollback_started:
            raise RebindDenied()
        freeze_journal = rollback_freeze if rollback_started else receipt / "freeze"
        state = STATE.lstat()
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0
            or stat.S_IMODE(state.st_mode) != 0o700):
            raise RebindDenied()
        _inert(record["uid"])
        systemd_tx.recover(UNIT_DIRS, receipt / "systemd", trusted_uid=0)
        pair_journal = receipt / "state"
        if (pair_journal / "prepared").exists() or (pair_journal / "prepared").is_symlink():
            state_tx.recover(STATE, pair_journal, trusted_uid=0)
        else:
            fd = state_tx._directory(STATE, 0)
            try:
                state_tx._no_pending(fd)
            finally:
                os.close(fd)
        _old_pair_matches(record)
        _reload()
        trust = checked_file(BASE / "trust/private-relay.json", 2048, modes={0o444})
        ca = checked_file(BASE / "trust/ca.crt", 8192, modes={0o444})
        if _sha(trust) != host.TRUST_SHA or _sha(ca) != host.CA_SHA:
            raise RebindDenied()
        relay = load_private_relay("hermes-vps", host.OLD)
        for name, expected in host.UNIT_SHA.items():
            key = "preflight" if "preflight" in name else "active"
            unit = checked_file(UNIT_DIRS[key] / name, 16384, modes={0o644})
            if _sha(unit) != expected:
                raise RebindDenied()
            host._check_unit(name, relay.relay_ipv4)
        _no_service_process(record["uid"])
        freeze.restore_owner(STATE, freeze_journal, trusted_uid=0,
                             service_uid=record["uid"], service_gid=record["gid"])
        _mark(receipt, "rollback-success" if completed else "recovered", b"OLD_DISABLED_PAIRED\n")
    except Exception:
        raise RebindDenied("native_paired_recovery_hold") from None


def rollback_disabled() -> None:
    """Roll back a verified, thawed install, including a missing final receipt."""
    try:
        if os.geteuid() != 0 or socket.gethostname() != "vps1777112993":
            raise RebindDenied()
        receipt = BASE / "receipts" / ("h454-paired-upgrade-" + host.NEW)
        record = _record(receipt)
        success = receipt / "success"
        if ((success.exists() or success.is_symlink())
            and checked_file(success, 128, private=True, modes={0o600}) != b"INSTALLED_DISABLED_PAIRED\n"):
            raise RebindDenied()
        for name in ("rollback-success", "recovered"):
            if (receipt / name).exists() or (receipt / name).is_symlink():
                raise RebindDenied()
        current = STATE.lstat()
        if (not stat.S_ISDIR(current.st_mode) or (current.st_uid, current.st_gid) !=
            (record["uid"], record["gid"]) or stat.S_IMODE(current.st_mode) != 0o700):
            raise RebindDenied()
        _inert(record["uid"])
        systemd_tx.verify_new(UNIT_DIRS, receipt / "systemd", trusted_uid=0)
        relay = load_private_relay("hermes-vps", host.NEW)
        for name in host.UNIT_SHA:
            host._check_unit(name, relay.relay_ipv4)
        for name, key in (("manifest.json", "new_manifest_sha256"), ("device.json", "new_device_sha256")):
            raw = checked_file(STATE / name, 8192, owner=record["uid"], private=True, modes={0o600})
            if _sha(raw) != record[key] or (STATE / name).lstat().st_gid != record["gid"]:
                raise RebindDenied()
        freeze_journal = receipt / "rollback-freeze"
        freeze_journal.mkdir(mode=0o700)
        freeze_journal.chmod(0o700)
        fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _inert(record["uid"])
        freeze.freeze(STATE, freeze_journal, trusted_uid=0,
                      service_uid=record["uid"], service_gid=record["gid"])
        state_tx.verify_new(STATE, receipt / "state", trusted_uid=0)
        recover_frozen()
    except Exception:
        raise RebindDenied("native_paired_rollback_hold") from None


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
        _mark(receipt, "success", b"INSTALLED_DISABLED_PAIRED\n")
    except Exception:
        raise ApplyHold(phase) from None


def operate(mode: str) -> str:
    """Run one coordinated operation; a trusted host launcher is still required."""
    if mode not in ("install-off", "recover-off", "rollback-off"):
        raise RebindDenied()
    with host_lock():
        if mode == "install-off":
            apply_staged(staging.stage())
            return "INSTALLED_DISABLED_PAIRED"
        if mode == "recover-off":
            recover_frozen()
        else:
            rollback_disabled()
        return "OLD_DISABLED_PAIRED"
