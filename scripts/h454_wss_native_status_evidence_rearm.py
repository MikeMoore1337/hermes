#!/usr/bin/env python3
"""H454: archive one verified restored WSS attempt without touching Docker.

Plan is read-only. Rearm requires a separate exact owner-root TTY consent.
Never restart BRC/WSS, delete the original native3 history or auto-retry
cutover. Preserve all prior status-WSS evidence under a private archive.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/var/lib/hermes-h454-wss-sidecar")
PREVIOUS_OPERATOR = Path("/root/h454_wss_native_status_sidecar_cutover_901.py")
PREVIOUS_BLOB = "ab4b07083955934f49994646b9bf634823620165"
CANDIDATE = Path("/root/h454-wss-native-status-8303.mjs")
ARCHIVE = ROOT / "native-status-failed-attempt-20261118-1237"
ARCHIVED_BACKUP = ARCHIVE / "evidence"
ARCHIVED_ORIGINAL = ARCHIVED_BACKUP / "native-status-original-pins.json"
RECEIPT = "native-status-rearm-receipt.json"
COPY = "native-status-original-pins.json"
SCHEMA = "h454-wss-native-status-first-failure-archive-v1"
PENDING_NAMES = (
    "prepare.pending", "reconcile.pending", "native3-pair.pending",
    "native-status-upgrade.pending", "stage1-pins.tmp",
    ".h454-native-status-proxy.tmp", ".h454-native-status-pending.tmp",
)


class RearmHold(ValueError):
    """A fixed reason only; never print original VPS secrets or file bytes."""


def gate(ok, reason):
    if not ok:
        raise RearmHold(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        raise RearmHold("ARCHIVE_PATH_UNREADABLE") from None
    return False


def sync_dir(path: Path) -> None:
    # A directory descriptor cannot be fdopen()'d as a regular file.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def root_operator():
    gate(os.geteuid() == 0, "ROOT_REQUIRED")
    info = PREVIOUS_OPERATOR.lstat()
    gate(stat.S_ISREG(info.st_mode) and info.st_uid == 0
         and info.st_gid == 0 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600
         and 0 < info.st_size <= 100000, "PREVIOUS_OPERATOR_METADATA")
    with os.fdopen(
        os.open(PREVIOUS_OPERATOR, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb"
    ) as reader:
        actual = os.fstat(reader.fileno())
        raw = reader.read(100001)
        after = os.fstat(reader.fileno())
    gate((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
         (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
         and len(raw) == info.st_size and blob(raw) == PREVIOUS_BLOB,
         "PREVIOUS_OPERATOR_PIN_CHANGED")
    spec = importlib.util.spec_from_file_location("h454_restored_wss_first_operator",
                                                   PREVIOUS_OPERATOR)
    gate(spec is not None and spec.loader is not None, "PREVIOUS_OPERATOR_NOT_LOADABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verified_preflight()
    return module


def inspect_locked(tx, preflight, current: bytes) -> dict:
    """Caller holds the existing original relay and old pins locks."""
    tx.stage1.protected(ROOT, 0o700, directory=True)
    gate(absent(ARCHIVE), "ARCHIVE_SLOT_OCCUPIED")
    for name in PENDING_NAMES:
        gate(absent(ROOT / name), "UNFINISHED_WSS_TRANSACTION")
    gate(tx.current_name(tx.CHECKPOINT) is None and
         tx.current_name(tx.CHECKPOINT_NEW) is None,
         "WSS_STATUS_CHECKPOINT_PRESENT")
    saved = tx.read_backup()
    old = tx.checked_file(ROOT / "proxy.mjs", mode=0o444)
    candidate = preflight.read_fixed(CANDIDATE, uid={0}, modes={0o600})
    wss = tx.stage1.load_existing_wss()
    live = wss._pins(current)
    gate(current == saved["old-pins.json"] and
         old == saved["old-proxy.mjs"],
         "ORIGINAL_PAIR_NOT_RESTORED")
    preflight.check_proxy_source(old, candidate, live["proxy_sha256"])
    gate(candidate == saved["candidate-proxy.mjs"] and
         live["relay_id"] == tx.LIVE_RELAY_ID and
         live["sidecar_id"] == tx.LIVE_SIDECAR_ID and
         live["relay_image"] == tx.LIVE_RELAY_IMAGE and
         live["sidecar_image"] == tx.stage1.LEGACY_IMAGE and
         saved["relay-id.txt"] == (tx.LIVE_RELAY_ID + "\n").encode("ascii") and
         saved["sidecar-id.txt"] == (tx.LIVE_SIDECAR_ID + "\n").encode("ascii"),
         "ORIGINAL_PAIR_IDENTITY_DRIFT")
    gate(preflight.verify_completed_native3_history(wss, live) is True,
         "HISTORICAL_NATIVE3_STATE_CHANGED")
    tx.verify_live(wss, live, tx.LIVE_RELAY_ID)
    preflight.native_release()
    previous = tx.current_name(tx.stage1.PROXY)
    gate(previous is not None and
         previous["Id"] == tx.LIVE_SIDECAR_ID and
         previous["Image"] == tx.stage1.LEGACY_IMAGE and
         previous["State"]["Running"] is True,
         "ORIGINAL_SIDECAR_CHANGED")
    return {
        "original_pins_sha256": digest(current),
        "old_proxy_sha256": digest(old),
        "candidate_proxy_sha256": digest(candidate),
        "original_relay_id": tx.LIVE_RELAY_ID,
        "original_sidecar_id": tx.LIVE_SIDECAR_ID,
        "original_native3_verified": True,
        "cutover_authorized": False,
        "archive_path": str(ARCHIVE),
    }


def plan() -> dict:
    tx = root_operator()
    preflight = tx.verified_preflight()
    with tx.stage1.legacy.lock():
        with tx.stage1.locked_pins() as raw:
            return inspect_locked(tx, preflight, raw)


def confirm(proof: dict) -> None:
    gate(sys.stdin.isatty() and sys.stdout.isatty() and os.geteuid() == 0,
         "OWNER_ROOT_TTY_REQUIRED")
    exact = ("H454 ARCHIVE RESTORED WSS ONLY " + proof["original_pins_sha256"]
             + " " + proof["original_sidecar_id"])
    with open("/dev/tty", "r", encoding="ascii") as reader, \
         open("/dev/tty", "w", encoding="ascii") as screen:
        screen.write("Archive the restored WSS attempt, preserving all evidence. "
                     "No new cutover or native service start.\n"
                     "Confirm exactly:\n" + exact + "\n> ")
        screen.flush()
        gate(reader.readline(300).strip() == exact, "OWNER_DECLINED")


def archive_evidence(tx, proof: dict) -> None:
    """Archive the failed attempt, keeping all original file bytes/inodes.

    An interrupted archive leaves at least one root-private copy and HALTS.
    It is never automatically retried/cleaned up when ambiguous.
    """
    gate(absent(ARCHIVE) and absent(tx.BACKUP / RECEIPT) and
         absent(tx.BACKUP / COPY), "ARCHIVE_ALREADY_STARTED")
    gate(tx.checked_file(tx.ORIGINAL, mode=0o600) ==
         tx.checked_file(tx.BACKUP / "old-pins.json", mode=0o600),
         "ORIGINAL_PINS_BACKUP_DRIFT")
    marker = tx.canonical({
        "schema": SCHEMA,
        "status": "FIRST_CUTOVER_FAILED_ORIGINAL_RESTORED",
        "old_pins_sha256": proof["original_pins_sha256"],
        "old_proxy_sha256": proof["old_proxy_sha256"],
        "candidate_proxy_sha256": proof["candidate_proxy_sha256"],
        "old_relay_id": proof["original_relay_id"],
        "old_sidecar_id": proof["original_sidecar_id"],
        "cutover_authorized": False,
        "native_service_started": False,
    })
    # A unique root-only parent is created before touching original evidence.
    ARCHIVE.mkdir(mode=0o700)
    tx.stage1.protected(ARCHIVE, 0o700, directory=True)
    sync_dir(ROOT)
    tx.stage1.write_once(tx.BACKUP / RECEIPT, marker)
    gate(tx.checked_file(tx.BACKUP / RECEIPT, mode=0o600) == marker,
         "ARCHIVE_RECEIPT_DRIFT")
    sync_dir(tx.BACKUP)

    # Hardlink first: both names refer to the SAME original 0600 inode.
    # If an operation fails, we preserve original bytes and STOP.
    os.link(tx.ORIGINAL, tx.BACKUP / COPY, follow_symlinks=False)
    orig_stat = tx.ORIGINAL.lstat()
    linked_stat = (tx.BACKUP / COPY).lstat()
    # rearm() has already enforced original-root EUID=0. Compare to the
    # executing owner here to permit identical non-root synthetic fixtures.
    gate(stat.S_ISREG(orig_stat.st_mode) and orig_stat.st_uid == os.geteuid()
         and stat.S_IMODE(orig_stat.st_mode) == 0o600
         and (orig_stat.st_dev, orig_stat.st_ino) ==
             (linked_stat.st_dev, linked_stat.st_ino)
         and orig_stat.st_nlink == linked_stat.st_nlink == 2,
         "ARCHIVED_ORIGINAL_LINK_DRIFT")
    sync_dir(tx.BACKUP)

    gate(absent(ARCHIVED_BACKUP), "ARCHIVED_BACKUP_COLLISION")
    os.rename(tx.BACKUP, ARCHIVED_BACKUP)
    sync_dir(ROOT)
    sync_dir(ARCHIVE)
    # The current original link is removed only AFTER the archive rename
    # and inode identity were independently re-read.
    archived_stat = ARCHIVED_ORIGINAL.lstat()
    live_stat = tx.ORIGINAL.lstat()
    gate((archived_stat.st_dev, archived_stat.st_ino) ==
         (live_stat.st_dev, live_stat.st_ino)
         and archived_stat.st_nlink == live_stat.st_nlink == 2,
         "POST_ARCHIVE_INODE_DRIFT")
    tx.ORIGINAL.unlink()
    sync_dir(ROOT)
    gate(tx.checked_file(ARCHIVED_ORIGINAL, mode=0o600) ==
         tx.checked_file(ARCHIVED_BACKUP / "old-pins.json", mode=0o600),
         "ARCHIVED_RESTORE_PINS_DRIFT")


def rearm() -> dict:
    reviewed = plan()
    confirm(reviewed)
    tx = root_operator()
    preflight = tx.verified_preflight()
    with tx.stage1.legacy.lock():
        with tx.stage1.locked_pins() as raw:
            confirmed = inspect_locked(tx, preflight, raw)
            gate(confirmed == reviewed, "PLAN_CHANGED_AFTER_CONFIRMATION")
            archive_evidence(tx, confirmed)
    # This is only a NO-MUTATION new-plan check; no Docker is changed.
    report = preflight.plan(CANDIDATE)
    gate(report["status"] == "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS" and
         report["brc_wss_mutation"] is False and
         report["cutover_approval"] == "NOT_GRANTED",
         "NEW_PLAN_NOT_READY")
    return {
        "status": "H454_WSS_RESTORED_EVIDENCE_ARCHIVED_NO_CUTOVER",
        "archived_evidence": True,
        "native_service_started": False,
        "cutover_authorized": False,
        "original_brc_wss_unchanged": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "rearm"))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        gate((args.action == "rearm") == args.execute,
             "EXPLICIT_EXECUTE_REQUIRED")
        if args.execute:
            report = rearm()
        else:
            proof = plan()
            report = {
                "status": "H454_WSS_RESTORED_EVIDENCE_PLAN_PASS",
                "original_pins_sha256": proof["original_pins_sha256"],
                "original_native3_verified": True,
                "cutover_authorized": False,
                "live_mutation": False,
            }
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, RearmHold) else "ORIGINAL_HOST_HOLD"
        gate_reason = reason if re.fullmatch("[A-Z_]{1,72}", reason) else "ORIGINAL_HOST_HOLD"
        print(json.dumps({"status": "H454_WSS_REARM_HOLD",
                          "reason": gate_reason, "cutover_authorized": False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
