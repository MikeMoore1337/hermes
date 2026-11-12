#!/usr/bin/env python3
"""H454: owner-root, evidence-preserving re-arm after a verified paired rollback.

The read-only plan refuses any live pair drift, pending operation, or occupied
checkpoint. A separate exact root-TTY approval is required to archive a
verified previous-transaction marker; no Docker, BRC, WSS or device changes
are made. Re-arm NEVER authorizes a new cutover or waives release/CVE gates.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from scripts import h454_native3_paired_preflight as pair

ROOT = pair.stage1.PIN_ROOT
RETAINED = pair.ORIGINAL_PINS
EVIDENCE = ROOT / "native3-rearm-evidence"
MAX_BYTES = 16_384
SCHEMA = "h454-native3-restored-rearm-v1"


class RearmDenied(ValueError):
    """Fixed rejection: do not leak owner paths, tokens or pin contents."""


def deny(reason: str) -> None:
    raise RearmDenied(reason)


@dataclass(frozen=True)
class Verified:
    source_sha: str
    candidate_sha: str
    digest: str
    pinned: bytes
    relay_id: str
    proxy_id: str
    runtime_image: str
    baseline_devices: int


def _root_required() -> bool:
    return os.geteuid() == 0


def _absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        deny("RECOVERY_PATH_UNVERIFIABLE")
    return False


def _private(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        mode = 0o700 if directory else 0o600
        if (not kind(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != mode
            or (not directory and (info.st_nlink != 1
                                    or not 0 < info.st_size <= MAX_BYTES))):
            deny("RECOVERY_PROTECTED_PATH_UNSAFE")
        return info
    except (OSError, ValueError):
        raise RearmDenied("RECOVERY_PROTECTED_PATH_UNSAFE") from None


def _read_private(path: Path) -> bytes:
    info = _private(path, directory=False)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        actual = os.fstat(fd)
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            != (actual.st_dev, actual.st_ino, actual.st_size,
                actual.st_mtime_ns)):
            deny("RECOVERY_PROTECTED_PATH_CHANGED")
        data = os.read(fd, MAX_BYTES + 1)
        after = os.fstat(fd)
        if (len(data) != info.st_size
            or (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns) !=
               (actual.st_dev, actual.st_ino, actual.st_size,
                actual.st_mtime_ns)):
            deny("RECOVERY_PROTECTED_PATH_CHANGED")
        return data
    except OSError:
        raise RearmDenied("RECOVERY_PROTECTED_PATH_UNREADABLE") from None
    finally:
        if fd is not None:
            os.close(fd)


def _sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_once(path: Path, content: bytes) -> None:
    if not content or len(content) > MAX_BYTES:
        deny("RECOVERY_EVIDENCE_SIZE_INVALID")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
    )
    with os.fdopen(fd, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def _attest_locked(*, source_sha: str, candidate_sha: str, bundle: Path,
                   image: str, archive_sha: str) -> Verified:
    """The caller holds the exclusive, root-owned existing relay lock."""
    try:
        pair.legacy.check_files()
        pair.stage1.protected(ROOT, 0o700, directory=True)
        pair.stage1.protected(pair.stage1.PINS, 0o600)
        pair.stage1.protected(RETAINED, 0o600)
        if not all(_absent(path) for path in
                   (pair.stage1.PENDING, pair.PAIR_PENDING)):
            deny("RECOVERY_PENDING_TRANSACTION")
        original = _read_private(RETAINED)
        expected = pair.candidate.admit(bundle, image, archive_sha,
                                        candidate_sha)
        if (expected.get("status") != "PREFLIGHT_PASS"
            or expected.get("bundle_verified") is not True
            or expected.get("changes_performed") is not False
            or expected.get("deployment_approved") is not False
            or expected.get("current_image") != pair.stage1.FORK_IMAGE):
            deny("RECOVERY_CANDIDATE_NOT_ADMITTED")

        wss = pair.stage1.load_existing_wss()
        relay, proxy = pair.verify_pair(wss)
        pair.check_free_checkpoints()
        with pair.stage1.locked_pins() as live:
            if live != original or _read_private(RETAINED) != live:
                deny("RECOVERY_RETAINED_PINS_DIFFER")
            pins = wss._pins(live)
            if (pins.get("relay_id") != relay["Id"]
                or pins.get("sidecar_id") != proxy["Id"]
                or pins.get("relay_image") != relay["Image"]
                or pins.get("sidecar_image") != proxy["Image"]):
                deny("RECOVERY_LIVE_PAIR_DRIFT")
        baseline = pair.legacy.devices()
        if type(baseline) is not int or not 1 <= baseline <= 25:
            deny("RECOVERY_BASELINE_UNAVAILABLE")
        return Verified(
            source_sha, candidate_sha, hashlib.sha256(original).hexdigest(),
            original, relay["Id"], proxy["Id"],
            expected["candidate_image"], baseline,
        )
    except RearmDenied:
        raise
    except Exception:
        raise RearmDenied("RECOVERY_ATTESTATION_UNAVAILABLE") from None


def plan(*, source_sha: str, candidate_sha: str, bundle: Path,
         image: str, archive_sha: str) -> Verified:
    if not _root_required():
        deny("RECOVERY_ROOT_REQUIRED")
    pair.verify_installed_source(source_sha)
    with pair.legacy.lock():
        return _attest_locked(
            source_sha=source_sha, candidate_sha=candidate_sha,
            bundle=bundle, image=image, archive_sha=archive_sha,
        )


def _owner_confirmation(proof: Verified) -> None:
    if (not _root_required() or not sys.stdin.isatty()
        or not sys.stdout.isatty()):
        deny("RECOVERY_INTERACTIVE_ROOT_TTY_REQUIRED")
    exact = ("H454 REARM RESTORED PAIR " + proof.source_sha
             + " " + proof.digest)
    try:
        with open("/dev/tty", "r", encoding="ascii") as reader, \
             open("/dev/tty", "w", encoding="ascii") as writer:
            writer.write("Archive the previous rollback proof and re-arm "
                         "the gate ONLY (no BRC/WSS cutover).\n"
                         "Confirm exactly:\n" + exact + "\n> ")
            writer.flush()
            if reader.readline(256).strip() != exact:
                deny("RECOVERY_OWNER_CONFIRMATION_DENIED")
    except (OSError, UnicodeError):
        raise RearmDenied("RECOVERY_OWNER_CONFIRMATION_UNAVAILABLE") from None


def _archive_restored(proof: Verified) -> None:
    """Preserve original bytes and private receipt before removing the gate.

    No overwrite, no 'force' or automatic cleanup of an interrupted attempt.
    Existing evidence files indicate a possible interrupted re-arm and STOP.
    """
    _private(ROOT, directory=True)
    if _read_private(RETAINED) != proof.pinned:
        deny("RECOVERY_RETAINED_PINS_CHANGED")
    if not _absent(EVIDENCE):
        _private(EVIDENCE, directory=True)
    else:
        EVIDENCE.mkdir(mode=0o700)
        _sync(ROOT)
    _private(EVIDENCE, directory=True)

    filename = "native3-original-pins-" + proof.digest + ".json"
    archived = EVIDENCE / filename
    receipt = EVIDENCE / ("native3-rearm-" + proof.digest + ".receipt.json")
    if not _absent(archived) or not _absent(receipt):
        deny("RECOVERY_ALREADY_ARCHIVED_OR_INTERRUPTED")

    _write_once(archived, proof.pinned)
    _sync(EVIDENCE)
    if _read_private(archived) != proof.pinned:
        deny("RECOVERY_ARCHIVE_VERIFICATION_FAILED")

    evidence = {
        "schema": SCHEMA,
        "status": "PREVIOUS_ROLLBACK_EVIDENCE_RETAINED",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "owner_source_sha": proof.source_sha,
        "candidate_source_sha": proof.candidate_sha,
        "original_pins_sha256": proof.digest,
        "retained_file": filename,
        "original_relay_id": proof.relay_id,
        "original_proxy_id": proof.proxy_id,
        "candidate_runtime_image": proof.runtime_image,
        "baseline_devices": proof.baseline_devices,
        "cutover_authorized": False,
        "native_service_activation_authorized": False,
    }
    payload = json.dumps(evidence, sort_keys=True,
                         separators=(",", ":")).encode("ascii")
    _write_once(receipt, payload)
    _sync(EVIDENCE)
    if _read_private(receipt) != payload or _read_private(archived) != proof.pinned:
        deny("RECOVERY_RECEIPT_VERIFICATION_FAILED")
    if _read_private(RETAINED) != proof.pinned:
        deny("RECOVERY_RETAINED_PINS_CHANGED")
    RETAINED.unlink()
    _sync(ROOT)


def rearm(*, source_sha: str, candidate_sha: str, bundle: Path,
          image: str, archive_sha: str) -> Verified:
    inspected = plan(
        source_sha=source_sha, candidate_sha=candidate_sha,
        bundle=bundle, image=image, archive_sha=archive_sha,
    )
    _owner_confirmation(inspected)
    # Re-check all host evidence under the lock AFTER human confirmation.
    pair.verify_installed_source(source_sha)
    with pair.legacy.lock():
        confirmed = _attest_locked(
            source_sha=source_sha, candidate_sha=candidate_sha,
            bundle=bundle, image=image, archive_sha=archive_sha,
        )
        if confirmed != inspected:
            deny("RECOVERY_STATE_CHANGED_DURING_CONFIRMATION")
        with pair.stage1.locked_pins() as live:
            if live != confirmed.pinned:
                deny("RECOVERY_LIVE_PINS_CHANGED")
            _archive_restored(confirmed)
    return confirmed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "rearm"))
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--archive-sha", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        if (args.action == "rearm") != args.execute:
            deny("RECOVERY_EXPLICIT_EXECUTE_REQUIRED")
        kwargs = dict(source_sha=args.release_sha,
                      candidate_sha=args.candidate_sha,
                      bundle=args.bundle_dir, image=args.image,
                      archive_sha=args.archive_sha)
        proof = rearm(**kwargs) if args.execute else plan(**kwargs)
        result = {
            "status": ("RESTORED_EVIDENCE_ARCHIVED_REARMED_NO_CUTOVER"
                       if args.execute else "RESTORED_BASELINE_VERIFIED_NO_MUTATIONS"),
            "source_sha": proof.source_sha,
            "candidate_sha": proof.candidate_sha,
            "retained_pins_sha256": proof.digest,
            "rollback_evidence_preserved": args.execute,
            "live_pair_matched": True,
            "cutover_authorized": False,
            "native_service_activated": False,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, RearmDenied) else "RECOVERY_UNAVAILABLE"
        print(json.dumps({"status": "REFUSED", "reason": reason,
                          "cutover_authorized": False},
                         sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
