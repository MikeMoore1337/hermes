"""Root-only automatic activation of owner-pre-signed H346 leaf certificates.

This never signs certificates or reads a CA private key. The one-time owner
batch, staged separately in a root-only directory, has a finite lifetime.
"""
from __future__ import annotations

import argparse
import datetime as dt
import grp
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat

from scripts.h15_presence_tls_preflight import PreflightError, check
from scripts.h15_presence_tls_rotation import (
    IDENTITY, RotationError, RotationPaths, SERVICE, TLS_HOME,
    _active_name, _exclusive, _file, _generation_name, _pending_name,
    _transaction, _trusted_expired_generation, _validate_layout, auto, stage,
)

ARCHIVE_NAME = "presigned-batch"
APPROVED_CA_PIN = "72e930d2ce5b3798237e1495ccfecf4300f303fb0f6b57f3accc9739b01d8ab0"
EXPECTED_SLOTS = ("primary",) + tuple(f"future-{i:02d}" for i in range(1, 14))


class BatchError(ValueError):
    pass


def _private_file(path: Path, *, uid: int, max_size: int = 65536) -> bytes:
    try:
        old = path.lstat()
        if (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1
                or old.st_uid != uid or stat.S_IMODE(old.st_mode) != 0o600
                or not 0 < old.st_size <= max_size):
            raise BatchError("BATCH_FILE_UNTRUSTED")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino, current.st_size) != (
                    old.st_dev, old.st_ino, old.st_size):
                raise BatchError("BATCH_FILE_CHANGED")
            data = os.read(fd, max_size + 1)
        finally:
            os.close(fd)
        if len(data) != old.st_size:
            raise BatchError("BATCH_FILE_CHANGED")
        return data
    except OSError as exc:
        raise BatchError("BATCH_FILE_UNAVAILABLE") from exc


def _ca_digest(pem: bytes) -> str:
    try:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))).hexdigest()
    except (ValueError, UnicodeError, ssl.SSLError) as exc:
        raise BatchError("INVALID_CA_PUBLIC_CERTIFICATE") from exc


def _der_digest(pem: bytes) -> str:
    try:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))).hexdigest()
    except (ValueError, UnicodeError, ssl.SSLError) as exc:
        raise BatchError("INVALID_LEAF_CERTIFICATE") from exc


def _manifest(paths: RotationPaths) -> tuple[Path, tuple[dict, ...]]:
    archive = paths.root / ARCHIVE_NAME
    try:
        meta = archive.lstat()
    except OSError as exc:
        raise BatchError("PRESIGNED_ARCHIVE_MISSING") from exc
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != paths.owner_uid
            or stat.S_IMODE(meta.st_mode) != 0o700):
        raise BatchError("PRESIGNED_ARCHIVE_UNTRUSTED")
    raw = _private_file(archive / "manifest.json", uid=paths.owner_uid, max_size=16384)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise BatchError("PRESIGNED_MANIFEST_INVALID") from exc
    if (not isinstance(data, dict) or set(data) != {"schema", "ca_der_sha256", "slots"}
            or data["schema"] != "hermes-h346-presigned-batch-v1"
            or data["ca_der_sha256"] != APPROVED_CA_PIN
            or _ca_digest(_file(paths.ca)) != APPROVED_CA_PIN):
        raise BatchError("PRESIGNED_CA_PIN_MISMATCH")
    slots = data["slots"]
    if (not isinstance(slots, list) or len(slots) != len(EXPECTED_SLOTS)
            or [s.get("slot") if isinstance(s, dict) else None for s in slots]
            != list(EXPECTED_SLOTS)):
        raise BatchError("PRESIGNED_SLOT_ORDER_UNTRUSTED")
    for slot in slots:
        if (set(slot) != {"slot", "der_sha256", "not_before", "not_after"}
                or type(slot["der_sha256"]) is not str
                or len(slot["der_sha256"]) != 64
                or any(ch not in "0123456789abcdef" for ch in slot["der_sha256"])):
            raise BatchError("PRESIGNED_SLOT_METADATA_UNTRUSTED")
        try:
            starts = dt.datetime.fromisoformat(slot["not_before"])
            ends = dt.datetime.fromisoformat(slot["not_after"])
            if starts.tzinfo is None or ends.tzinfo is None or ends - starts != dt.timedelta(days=30):
                raise BatchError("PRESIGNED_SLOT_INVALID_DATES")
        except (TypeError, ValueError) as exc:
            raise BatchError("PRESIGNED_SLOT_INVALID_DATES") from exc
    return archive, tuple(slots)


def process(paths: RotationPaths, *, gid: int, now: dt.datetime | None = None,
            restart=None, probe=None, dry_run: bool = False) -> str:
    """One lock spans candidate selection, staging, and the real core rotation.

    Do not blindly retry a candidate that was quarantined by a failed
    restart, probe or interrupted transaction.
    """
    at = now or dt.datetime.now(dt.timezone.utc)
    if at.tzinfo is None:
        raise BatchError("CURRENT_TIME_NAIVE")
    extra = {}
    if restart is not None:
        extra["restart"] = restart
    if probe is not None:
        extra["probe"] = probe
    with _exclusive(paths):
        _validate_layout(paths, gid=gid)
        if _transaction(paths, gid=gid) is not None:
            if dry_run:
                return "PRESIGNED_BATCH=RECOVERY_REQUIRED"
            return auto(paths, gid=gid, now=at, **extra)
        archive, slots = _manifest(paths)
        current = _active_name(paths, gid=gid)
        if current is None:
            raise BatchError("INITIAL_MIGRATION_REQUIRED")
        cert = paths.generations / current / "cert.pem"
        key = paths.generations / current / "key.pem"
        current_pin = _der_digest(_file(cert))
        positions = [idx for idx, item in enumerate(slots)
                     if item["der_sha256"] == current_pin]
        if len(positions) != 1:
            raise BatchError("ACTIVE_LEAF_NOT_IN_APPROVED_BATCH")
        idx = positions[0]
        try:
            check(paths.ca, cert, key, min_valid_days=3,
                  now=at, key_group_readable=True)
            return "PRESIGNED_BATCH=NOT_DUE"
        except PreflightError as exc:
            if (str(exc) != "CERTIFICATE_EXPIRING_TOO_SOON"
                    and not _trusted_expired_generation(paths, current, at=at)):
                raise BatchError("ACTIVE_LEAF_NOT_TRUSTED") from exc
        if idx + 1 >= len(slots):
            raise BatchError("PRESIGNED_BATCH_EXHAUSTED_OWNER_RENEWAL_REQUIRED")
        candidate = slots[idx + 1]
        leaf_path = archive / (candidate["slot"] + ".pem")
        key_path = archive / (candidate["slot"] + ".key")
        cert_bytes = _private_file(leaf_path, uid=paths.owner_uid)
        _private_file(key_path, uid=paths.owner_uid)
        if _der_digest(cert_bytes) != candidate["der_sha256"]:
            raise BatchError("PRESIGNED_CERTIFICATE_TAMPERED")
        target = _generation_name(cert_bytes)
        pending = _pending_name(paths, gid=gid)
        if pending is not None and pending != target:
            raise BatchError("PENDING_CANDIDATE_NOT_APPROVED")
        if pending is None and (paths.generations / target).exists():
            raise BatchError("FAILED_CANDIDATE_REQUIRES_OWNER_REVIEW")
        if dry_run:
            return "PRESIGNED_BATCH=WOULD_STAGE_" + candidate["slot"]
        if pending is None:
            staged = stage(paths, leaf=leaf_path, key=key_path, gid=gid, now=at)
            if staged != target:
                raise BatchError("STAGED_GENERATION_MISMATCH")
        return auto(paths, gid=gid, now=at, **extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("auto", "check"))
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise BatchError("ROOT_REQUIRED")
        gid = grp.getgrnam(IDENTITY).gr_gid
        paths = RotationPaths(TLS_HOME)
        print(process(paths, gid=gid, dry_run=args.mode == "check"))
        return 0
    except (BatchError, RotationError, PreflightError, OSError, TypeError, ValueError) as exc:
        print("PRESIGNED_BATCH=NO_GO")
        print("REASON=" + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
