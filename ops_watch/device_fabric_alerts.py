"""Owner-enabled, networkless monitoring of two self-hosted presence agents.

Reads only the fixed device IDs and heartbeat timestamps from the local SQLite
registry. Never opens the WSS port, reads pairing tokens, or executes commands.
Missing owner opt-in is NOT an outage.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import binascii
import json
import os
from pathlib import Path
import sqlite3
import ssl
import stat
import subprocess

DB = Path("/var/lib/hermes-device-fabric/devices.sqlite3")
OPT_IN = Path("/var/lib/hermes-device-fabric/ops-watch-presence.json")
# Separate root-only TLS consent: clients may be offline while their cert expires.
TLS_OPT_IN = Path("/etc/hermes-device-fabric/ops-watch-tls.json")
CERT = Path("/var/lib/hermes-device-fabric/tls/cert.pem")
ROTATED_CERT = CERT.parent / "active" / "cert.pem"
DEVICES = ("windows-pc", "linux-vps")
# Public, owner-attested SHA-256 of the one-time H346 signer CA (DER).
# The CA *private* key was destroyed; renewal cannot be performed by Ops Watch.
BATCH_CA_SHA256 = "72e930d2ce5b3798237e1495ccfecf4300f303fb0f6b57f3accc9739b01d8ab0"
BATCH_TLS_ROOT = CERT.parent
BATCH_SLOTS = ("primary",) + tuple(f"future-{n:02d}" for n in range(1, 14))
BATCH_RENEWAL_DAYS = 90
BATCH_CRITICAL_DAYS = 30

DELAY = {"windows-pc": timedelta(minutes=20),
         "linux-vps": timedelta(minutes=10)}
FRESH = timedelta(seconds=45)
FUTURE = timedelta(seconds=30)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 42:
        raise ValueError("invalid_time")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("invalid_timezone")
    return result.astimezone(UTC)


def _tls_only_consent(at: datetime) -> bool | None:
    """True for root-owned TLS-only consent, None if absent, False if unsafe.

    The independent marker must not grant enrollment/device monitoring rights.
    The old device opt-in remains supported when this marker is absent.
    """
    marker = TLS_OPT_IN
    try:
        parent = marker.parent.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return False
    if (not stat.S_ISDIR(parent.st_mode) or
            stat.S_IMODE(parent.st_mode) != 0o700 or
            (os.name == "posix" and parent.st_uid != os.geteuid())):
        return False
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return False
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= 512 or
            (os.name == "posix" and info.st_uid != os.geteuid())):
        return False
    try:
        fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev != info.st_dev or opened.st_ino != info.st_ino or
                    opened.st_size != info.st_size):
                return False
            data = os.read(fd, 513)
        finally:
            os.close(fd)
        if len(data) != info.st_size:
            return False
        gate = json.loads(data.decode("utf-8"))
        if (not isinstance(gate, dict) or
                set(gate) != {"schema", "purpose", "enabled_at"} or
                type(gate["schema"]) is not int or gate["schema"] != 1 or
                gate["purpose"] != "tls-expiry"):
            return False
        return _timestamp(gate["enabled_at"]) <= at + FUTURE
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        return False


def certificate_status(cert: Path = CERT, opt_in: Path = OPT_IN, *,
                       now: datetime | None = None) -> str:
    """Warn before the seven-day pilot TLS identity expires.

    Local, bounded openssl call reads only cert (not key) in private networkless
    Ops Watch. Missing opt-in is not evidence of a service outage.
    """
    at = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        independent = _tls_only_consent(at)
        if independent is False:
            return "unknown"
        if independent is None:
            if opt_in.is_symlink() or not opt_in.is_file():
                return "not_configured"
            if opt_in.stat().st_size > 512:
                return "unknown"
            gate = json.loads(opt_in.read_text(encoding="utf-8"))
            if (not isinstance(gate, dict) or set(gate) !=
                    {"schema", "devices", "enabled_at"} or
                    gate["schema"] != 1 or gate["devices"] != list(DEVICES)):
                return "unknown"
        # After an explicitly approved service migration, follow only the
        # root-managed "active" generation. Before migration retain the old
        # direct certificate path and all existing expiry semantics.
        if cert == CERT and (CERT.parent / "active").is_symlink():
            target = (CERT.parent / "active").readlink().as_posix()
            if (not target.startswith("generations/leaf-") or
                    target.count("/") != 1 or len(target) != 49 or
                    any(ch not in "0123456789abcdef" for ch in target[-32:])):
                return "unknown"
            cert = ROTATED_CERT
        if cert.is_symlink() or not cert.is_file() or cert.stat().st_size > 8192:
            return "unknown"
        result = subprocess.run(
            ["/usr/bin/openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
            capture_output=True, text=True, check=False, timeout=3,
        )
        if result.returncode != 0 or len(result.stdout) > 120 or not result.stdout.startswith("notAfter="):
            return "unknown"
        expiry = datetime.strptime(result.stdout.strip()[9:],
                                   "%b %d %H:%M:%S %Y GMT").replace(tzinfo=UTC)
        if expiry <= at:
            return "expired"
        return "expiring" if expiry - at <= timedelta(hours=48) else "healthy"
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, OverflowError):
        return "unknown"



def _private_batch_file(path: Path, *, mode: int, limit: int = 16384) -> bytes:
    """Read only the fixed root-owned *public* batch inventory, never keys."""
    original = path.lstat()
    if (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1
            or original.st_uid != os.geteuid()
            or stat.S_IMODE(original.st_mode) != mode
            or not 0 < original.st_size <= limit):
        raise ValueError("untrusted_public_batch_file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino, actual.st_size) != (
                original.st_dev, original.st_ino, original.st_size):
            raise ValueError("public_batch_file_changed")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) != original.st_size:
        raise ValueError("public_batch_file_changed")
    return data


def presigned_batch_status(root: Path = BATCH_TLS_ROOT, *,
                           now: datetime | None = None) -> str:
    """Finite CA-issuance runway: no secret reads, signing, or network calls.

    Status is an opt-in observation, NOT proof of revocation or auto-reissue.
    Owners require a new CA/trust cutover before the last pre-signed leaf expires.
    Unknown input must never be interpreted as a safe renewal runway.
    """
    at = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        gate = _tls_only_consent(at)
        if gate is None:
            return "not_configured"
        if gate is False:
            return "unknown"
        archive = root / "presigned-batch"
        try:
            meta = archive.lstat()
        except FileNotFoundError:
            # A legacy pilot may have opted into TLS expiry before batching.
            return "not_configured"
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o700):
            return "unknown"
        raw = _private_batch_file(archive / "manifest.json", mode=0o600)
        data = json.loads(raw.decode("utf-8"))
        if (not isinstance(data, dict)
                or set(data) != {"schema", "ca_der_sha256", "slots"}
                or data["schema"] != "hermes-h346-presigned-batch-v1"
                or data["ca_der_sha256"] != BATCH_CA_SHA256
                or not isinstance(data["slots"], list)
                or len(data["slots"]) != len(BATCH_SLOTS)):
            return "unknown"
        # The current CA must still be exactly the one in the owner-reviewed
        # pre-signed inventory; do not use global system trust or a new issuer.
        ca = _private_batch_file(root / "ca-public.pem", mode=0o640)
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                ca.decode("ascii"))).hexdigest() != BATCH_CA_SHA256:
            return "unknown"
        dates: list[tuple[datetime, datetime]] = []
        for expected_name, item in zip(BATCH_SLOTS, data["slots"]):
            if (not isinstance(item, dict)
                    or set(item) != {"slot", "der_sha256", "not_before", "not_after"}
                    or item["slot"] != expected_name
                    or not isinstance(item["der_sha256"], str)
                    or len(item["der_sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in item["der_sha256"])):
                return "unknown"
            start = _timestamp(item["not_before"])
            end = _timestamp(item["not_after"])
            if end - start != timedelta(days=30):
                return "unknown"
            dates.append((start, end))
        baseline = dates[0][0]
        if any(start != baseline + timedelta(days=25 * i)
               for i, (start, _) in enumerate(dates)):
            return "unknown"
        # Reading the PUBLIC CA's expiration is safe in Ops Watch. Fail closed
        # on malformed output, invalid trust, or a shorter CA lifetime.
        result = subprocess.run(
            ["/usr/bin/openssl", "x509", "-in", str(root / "ca-public.pem"),
             "-noout", "-enddate"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if (result.returncode != 0 or len(result.stdout) > 120
                or not result.stdout.startswith("notAfter=")):
            return "unknown"
        ca_end = datetime.strptime(result.stdout.strip()[9:],
                                  "%b %d %H:%M:%S %Y GMT").replace(tzinfo=UTC)
        remaining = min(dates[-1][1], ca_end) - at
        if remaining <= timedelta(0):
            return "expired"
        if remaining <= timedelta(days=BATCH_CRITICAL_DAYS):
            return "renewal_critical"
        if remaining <= timedelta(days=BATCH_RENEWAL_DAYS):
            return "renewal_due"
        return "healthy"
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, ssl.SSLError, binascii.Error,
            subprocess.TimeoutExpired):
        return "unknown"


def observe(db: Path = DB, opt_in: Path = OPT_IN, *,
            now: datetime | None = None) -> dict[str, dict[str, str]]:
    """Online only after fresh heartbeat; alert only after an owner-enabled grace.

    'unknown' is never evidence of successful recovery. The caller preserves
    previously confirmed incidents until a fresh, authenticated Online state.
    """
    at = (now or datetime.now(UTC)).astimezone(UTC)
    default = {key: {"status": "not_configured"} for key in DEVICES}
    try:
        if opt_in.is_symlink() or not opt_in.is_file():
            return default
    except (PermissionError, OSError):
        return {key: {"status": "unknown"} for key in DEVICES}

    unknown = {key: {"status": "unknown"} for key in DEVICES}
    try:
        if opt_in.stat().st_size > 512 or opt_in.stat().st_size == 0:
            return unknown
        settings = json.loads(opt_in.read_text(encoding="utf-8"))
        if (not isinstance(settings, dict) or set(settings) !=
                {"schema", "devices", "enabled_at"} or settings["schema"] != 1 or
                settings["devices"] != list(DEVICES)):
            return unknown
        enabled_at = _timestamp(settings["enabled_at"])
        if enabled_at > at + FUTURE:
            return unknown
        if db.is_symlink() or not db.is_file() or db.stat().st_size > 50_000_000:
            return unknown
        # Strictly read-only, using fixed identifiers; no tokens in SELECT/output.
        with sqlite3.connect(db.absolute().as_uri() + "?mode=ro",
                             uri=True, timeout=2) as conn:
            rows = conn.execute(
                "SELECT device_id, revoked, connected, last_seen FROM devices "
                "WHERE device_id IN (?,?)", DEVICES).fetchall()
        if len(rows) != len(DEVICES) or {r[0] for r in rows} != set(DEVICES):
            return unknown
        result = {}
        for ident, revoked, connected, last_seen in rows:
            if type(revoked) is not int or revoked not in (0, 1) or type(connected) is not int or connected not in (0, 1):
                return unknown
            if revoked:
                result[ident] = {"status": "unknown"}
                continue
            stamp = _timestamp(last_seen) if last_seen is not None else enabled_at
            if stamp > at + FUTURE:
                return unknown
            if connected and last_seen is not None and -FUTURE <= at - stamp <= FRESH:
                status = "online"
            elif at - max(enabled_at, stamp) >= DELAY[ident]:
                status = "offline"
            else:
                status = "warming"
            result[ident] = {"status": status}
        return {ident: result[ident] for ident in DEVICES}
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, OverflowError, UnicodeError):
        return unknown
