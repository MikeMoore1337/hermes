"""Owner-enabled, networkless monitoring of two self-hosted presence agents.

Reads only the fixed device IDs and heartbeat timestamps from the local SQLite
registry. Never opens the WSS port, reads pairing tokens, or executes commands.
Missing owner opt-in is NOT an outage.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
import subprocess

DB = Path("/var/lib/hermes-device-fabric/devices.sqlite3")
OPT_IN = Path("/var/lib/hermes-device-fabric/ops-watch-presence.json")
CERT = Path("/var/lib/hermes-device-fabric/tls/cert.pem")
DEVICES = ("windows-pc", "linux-vps")
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


def certificate_status(cert: Path = CERT, opt_in: Path = OPT_IN, *,
                       now: datetime | None = None) -> str:
    """Warn before the seven-day pilot TLS identity expires.

    Local, bounded openssl call reads only cert (not key) in private networkless
    Ops Watch. Missing opt-in is not evidence of a service outage.
    """
    at = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        if opt_in.is_symlink() or not opt_in.is_file():
            return "not_configured"
        if opt_in.stat().st_size > 512:
            return "unknown"
        gate = json.loads(opt_in.read_text(encoding="utf-8"))
        if (not isinstance(gate, dict) or set(gate) !=
                {"schema", "devices", "enabled_at"} or
                gate["schema"] != 1 or gate["devices"] != list(DEVICES)):
            return "unknown"
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
