"""Owner-only local notification leasing protocol; DOES NOT send messages.

Claims are single-use bounded leases against the existing Ops Watch SQLite
event journal, and acknowledgments require the caller to provide a verified
remote message ID. Delivery itself and credentials are separate gated work.
If the remote service accepted a message but the client lost its ACK, eventual
retry MAY duplicate a message. No exactly-once delivery claim is made.
"""
from __future__ import annotations

import os
import re
import stat
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .core import INCIDENT_CODES, InputError
from .incident_preview import ACTIONS, CRITICAL, TITLES, resolved_action, resolved_title
from .state_store import _connection

MAX_ATTEMPTS = 5
LEASE_SECONDS = 90
TOKEN = re.compile(r"^[0-9a-f]{32}$")


def _time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise InputError("delivery_timezone_required")
    return value.astimezone(UTC)


def _create_receipts(db: sqlite3.Connection) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS delivery_receipts ("
        "event_id INTEGER PRIMARY KEY, "
        "status TEXT NOT NULL CHECK(status IN ('leased','acknowledged')), "
        "lease_token TEXT NOT NULL, "
        "lease_until TEXT NOT NULL, "
        "attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 5), "
        "telegram_message_id INTEGER, "
        "acknowledged_at TEXT)"
    )


def _verified_event(row: tuple[Any, ...]) -> dict[str, Any]:
    event_id, fingerprint, phase, severity, title, action, created = row
    if (type(event_id) is not int or event_id <= 0
            or type(fingerprint) is not str or not fingerprint.startswith("ops:")):
        raise InputError("delivery_event_invalid")
    code = fingerprint[4:]
    if code not in INCIDENT_CODES or phase not in ("new", "resolved"):
        raise InputError("delivery_event_invalid")
    expected_title = TITLES[code] if phase == "new" else resolved_title(code)
    expected_action = ACTIONS[code] if phase == "new" else resolved_action(code)
    expected_severity = (
        ("critical" if code in CRITICAL else "warning")
        if phase == "new" else "resolved"
    )
    if title != expected_title or action != expected_action or severity != expected_severity:
        raise InputError("delivery_event_tampered")
    if type(created) is not str or len(created) > 40:
        raise InputError("delivery_event_invalid")
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("delivery_event_invalid") from exc
    if when.tzinfo is None:
        raise InputError("delivery_event_invalid")
    return {
        "event_id": event_id, "code": code, "phase": phase,
        "severity": expected_severity, "title": expected_title,
        "action": expected_action, "created_at": when.astimezone(UTC).isoformat(),
    }


def claim_one(directory: Path, *, now: datetime) -> dict[str, Any] | None:
    """Atomically acquire the oldest undelivered event for a future sender.

    A claim may be retried only after its lease expires and at most five
    times. No outbound I/O or recipient information is handled here.
    """
    moment = _time(now)
    try:
        with closing(_connection(directory)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            _create_receipts(db)
            candidates = db.execute(
                "SELECT e.id,e.fingerprint,e.phase,e.severity,e.title,"
                "e.action,e.created_at,d.status,d.lease_until,d.attempts "
                "FROM events AS e LEFT JOIN delivery_receipts AS d "
                "ON d.event_id=e.id "
                "WHERE d.event_id IS NULL OR d.status!='acknowledged' "
                "ORDER BY e.id ASC LIMIT 1001"
            ).fetchall()
            if len(candidates) > 1000:
                raise InputError("delivery_queue_oversize")
            for row in candidates:
                event = _verified_event(row[:7])
                status, expiration, attempts = row[7:]
                if status == "acknowledged":
                    continue
                if status is not None:
                    if status != "leased" or type(expiration) is not str or type(attempts) is not int:
                        raise InputError("delivery_receipt_invalid")
                    try:
                        expiry = datetime.fromisoformat(expiration)
                    except ValueError as exc:
                        raise InputError("delivery_receipt_invalid") from exc
                    if expiry.tzinfo is None or not 1 <= attempts <= MAX_ATTEMPTS:
                        raise InputError("delivery_receipt_invalid")
                    if expiry.astimezone(UTC) > moment:
                        # Preserve chronological ordering; do not skip an unconfirmed event.
                        return None
                    if attempts >= MAX_ATTEMPTS:
                        # Retain failed receipt and evidence permanently;
                        # do not let one exhausted incident suppress all
                        # subsequent alerts, including its own recovery.
                        # The sender still reports an unhealthy queue until
                        # an operator separately resolves the exhausted item.
                        continue
                else:
                    attempts = 0
                token = secrets.token_hex(16)
                expiration = (moment + timedelta(seconds=LEASE_SECONDS)).isoformat()
                db.execute(
                    "INSERT INTO delivery_receipts "
                    "(event_id,status,lease_token,lease_until,attempts) "
                    "VALUES (?,?,?,?,?) "
                    "ON CONFLICT(event_id) DO UPDATE SET "
                    "status=excluded.status,lease_token=excluded.lease_token,"
                    "lease_until=excluded.lease_until,attempts=excluded.attempts",
                    (event["event_id"], "leased", token, expiration, attempts + 1),
                )
                db.commit()
                return {**event, "lease_token": token, "lease_until": expiration,
                        "attempt": attempts + 1}
            db.commit()
            return None
    except sqlite3.Error as exc:
        raise InputError("delivery_storage_unavailable") from exc


def confirm_one(
    directory: Path, *, event_id: int, lease_token: str,
    telegram_message_id: int, now: datetime,
) -> None:
    """Persist a real transport ACK; cannot invent the remote confirmation."""
    moment = _time(now)
    if (type(event_id) is not int or event_id <= 0
            or type(lease_token) is not str or TOKEN.fullmatch(lease_token) is None
            or type(telegram_message_id) is not int or telegram_message_id <= 0):
        raise InputError("delivery_confirmation_invalid")
    try:
        with closing(_connection(directory)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            _create_receipts(db)
            row = db.execute(
                "SELECT status,lease_token,lease_until FROM delivery_receipts "
                "WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None or row[0] != "leased" or row[1] != lease_token:
                raise InputError("delivery_confirmation_stale")
            try:
                expires = datetime.fromisoformat(row[2]).astimezone(UTC)
            except (ValueError, TypeError) as exc:
                raise InputError("delivery_confirmation_stale") from exc
            if expires < moment:
                raise InputError("delivery_confirmation_expired")
            db.execute(
                "UPDATE delivery_receipts SET status='acknowledged',"
                "telegram_message_id=?,acknowledged_at=? "
                "WHERE event_id=? AND lease_token=? AND status='leased'",
                (telegram_message_id, moment.isoformat(), event_id, lease_token),
            )
            db.commit()
    except sqlite3.Error as exc:
        raise InputError("delivery_storage_unavailable") from exc


def stats(directory: Path) -> dict[str, int]:
    """Aggregate state using a read-only SQLite connection (no DDL)."""
    path = directory / "incidents.sqlite3"
    if path.is_symlink() or not path.is_file():
        raise InputError("delivery_storage_unavailable")
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise InputError("unsafe_outbox_db")
    try:
        # as_uri percent-encodes '?' and '#' in legitimate directory names,
        # preventing those characters from changing SQLite URI parameters.
        uri = path.absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as db:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "events" not in tables:
                raise InputError("delivery_storage_unavailable")
            total = int(db.execute("SELECT count(*) FROM events").fetchone()[0])
            acknowledged = exhausted = 0
            if "delivery_receipts" in tables:
                acknowledged = int(db.execute(
                    "SELECT count(*) FROM delivery_receipts WHERE status='acknowledged'"
                ).fetchone()[0])
                exhausted = int(db.execute(
                    "SELECT count(*) FROM delivery_receipts "
                    "WHERE status='leased' AND attempts>=?", (MAX_ATTEMPTS,)
                ).fetchone()[0])
            if acknowledged > total:
                raise InputError("delivery_storage_invalid")
            return {"total": total, "acknowledged": acknowledged,
                    "unacknowledged": total - acknowledged, "exhausted": exhausted}
    except sqlite3.Error as exc:
        raise InputError("delivery_storage_unavailable") from exc
