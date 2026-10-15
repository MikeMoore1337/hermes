"""Manual read-only evidence of durable incident and recovery receipts.

Recorded Telegram ACKs prove only what the local outbox claims was accepted.
They do not independently prove Telegram delivery, human reading, or a
naturally occurring incident. No network, secrets, systemd or SQLite writes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import INCIDENT_CODES, InputError
from .delivery_contract import MAX_ATTEMPTS, _verified_event
from .state_store import DATABASE

DIRECTORY = Path("/var/lib/hermes-agent/ops-watch")
MAX_ROWS = 1000
HEX_TOKEN = re.compile(r"[0-9a-f]{32}\Z")


def _date(text: Any) -> datetime:
    if type(text) is not str or len(text) > 40:
        raise InputError("invalid_evidence_timestamp")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise InputError("invalid_evidence_timestamp") from None
    if moment.tzinfo is None:
        raise InputError("invalid_evidence_timestamp")
    return moment.astimezone(UTC)


def inspect_receipts(directory: Path, *, code: str) -> dict[str, Any]:
    """Find a historical acknowledged new -> acknowledged resolved pair."""
    if type(code) is not str or code not in INCIDENT_CODES:
        raise InputError("unapproved_incident_code")
    path = directory / DATABASE
    if path.is_symlink() or not path.is_file():
        raise InputError("outbox_evidence_unavailable")
    try:
        meta = path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_nlink != 1):
            raise InputError("unsafe_outbox_db")
        # SQLite URI delimiters must be percent-encoded for literal paths.
        uri = path.absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as db:
            tables = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "events" not in tables:
                raise InputError("evidence_schema_unavailable")
            if "delivery_receipts" not in tables:
                return _empty(code)
            rows = db.execute(
                "SELECT e.id,e.fingerprint,e.phase,e.severity,e.title,"
                "e.action,e.created_at,r.status,r.lease_token,r.lease_until,"
                "r.attempts,r.telegram_message_id,r.acknowledged_at "
                "FROM events AS e LEFT JOIN delivery_receipts AS r "
                "ON r.event_id=e.id WHERE e.fingerprint=? "
                "ORDER BY e.id DESC LIMIT ?",
                ("ops:" + code, MAX_ROWS + 1),
            ).fetchall()
    except sqlite3.Error:
        raise InputError("outbox_evidence_unavailable") from None
    except OSError:
        raise InputError("outbox_evidence_unavailable") from None
    if len(rows) > MAX_ROWS:
        raise InputError("evidence_window_exceeded")

    new_ack: tuple[int, int] | None = None
    pair: tuple[int, int, int, int] | None = None
    for row in reversed(rows):
        event = _verified_event(row[:7])
        status, token, expiry, attempts, message_id, acked_at = row[7:]
        if status is None:
            if any(v is not None for v in row[8:]):
                raise InputError("evidence_receipt_invalid")
            continue
        if status not in ("leased", "acknowledged"):
            raise InputError("evidence_receipt_invalid")
        if (type(token) is not str or HEX_TOKEN.fullmatch(token) is None
                or type(expiry) is not str
                or type(attempts) is not int
                or not 1 <= attempts <= MAX_ATTEMPTS):
            raise InputError("evidence_receipt_invalid")
        _date(expiry)
        if status == "leased":
            if message_id is not None or acked_at is not None:
                raise InputError("evidence_receipt_invalid")
            continue
        if type(message_id) is not int or message_id <= 0:
            raise InputError("evidence_receipt_invalid")
        if _date(acked_at) < _date(event["created_at"]):
            raise InputError("evidence_receipt_invalid")
        if event["phase"] == "new":
            new_ack = (event["event_id"], message_id)
        elif new_ack:
            pair = (new_ack[0], event["event_id"], new_ack[1], message_id)
            new_ack = None
    if pair is None:
        return _empty(code)
    return {
        "status": "RECORDED_ACK_PAIR_UNVERIFIED",
        "code": code,
        "new_event_id": pair[0],
        "resolved_event_id": pair[1],
        "new_telegram_message_id": pair[2],
        "resolved_telegram_message_id": pair[3],
        "telegram_acceptance_independently_verified": False,
        "natural_incident_origin_verified": False,
        "current_service_health_verified": False,
        "database_modified": False,
    }


def _empty(code: str) -> dict[str, Any]:
    return {
        "status": "NO_RECORDED_ACK_PAIR", "code": code,
        "telegram_acceptance_independently_verified": False,
        "natural_incident_origin_verified": False,
        "current_service_health_verified": False,
        "database_modified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manual local receipt evidence only")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--code", choices=sorted(INCIDENT_CODES), required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        report = inspect_receipts(DIRECTORY, code=args.code)
    except InputError:
        print(json.dumps({"status": "UNKNOWN", "reason": "receipt_evidence_unavailable",
                          "natural_incident_origin_verified": False,
                          "database_modified": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "RECORDED_ACK_PAIR_UNVERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
