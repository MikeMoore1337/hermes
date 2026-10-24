#!/usr/bin/env python3
"""#454: approve one private re-pair of the SAME existing native Win32 device.

Only a pending device_codes row is approved here. The existing BRC /device/poll
rotates the bearer in memory after approval; this operator never handles it.
Requires an interactive owner-root TTY on the pinned Hermes host.
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
import time

from scripts.h15_brc_owner_private_pair import (
    CODE, DB, DEVICE, OWNER, PairDenied,
    find_pending, host_db_preflight, prompt_tty,
)

DEVICE_ID = "h454-win-01335a1f6e6705b4"
TOKEN_HASH = re.compile(r"^[a-f0-9]{64}$")


def existing_owner_device(conn: sqlite3.Connection) -> tuple[str, str]:
    owners = conn.execute(
        "SELECT id FROM users WHERE username = ?", (OWNER,)
    ).fetchall()
    if len(owners) != 1 or not isinstance(owners[0]["id"], str) or not owners[0]["id"]:
        raise PairDenied("OWNER_NOT_UNIQUE")

    # Never re-key another native device, including a similarly named clone.
    rows = conn.execute(
        "SELECT device_id, user_id, name, platform, paused, token_hash "
        "FROM devices WHERE name = ? OR device_id = ?",
        (DEVICE, DEVICE_ID),
    ).fetchall()
    if len(rows) != 1:
        raise PairDenied("NATIVE_DEVICE_NOT_UNIQUE")
    row = rows[0]
    if (
        row["device_id"] != DEVICE_ID or row["user_id"] != owners[0]["id"]
        or row["name"] != DEVICE or row["platform"] != "win32"
        or row["paused"] != 0 or not isinstance(row["token_hash"], str)
        or TOKEN_HASH.fullmatch(row["token_hash"]) is None
    ):
        raise PairDenied("NATIVE_DEVICE_IDENTITY_MISMATCH")
    return owners[0]["id"], row["token_hash"]


def approve_existing(conn: sqlite3.Connection, code: str, baseline: sqlite3.Row) -> None:
    """Atomic single-code approval; leave all device rows and token hashes intact."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        owner_id, before_token = existing_owner_device(conn)
        current = find_pending(conn, code)
        if (current["device_code"] != baseline["device_code"]
                or current["created_at"] != baseline["created_at"]):
            raise PairDenied("PAIRING_REQUEST_CHANGED")
        now = int(time.time() * 1000)
        result = conn.execute(
            """UPDATE device_codes
               SET approved=1, user_id=?, device_id=?
               WHERE device_code=? AND user_code=? AND client_name=?
                 AND approved=0 AND denied=0 AND user_id IS NULL
                 AND (device_id IS NULL OR device_id='')
                 AND created_at<=? AND expires_at>?""",
            (owner_id, DEVICE_ID, current["device_code"], code, DEVICE, now, now + 20_000),
        )
        if result.rowcount != 1:
            raise PairDenied("ATOMIC_APPROVAL_FAILED")
        check = conn.execute(
            "SELECT approved, user_id, device_id FROM device_codes WHERE device_code=?",
            (current["device_code"],),
        ).fetchone()
        if (check is None or check["approved"] != 1
                or check["user_id"] != owner_id
                or check["device_id"] != DEVICE_ID):
            raise PairDenied("APPROVAL_READBACK_MISMATCH")
        after_owner, after_token = existing_owner_device(conn)
        if after_owner != owner_id or after_token != before_token:
            raise PairDenied("DEVICE_CHANGED_DURING_APPROVAL")
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def main() -> int:
    try:
        identity = host_db_preflight()
        with open("/dev/tty", "r", encoding="ascii") as reader, \
             open("/dev/tty", "w", encoding="ascii", buffering=1) as writer:
            code = prompt_tty(reader, writer,
                              "Enter a NEW private Windows code (never a bearer): ", 64)
            if CODE.fullmatch(code) is None:
                raise PairDenied("INVALID_PAIRING_CODE_FORMAT")
            # Drop root BEFORE opening production SQLite, preserving WAL ownership.
            os.setgroups([])
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
            if os.geteuid() != identity.pw_uid:
                raise PairDenied("UID_DROP_FAILED")
            conn = sqlite3.connect(f"file:{DB}?mode=rw", uri=True,
                                   timeout=3.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                    raise PairDenied("SQLITE_NOT_WAL")
                existing_owner_device(conn)
                original = find_pending(conn, code)
                remaining = (original["expires_at"] - int(time.time() * 1000)) // 1000
                print("REKEY_EXISTING_DEVICE=VERIFIED")
                print("DEVICE_ID=" + DEVICE_ID)
                print("OWNER=" + OWNER)
                print("PENDING_TTL_SECONDS=" + str(remaining))
                print("OLD_BEARER_ROTATED=NO")
                answer = prompt_tty(
                    reader, writer,
                    f"Confirm exactly: APPROVE H454 REKEY {code}\n> ", 128,
                )
                if answer != f"APPROVE H454 REKEY {code}":
                    raise PairDenied("OWNER_CONFIRMATION_DENIED")
                approve_existing(conn, code, original)
                print("H454_PRIVATE_REPAIR_APPROVAL=PASS")
                print("DEVICE_ROW_CHANGED=NO")
                print("TOKEN_ISSUED_ON_VPS=NO")
                print("WINDOWS_PRIVATE_POLL=READY")
            finally:
                conn.close()
    except PairDenied as exc:
        print("H454_PRIVATE_REPAIR_APPROVAL=REFUSED")
        print("REASON=" + str(exc))
        return 2
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("H454_PRIVATE_REPAIR_APPROVAL=REFUSED")
        print("REASON=HOST_OR_DATABASE_CHECK_FAILED")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
