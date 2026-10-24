#!/usr/bin/env python3
"""#454: one-use, owner-TTY approval to renew one EXISTING native device.

Approves one fresh device-code row bound to the already-paired Win32 ID.
Does not read, generate, print, or persist a bearer. The private BRC poll
will re-key the existing device ONLY if the Windows client uses the same ID.
Requires separately approved real owner-host execution.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time

from scripts.h15_brc_owner_private_pair import (
    CODE, DB, DEVICE, OWNER, PairDenied, find_pending,
    host_db_preflight, prompt_tty,
)

NATIVE_ID = "h454-win-01335a1f6e6705b4"
NATIVE_PLATFORM = "win32"


def verify_existing(conn: sqlite3.Connection) -> str:
    owners = conn.execute("SELECT id FROM users WHERE username=?", (OWNER,)).fetchall()
    if len(owners) != 1 or type(owners[0]["id"]) is not str or not owners[0]["id"]:
        raise PairDenied("OWNER_NOT_UNIQUE")
    owner = owners[0]["id"]
    devices = conn.execute(
        "SELECT device_id,user_id,name,platform,paused FROM devices WHERE name=?",
        (DEVICE,),
    ).fetchall()
    if (len(devices) != 1 or devices[0]["device_id"] != NATIVE_ID
            or devices[0]["user_id"] != owner
            or devices[0]["platform"] != NATIVE_PLATFORM
            or devices[0]["paused"] != 0):
        raise PairDenied("NATIVE_REGISTRATION_NOT_EXACT")
    return owner


def approve_rekey(conn: sqlite3.Connection, code: str, original: sqlite3.Row) -> None:
    """Atomic one-row authorization; do not update devices or token hashes."""
    before = conn.total_changes
    try:
        conn.execute("BEGIN IMMEDIATE")
        owner = verify_existing(conn)
        current = find_pending(conn, code)
        if (current["device_code"] != original["device_code"]
                or current["created_at"] != original["created_at"]):
            raise PairDenied("PAIRING_REQUEST_CHANGED")
        now = int(time.time() * 1000)
        changed = conn.execute("""
            UPDATE device_codes SET approved=1,user_id=?,device_id=?
            WHERE device_code=? AND user_code=? AND client_name=?
              AND approved=0 AND denied=0 AND user_id IS NULL
              AND (device_id IS NULL OR device_id='')
              AND created_at<=? AND expires_at>?
        """, (owner, NATIVE_ID, current["device_code"], code, DEVICE,
              now, now + 20_000))
        if changed.rowcount != 1 or conn.total_changes - before != 1:
            raise PairDenied("REKEY_APPROVAL_ATOMICITY_FAILED")
        confirmed = conn.execute(
            "SELECT approved,user_id,device_id FROM device_codes WHERE device_code=?",
            (current["device_code"],),
        ).fetchone()
        if (confirmed is None or confirmed["approved"] != 1
                or confirmed["user_id"] != owner
                or confirmed["device_id"] != NATIVE_ID
                or verify_existing(conn) != owner):
            raise PairDenied("REKEY_APPROVAL_READBACK_MISMATCH")
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def main() -> int:
    try:
        identity = host_db_preflight()
        # /dev/tty is non-seekable: use distinct read and write streams.
        with open("/dev/tty", "r", encoding="ascii") as reader, \
             open("/dev/tty", "w", encoding="ascii", buffering=1) as writer:
            code = prompt_tty(reader, writer,
                              "Enter fresh PRIVATE Windows pairing code: ", 64)
            if not CODE.fullmatch(code):
                raise PairDenied("INVALID_PAIRING_CODE_FORMAT")
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
                verify_existing(conn)
                row = find_pending(conn, code)
                seconds = (row["expires_at"] - int(time.time() * 1000)) // 1000
                print("EXISTING_NATIVE_ID=VERIFIED")
                print("OWNER=VERIFIED")
                print("PENDING_TTL_SECONDS=" + str(seconds))
                print("OLD_TOKEN=NOT_READ")
                print("PENDING_APPROVAL_ONLY=YES")
                confirm = prompt_tty(reader, writer,
                                     f"Confirm exactly: REKEY H454 {code}\n> ", 128)
                if confirm != f"REKEY H454 {code}":
                    raise PairDenied("OWNER_CONFIRMATION_DENIED")
                approve_rekey(conn, code, row)
                print("H454_NATIVE_REKEY_APPROVAL=PASS")
                print("WINDOWS_PRIVATE_POLL=READY")
                print("TOKEN_ISSUED_BY_OPERATOR=NO")
            finally:
                conn.close()
    except PairDenied as exc:
        print("H454_NATIVE_REKEY_APPROVAL=REFUSED")
        print("REASON=" + str(exc))
        return 2
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("H454_NATIVE_REKEY_APPROVAL=REFUSED")
        print("REASON=HOST_OR_DATABASE_CHECK_FAILED")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
