#!/usr/bin/env python3
"""#454: owner-gated irreversible revocation of a single native Win32 bearer.

This operation deliberately preserves the paired device row for audit/recovery,
while atomically pausing it and replacing its token hash with an unrecoverable
random digest. It never prints or creates a usable device bearer token.
No container, sandbox device, or Windows original file is modified.
"""
from __future__ import annotations

from hashlib import sha256
import os
import secrets
import sqlite3
import sys
import time

from scripts.h15_brc_owner_private_pair import (
    DB, DEVICE, PairDenied, host_db_preflight, prompt_tty,
)
from scripts.h15_brc_owner_private_repair import DEVICE_ID, existing_owner_device


def revoke_native(conn: sqlite3.Connection) -> None:
    """Pause/re-key ONLY expected native device, transactionally and once."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        owner_id, original_hash = existing_owner_device(conn)
        pending = conn.execute(
            "SELECT count(*) FROM device_codes WHERE client_name=? AND expires_at>?",
            (DEVICE, int(time.time() * 1000)),
        ).fetchone()[0]
        if pending:
            raise PairDenied("NATIVE_PAIRING_STILL_PENDING")

        # Protect other paired devices even if schema or target row was changed.
        other_before = conn.execute(
            "SELECT device_id,user_id,name,token_hash,platform,paused "
            "FROM devices WHERE device_id<>? ORDER BY device_id", (DEVICE_ID,)
        ).fetchall()
        if len(other_before) < 3:
            raise PairDenied("SANDBOX_BASELINE_INCOMPLETE")

        # No raw bearer issued; this digest is a one-way random dead-end.
        disabled_hash = sha256(secrets.token_bytes(32)).hexdigest()
        if disabled_hash == original_hash:
            raise PairDenied("TOKEN_ROTATION_COLLISION")
        cur = conn.execute(
            "UPDATE devices SET token_hash=?, paused=1 "
            "WHERE device_id=? AND user_id=? AND name=? AND platform='win32' "
            "AND token_hash=? AND paused=0",
            (disabled_hash, DEVICE_ID, owner_id, DEVICE, original_hash),
        )
        if cur.rowcount != 1:
            raise PairDenied("REVOKE_COMPARE_AND_SET_FAILED")
        updated = conn.execute(
            "SELECT paused,token_hash FROM devices WHERE device_id=?", (DEVICE_ID,)
        ).fetchone()
        if (updated is None or updated["paused"] != 1
                or updated["token_hash"] != disabled_hash):
            raise PairDenied("REVOKE_READBACK_MISMATCH")

        other_after = conn.execute(
            "SELECT device_id,user_id,name,token_hash,platform,paused "
            "FROM devices WHERE device_id<>? ORDER BY device_id", (DEVICE_ID,)
        ).fetchall()
        if other_before != other_after:
            raise PairDenied("OTHER_DEVICE_CHANGED")
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
            # Privilege drop BEFORE opening SQLite; preserve relay-owned WAL.
            os.setgroups([])
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
            if os.geteuid() != identity.pw_uid:
                raise PairDenied("UID_DROP_FAILED")
            conn = sqlite3.connect(
                f"file:{DB}?mode=rw", uri=True, timeout=3.0, isolation_level=None
            )
            conn.row_factory = sqlite3.Row
            try:
                if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                    raise PairDenied("SQLITE_NOT_WAL")
                existing_owner_device(conn)
                print("NATIVE_OWNER_DEVICE_ID=" + DEVICE_ID)
                print("REVOCATION_SCOPE=SINGLE_NATIVE_DEVICE")
                print("ACTION=PAUSE_AND_INVALIDATE_BEARER")
                print("OTHER_DEVICES=UNMODIFIED")
                print("WINDOWS_PROCESS_TERMINATION=NOT_PERFORMED")
                prompt = f"REVOKE H454 {DEVICE_ID}"
                answer = prompt_tty(reader, writer,
                                    f"Type exactly: {prompt}\n> ", 96)
                if answer != prompt:
                    raise PairDenied("OWNER_CONFIRMATION_DENIED")
                revoke_native(conn)
                print("H454_NATIVE_TOKEN_REVOKED=PASS")
                print("NATIVE_DEVICE_PAUSED=PASS")
                print("NATIVE_DEVICE_ROW_PRESERVED=YES")
                print("OTHER_DEVICE_RECORDS_UNCHANGED=PASS")
                print("NEW_BEARER_ISSUED=NO")
            finally:
                conn.close()
    except PairDenied as exc:
        print("H454_NATIVE_TOKEN_REVOKED=REFUSED")
        print("REASON=" + str(exc))
        return 2
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("H454_NATIVE_TOKEN_REVOKED=REFUSED")
        print("REASON=HOST_OR_DATABASE_CHECK_FAILED")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
