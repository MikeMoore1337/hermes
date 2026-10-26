#!/usr/bin/env python3
"""#454: one-time *owner-confirmed* re-pair of a previously REVOKED win32 device.

The prior operator intentionally set paused=1 and replaced the old bearer hash
with an unrecoverable digest. The normal existing-device repair intentionally
refuses paused devices; never relax that gate. This separate operator makes
exactly one approved, pending device-code request eligible for a NEW token,
while keeping the old bearer invalid and retaining the registered device ID.

NO private code/token/hashed token is logged. No API, network, SSH, Docker,
existing sandbox device, or original Windows project is touched here.
"""
from __future__ import annotations

from hashlib import sha256
import os
import secrets
import sqlite3
import sys
import time

from scripts.h15_brc_owner_private_pair import (
    CODE, DB, DEVICE, OWNER, PairDenied, find_pending,
    host_db_preflight, prompt_tty,
)
from scripts.h15_brc_owner_private_repair import DEVICE_ID, TOKEN_HASH


def revoked_owner_device(conn: sqlite3.Connection) -> tuple[str, str]:
    owners = conn.execute(
        "SELECT id FROM users WHERE username=?", (OWNER,)
    ).fetchall()
    if len(owners) != 1 or type(owners[0]["id"]) is not str or not owners[0]["id"]:
        raise PairDenied("NATIVE_OWNER_NOT_UNIQUE")
    matches = conn.execute(
        "SELECT device_id,user_id,name,platform,paused,token_hash "
        "FROM devices WHERE name=? OR device_id=?",
        (DEVICE, DEVICE_ID),
    ).fetchall()
    if len(matches) != 1:
        raise PairDenied("NATIVE_DEVICE_NOT_UNIQUE")
    row = matches[0]
    if (row["device_id"] != DEVICE_ID
        or row["user_id"] != owners[0]["id"]
        or row["name"] != DEVICE
        or row["platform"] != "win32"
        or type(row["paused"]) is not int or row["paused"] != 1
        or type(row["token_hash"]) is not str
        or TOKEN_HASH.fullmatch(row["token_hash"]) is None):
        raise PairDenied("NATIVE_NOT_REVOKED_OR_WRONG_IDENTITY")
    return owners[0]["id"], row["token_hash"]


def approve_revoked(conn: sqlite3.Connection, code: str,
                    baseline: sqlite3.Row) -> None:
    """Atomically admit only a fresh owner pairing code and unrevoke one ID.

    On commit the stored hash is STILL a fresh random DEAD-END digest, not
    the actual new bearer. Only the existing, independent relay device/poll
    may issue a new token to the approved Windows caller, never the VPS TTY.

    Failure before commit rolls back BOTH rows. Never reuse a code.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
        owner_id, revoked_hash = revoked_owner_device(conn)
        row = find_pending(conn, code)
        if (row["device_code"] != baseline["device_code"]
                or row["created_at"] != baseline["created_at"]):
            raise PairDenied("PAIR_REQUEST_CHANGED")
        now = int(time.time() * 1000)
        other_pending = conn.execute(
            "SELECT count(*) FROM device_codes WHERE client_name=? "
            "AND approved=0 AND denied=0 AND expires_at>? "
            "AND device_code<>?",
            (DEVICE, now, row["device_code"]),
        ).fetchone()[0]
        if other_pending:
            raise PairDenied("OTHER_NATIVE_PAIR_PENDING")
        sandbox_before = conn.execute(
            "SELECT device_id,user_id,name,platform,paused,token_hash "
            "FROM devices WHERE device_id<>? ORDER BY device_id",
            (DEVICE_ID,),
        ).fetchall()
        if len(sandbox_before) < 3:
            raise PairDenied("SANDBOX_BASELINE_INCOMPLETE")
        result = conn.execute(
            """UPDATE device_codes
               SET approved=1, user_id=?, device_id=?
               WHERE device_code=? AND user_code=? AND client_name=?
                 AND approved=0 AND denied=0 AND user_id IS NULL
                 AND (device_id IS NULL OR device_id='')
                 AND created_at<=? AND expires_at>?""",
            (owner_id, DEVICE_ID, row["device_code"], code, DEVICE,
             now, now + 20_000),
        )
        if result.rowcount != 1:
            raise PairDenied("PAIR_CODE_CAS_DENIED")
        # Replace dead hash with a *different* dead hash; NEVER restore the
        # old revoked bearer, and never issue a usable token in this helper.
        next_dead_hash = sha256(secrets.token_bytes(32)).hexdigest()
        if next_dead_hash == revoked_hash:
            raise PairDenied("HASH_COLLISION")
        change = conn.execute(
            "UPDATE devices SET token_hash=?,paused=0 "
            "WHERE device_id=? AND user_id=? AND name=? AND platform='win32' "
            "AND paused=1 AND token_hash=?",
            (next_dead_hash, DEVICE_ID, owner_id, DEVICE, revoked_hash),
        )
        if change.rowcount != 1:
            raise PairDenied("DEVICE_CAS_DENIED")
        approved = conn.execute(
            "SELECT approved,user_id,device_id FROM device_codes WHERE device_code=?",
            (row["device_code"],)
        ).fetchone()
        active = conn.execute(
            "SELECT user_id,name,platform,paused,token_hash FROM devices WHERE device_id=?",
            (DEVICE_ID,)
        ).fetchone()
        if (approved is None or tuple(approved) != (1, owner_id, DEVICE_ID)
            or active is None or tuple(active) !=
                (owner_id, DEVICE, "win32", 0, next_dead_hash)):
            raise PairDenied("REACTIVATION_READBACK_FAILED")
        sandbox_after = conn.execute(
            "SELECT device_id,user_id,name,platform,paused,token_hash "
            "FROM devices WHERE device_id<>? ORDER BY device_id",
            (DEVICE_ID,),
        ).fetchall()
        if [tuple(v) for v in sandbox_before] != [tuple(v) for v in sandbox_after]:
            raise PairDenied("OTHER_DEVICE_CHANGED")
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def main() -> int:
    try:
        identity = host_db_preflight()
        # Real interactive owner TTY. Do not accept -c or stdin/heredoc
        # impersonations from ChatGPT/agents, or a printed bearer.
        with open("/dev/tty", "r", encoding="ascii") as reader, \
             open("/dev/tty", "w", encoding="ascii", buffering=1) as writer:
            code = prompt_tty(reader, writer,
                "Enter fresh private Windows re-pair CODE (never bearer): ", 64)
            if CODE.fullmatch(code) is None:
                raise PairDenied("INVALID_PAIR_CODE")
            # Privilege drop BEFORE opening the live database, its WAL and shm.
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
                revoked_owner_device(conn)
                request = find_pending(conn, code)
                print("REVOKED_NATIVE_IDENTITY=VERIFIED")
                print("DEVICE_ID=" + DEVICE_ID)
                print("REACTIVATION_SCOPE=ONE_NATIVE_DEVICE_AND_ONE_PENDING_CODE")
                print("OLD_TOKEN_REMAINS_REVOKED=YES")
                print("OTHER_SANDBOX_DEVICES=UNCHANGED")
                print("NEW_TOKEN_NOT_ISSUED_BY_OPERATOR=YES")
                answer = prompt_tty(
                    reader, writer,
                    "Confirm exactly: REACTIVATE H454 " + code + "\n> ", 128,
                )
                if answer != "REACTIVATE H454 " + code:
                    raise PairDenied("OWNER_CONFIRMATION_DENIED")
                approve_revoked(conn, code, request)
                print("H454_NATIVE_REACTIVATION=PASS")
                print("WINDOWS_PRIVATE_POLL=READY")
                print("NEW_BEARER_ISSUED_ON_VPS=NO")
            finally:
                conn.close()
    except PairDenied as exc:
        print("H454_NATIVE_REACTIVATION=REFUSED")
        print("REASON=" + str(exc))
        return 2
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("H454_NATIVE_REACTIVATION=REFUSED")
        print("REASON=HOST_OR_DATABASE_CHECK_FAILED")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
