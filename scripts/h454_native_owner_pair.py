"""H454: owner-only atomic approval for a NEW BRC native device code.

Real relay sqlite device_code approval, not a duplicate MCP server.
An unprivileged native agent obtains /device/start, waits on /device/poll
WITHOUT specifying device_id, then receives only the owner-bound ID/token.

Only this exact pending row changes. The old revoked Windows record and
all Docker/sandbox devices are untouched. Operator requires a real root
TTY on the pinned Hermes VPS, drops privileges before touching SQLite.
No SSH/HTTP listener, service activation or token delivery in this module.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import sys
import time

from device_fabric.native_brc_enrollment import NAME, IDENTITY, OLD_WINDOWS
from scripts.h15_brc_owner_private_pair import (
    CODE, DB, OWNER, PairDenied, host_db_preflight, prompt_tty,
)

PREFIX = {
    "windows": "h454-win-native-",
    "hermes-vps": "h454-linux-hermes-",
    "yfc-vps": "h454-linux-yfc-",
}
MAX_TTL_MS = 900_000


def _owner(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT id FROM users WHERE username=?", (OWNER,)
    ).fetchall()
    if len(rows) != 1 or type(rows[0]["id"]) is not str or not rows[0]["id"]:
        raise PairDenied("H454_NATIVE_OWNER_NOT_UNIQUE")
    return rows[0]["id"]


def pending(conn: sqlite3.Connection, target: str,
            user_code: str, now_ms: int) -> sqlite3.Row:
    if (type(target) is not str or target not in NAME
        or type(user_code) is not str or CODE.fullmatch(user_code) is None
        or type(now_ms) is not int):
        raise PairDenied("H454_NATIVE_PAIR_SCOPE_DENIED")
    matches = conn.execute(
        "SELECT * FROM device_codes WHERE user_code=?", (user_code,)
    ).fetchall()
    if len(matches) != 1:
        raise PairDenied("H454_NATIVE_PAIR_NOT_UNIQUE")
    row = matches[0]
    if (row["client_name"] != NAME[target]
        or row["approved"] != 0 or row["denied"] != 0
        or row["user_id"] is not None
        or row["device_id"] not in (None, "")
        or type(row["created_at"]) is not int
        or type(row["expires_at"]) is not int
        or row["created_at"] > now_ms
        or row["expires_at"] <= now_ms + 20_000
        or row["expires_at"] - row["created_at"] <= 0
        or row["expires_at"] - row["created_at"] > MAX_TTL_MS):
        raise PairDenied("H454_NATIVE_PAIR_NOT_PENDING")
    return row


def approve(
    conn: sqlite3.Connection, *,
    target: str, user_code: str, original: sqlite3.Row,
    new_hex: str, now_ms: int,
) -> str:
    """Compare-and-set exact owner, pending code, and fresh device identity.

    No token is minted here. The existing BRC /device/poll endpoint issues
    a bearer into the native process only AFTER this transaction commits.
    """
    try:
        if (type(new_hex) is not str or len(new_hex) != 32
            or any(c not in "0123456789abcdef" for c in new_hex)
            or target not in PREFIX):
            raise PairDenied("H454_NATIVE_IDENTITY_DENIED")
        device_id = PREFIX[target] + new_hex
        if (IDENTITY[target].fullmatch(device_id) is None
            or device_id == OLD_WINDOWS):
            raise PairDenied("H454_NATIVE_IDENTITY_DENIED")
        conn.execute("BEGIN IMMEDIATE")
        owner_id = _owner(conn)
        current = pending(conn, target, user_code, now_ms)
        if (original["device_code"] != current["device_code"]
            or original["created_at"] != current["created_at"]
            or original["expires_at"] != current["expires_at"]):
            raise PairDenied("H454_NATIVE_PAIR_CHANGED")
        if conn.execute(
            "SELECT count(*) FROM devices "
            "WHERE name=? OR device_id=?",
            (NAME[target], device_id),
        ).fetchone()[0] != 0:
            raise PairDenied("H454_NATIVE_DEVICE_EXISTS")
        if conn.execute(
            "SELECT count(*) FROM device_codes "
            "WHERE client_name=? AND device_code<>? "
            "AND approved=0 AND denied=0 AND expires_at>?",
            (NAME[target], current["device_code"], now_ms),
        ).fetchone()[0] != 0:
            raise PairDenied("H454_NATIVE_OTHER_PENDING")
        # Atomic predicate preserves the existing code and name under
        # concurrent owner/browser/poll attempts.
        changed = conn.execute(
            """UPDATE device_codes SET approved=1,user_id=?,device_id=?
               WHERE device_code=? AND user_code=? AND client_name=?
                 AND approved=0 AND denied=0 AND user_id IS NULL
                 AND (device_id IS NULL OR device_id='')
                 AND created_at<=? AND expires_at>?""",
            (owner_id, device_id, current["device_code"], user_code,
             NAME[target], now_ms, now_ms + 20_000),
        )
        if changed.rowcount != 1:
            raise PairDenied("H454_NATIVE_PAIR_CAS_DENIED")
        readback = conn.execute(
            "SELECT approved,user_id,device_id FROM device_codes WHERE device_code=?",
            (current["device_code"],),
        ).fetchone()
        if (readback is None
            or tuple(readback) != (1, owner_id, device_id)):
            raise PairDenied("H454_NATIVE_PAIR_READBACK_DENIED")
        conn.execute("COMMIT")
        return device_id
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise PairDenied("H454_NATIVE_PAIR_DENIED") from None


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="H454 new owner-paired device")
    parser.add_argument("--target", choices=sorted(NAME), required=True)
    args = parser.parse_args(argv)
    try:
        # The existing owner-verified host gate also ensures root TTY,
        # correct relay DB permissions, actual VPS hostname and UID.
        identity = host_db_preflight()
        with open("/dev/tty", "r", encoding="ascii") as reader, \
             open("/dev/tty", "w", encoding="ascii", buffering=1) as writer:
            code = prompt_tty(reader, writer,
                "Enter fresh H454 native pairing code (NEVER the bearer): ", 64)
            if CODE.fullmatch(code) is None:
                raise PairDenied("H454_NATIVE_CODE_FORMAT_DENIED")
            os.setgroups([])
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
            if os.geteuid() != identity.pw_uid:
                raise PairDenied("H454_NATIVE_UID_DROP_DENIED")
            conn = sqlite3.connect(f"file:{DB}?mode=rw", uri=True,
                                   isolation_level=None, timeout=3.0)
            conn.row_factory = sqlite3.Row
            try:
                if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                    raise PairDenied("H454_NATIVE_DB_NOT_WAL")
                _owner(conn)
                current = pending(conn, args.target, code, int(time.time()*1000))
                # Exact owner review: target, code, ID namespace, no writes
                # outside this one device_codes row.
                print("TARGET=" + args.target)
                print("DEVICE_NAME=" + NAME[args.target])
                print("DEVICE_ID_PREFIX=" + PREFIX[args.target])
                print("PAIRING_CODE_PENDING=YES")
                print("TOKEN_ISSUED=NO")
                check = prompt_tty(reader, writer,
                    f"Confirm exactly: PAIR H454 {args.target} {code}\n> ", 160)
                if check != f"PAIR H454 {args.target} {code}":
                    raise PairDenied("H454_NATIVE_CONFIRMATION_DENIED")
                approve(conn, target=args.target, user_code=code,
                        original=current, new_hex=secrets.token_hex(16),
                        now_ms=int(time.time()*1000))
                print("H454_NATIVE_PAIRING_APPROVAL=PASS")
                print("NATIVE_ID=BOUND_TO_PENDING_CODE")
                print("DEVICE_TOKEN=RELAY_POLL_ONLY")
            finally:
                conn.close()
        return 0
    except PairDenied:
        print("H454_NATIVE_PAIRING_APPROVAL=REFUSED")
        return 2
    except (OSError, sqlite3.Error, UnicodeError, ValueError):
        print("H454_NATIVE_PAIRING_APPROVAL=REFUSED")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
