#!/usr/bin/env python3
"""Hermes #454: owner TTY approval for a pending BRC device over private relay.

No HTTP endpoints, WebSocket, OAuth, token issuance or container changes.
Changes exactly one pending device_codes row in the live SQLite database.
Operator must use an interactive root TTY on the pinned Hermes VPS.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import socket
import sqlite3
import stat
import sys
import time

HOST = "vps1777112993"
RELAY_USER = "hermes-brc-relay"
DB = Path("/var/lib/hermes-brc-relay/relay.sqlite")
DEVICE = "H15 Windows native read-only"
OWNER = "admin"
CODE = re.compile(r"^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$")
MAX_TTL_MS = 900_000


class PairDenied(Exception):
    """Bounded rejection without exposing credentials or database contents."""


def verify(row: sqlite3.Row | None, now: int) -> None:
    if row is None:
        raise PairDenied("CODE_ABSENT")
    if (row["client_name"] != DEVICE or row["approved"] != 0
            or row["denied"] != 0 or row["user_id"] is not None
            or row["device_id"] not in (None, "")
            or type(row["created_at"]) is not int
            or type(row["expires_at"]) is not int
            or row["created_at"] > now
            or row["expires_at"] <= now + 20_000
            or row["expires_at"] - row["created_at"] > MAX_TTL_MS
            or row["expires_at"] - row["created_at"] <= 0):
        raise PairDenied("CODE_NOT_PENDING_OR_EXPIRED")


def get_owner(conn: sqlite3.Connection) -> str:
    owners = conn.execute("SELECT id FROM users WHERE username = ?", (OWNER,)).fetchall()
    if len(owners) != 1 or type(owners[0]["id"]) is not str or not owners[0]["id"]:
        raise PairDenied("OWNER_NOT_UNIQUE")
    count = conn.execute("SELECT count(*) FROM devices WHERE name = ?", (DEVICE,)).fetchone()[0]
    if count != 0:
        raise PairDenied("NATIVE_DEVICE_ALREADY_REGISTERED")
    return owners[0]["id"]


def find_pending(conn: sqlite3.Connection, code: str) -> sqlite3.Row:
    now = int(time.time() * 1000)
    row = conn.execute("SELECT * FROM device_codes WHERE user_code = ?", (code,)).fetchone()
    verify(row, now)
    assert row is not None
    return row


def approve(conn: sqlite3.Connection, code: str, original: sqlite3.Row) -> None:
    """Atomic compare-and-set, not a direct device-token or device creation."""
    baseline_changes = conn.total_changes
    try:
        conn.execute("BEGIN IMMEDIATE")
        owner_id = get_owner(conn)
        row = find_pending(conn, code)
        if (row["device_code"] != original["device_code"]
                or row["created_at"] != original["created_at"]):
            raise PairDenied("PAIRING_REQUEST_CHANGED")
        now = int(time.time() * 1000)
        result = conn.execute("""
            UPDATE device_codes
            SET approved=1, user_id=?
            WHERE device_code=? AND user_code=? AND client_name=?
              AND approved=0 AND denied=0 AND user_id IS NULL
              AND (device_id IS NULL OR device_id='')
              AND expires_at > ? AND created_at <= ?
        """, (owner_id, row["device_code"], code, DEVICE, now + 20_000, now))
        if result.rowcount != 1 or conn.total_changes - baseline_changes != 1:
            raise PairDenied("ATOMIC_APPROVAL_FAILED")
        persisted = conn.execute(
            "SELECT approved,user_id FROM device_codes WHERE device_code=?",
            (row["device_code"],)).fetchone()
        if persisted is None or persisted["approved"] != 1 or persisted["user_id"] != owner_id:
            raise PairDenied("APPROVAL_READBACK_MISMATCH")
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def host_db_preflight() -> pwd.struct_passwd:
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PairDenied("ROOT_INTERACTIVE_TTY_REQUIRED")
    if socket.gethostname().split(".")[0] != HOST:
        raise PairDenied("WRONG_VPS")
    identity = pwd.getpwnam(RELAY_USER)
    if identity.pw_uid == 0 or identity.pw_gid == 0:
        raise PairDenied("SERVICE_USER_IS_ROOT")
    directory = DB.parent.lstat()
    file = DB.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode)
            or directory.st_uid != identity.pw_uid or directory.st_gid != identity.pw_gid
            or (directory.st_mode & 0o077) != 0
            or not stat.S_ISREG(file.st_mode) or stat.S_ISLNK(file.st_mode)
            or file.st_uid != identity.pw_uid or file.st_gid != identity.pw_gid):
        raise PairDenied("UNSAFE_SQLITE_OWNERSHIP")
    return identity


def main() -> int:
    try:
        identity = host_db_preflight()
        # Open TTY while privileged; drop to the relay's own UID/GID BEFORE
        # opening SQLite, so WAL sidecars can never become root-owned.
        with open("/dev/tty", "r+", encoding="ascii", buffering=1) as tty:
            tty.write("Enter a FRESH Windows pairing code (not a bearer token): ")
            raw = tty.readline(64).strip()
            if not CODE.fullmatch(raw):
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
                get_owner(conn)
                row = find_pending(conn, raw)
                seconds = (row["expires_at"] - int(time.time() * 1000)) // 1000
                print("DATABASE=OPEN_AS_SERVICE_USER")
                print("PENDING_DEVICE_NAME=" + DEVICE)
                print("PENDING_OWNER=" + OWNER)
                print("PENDING_TTL_SECONDS=" + str(seconds))
                print("TOKEN_ISSUED=NO")
                tty.write(f"Confirm exactly: APPROVE H454 {raw}\n> ")
                confirm = tty.readline(128).strip()
                if confirm != f"APPROVE H454 {raw}":
                    raise PairDenied("OWNER_CONFIRMATION_DENIED")
                approve(conn, raw, row)
                print("H454_PRIVATE_PAIRING_APPROVAL=PASS")
                print("DEVICE_TOKEN=NOT_ISSUED_ON_VPS")
                print("WINDOWS_PRIVATE_POLL=READY")
            finally:
                conn.close()
    except PairDenied as exc:
        print("H454_PRIVATE_PAIRING_APPROVAL=REFUSED")
        print("REASON=" + str(exc))
        return 2
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("H454_PRIVATE_PAIRING_APPROVAL=REFUSED")
        print("REASON=HOST_OR_DATABASE_CHECK_FAILED")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
