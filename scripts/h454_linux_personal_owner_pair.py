"""Bind one owner-authorized personal Linux code without issuing a token.

The caller must independently verify the host database and owner authorization.
This module has no CLI, credential transport, or service activation.
"""
from __future__ import annotations

import sqlite3

from device_fabric.linux_personal_enrollment import NAMES
from device_fabric.linux_personal_status import IDENTITIES
from scripts.h15_brc_owner_private_pair import CODE, PairDenied
from scripts.h454_native_owner_pair import MAX_TTL_MS, _owner

PREFIX = {'hermes-vps': 'h454-linux-personal-hermes-',
          'yfc-vps': 'h454-linux-personal-yfc-'}


def pending(conn: sqlite3.Connection, target: str, user_code: str, now_ms: int) -> sqlite3.Row:
    if (type(target) is not str or target not in NAMES or
        type(user_code) is not str or CODE.fullmatch(user_code) is None or type(now_ms) is not int):
        raise PairDenied('H454_NATIVE_PAIR_SCOPE_DENIED')
    rows = conn.execute('SELECT * FROM device_codes WHERE user_code=?', (user_code,)).fetchall()
    if len(rows) != 1:
        raise PairDenied('H454_NATIVE_PAIR_NOT_UNIQUE')
    row = rows[0]
    if (row['client_name'] != NAMES[target] or row['approved'] != 0 or row['denied'] != 0 or
        row['user_id'] is not None or row['device_id'] not in (None, '') or
        type(row['created_at']) is not int or type(row['expires_at']) is not int or
        row['created_at'] > now_ms or row['expires_at'] <= now_ms + 20_000 or
        not 0 < row['expires_at'] - row['created_at'] <= MAX_TTL_MS):
        raise PairDenied('H454_NATIVE_PAIR_NOT_PENDING')
    return row


def approve(conn: sqlite3.Connection, *, target: str, user_code: str, original: sqlite3.Row,
            new_hex: str, now_ms: int) -> str:
    """Compare and set one still-pending row, requiring the unique owner."""
    try:
        if (type(target) is not str or target not in PREFIX or type(new_hex) is not str or
            len(new_hex) != 32 or any(ch not in '0123456789abcdef' for ch in new_hex)):
            raise ValueError()
        device_id = PREFIX[target] + new_hex
        if IDENTITIES[target].fullmatch(device_id) is None:
            raise ValueError()
        conn.execute('BEGIN IMMEDIATE')
        owner = _owner(conn)
        row = pending(conn, target, user_code, now_ms)
        if any(original[field] != row[field] for field in ('device_code', 'created_at', 'expires_at')):
            raise ValueError()
        if conn.execute('SELECT count(*) FROM devices WHERE name=? OR device_id=?',
                        (NAMES[target], device_id)).fetchone()[0] != 0:
            raise ValueError()
        if conn.execute('SELECT count(*) FROM device_codes WHERE client_name=? AND device_code<>? '
                        'AND approved=0 AND denied=0 AND expires_at>?',
                        (NAMES[target], row['device_code'], now_ms)).fetchone()[0] != 0:
            raise ValueError()
        changed = conn.execute(
            'UPDATE device_codes SET approved=1,user_id=?,device_id=? '
            'WHERE device_code=? AND user_code=? AND client_name=? AND approved=0 AND denied=0 '
            "AND user_id IS NULL AND (device_id IS NULL OR device_id='') AND created_at<=? AND expires_at>?",
            (owner, device_id, row['device_code'], user_code, NAMES[target], now_ms, now_ms + 20_000))
        if changed.rowcount != 1:
            raise ValueError()
        bound = conn.execute('SELECT approved,user_id,device_id FROM device_codes WHERE device_code=?',
                             (row['device_code'],)).fetchone()
        if bound is None or tuple(bound) != (1, owner, device_id):
            raise ValueError()
        conn.execute('COMMIT')
        return device_id
    except Exception:
        if conn.in_transaction:
            conn.execute('ROLLBACK')
        raise PairDenied('H454_NATIVE_PAIR_DENIED') from None
