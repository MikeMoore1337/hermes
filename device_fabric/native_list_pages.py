"""Bounded stable pages over an already-authorized native directory listing."""
from __future__ import annotations

import hashlib
import json
import re

PAGE_SIZE = 64
SCAN_LIMIT = 256
_CURSOR = re.compile(r'(64|128|192):([a-f0-9]{64})\Z')


class NativePageDenied(ValueError):
    pass


def parse_cursor(cursor: str) -> tuple[int, str]:
    if type(cursor) is not str:
        raise NativePageDenied('native_page_denied')
    if not cursor:
        return 0, ''
    match = _CURSOR.fullmatch(cursor)
    if match is None:
        raise NativePageDenied('native_page_denied')
    return int(match.group(1)), match.group(2)


def validate_next(cursor: str, next_cursor: str, entries: list[object], truncated: bool) -> None:
    offset, fingerprint = parse_cursor(cursor)
    if type(next_cursor) is not str or type(truncated) is not bool or truncated != bool(next_cursor):
        raise NativePageDenied('native_page_denied')
    if next_cursor:
        new_offset, new_fingerprint = parse_cursor(next_cursor)
        if (new_offset != offset + PAGE_SIZE or len(entries) != PAGE_SIZE
            or (fingerprint and fingerprint != new_fingerprint)):
            raise NativePageDenied('native_page_denied')


def page(entries: list[dict[str, str]], project: str, relative: str,
         cursor: str) -> tuple[list[dict[str, str]], str]:
    """Return a page only if the visible directory has not changed.

    The caller must enumerate and authorize each entry independently. The
    fingerprint detects changed directory contents; it grants no access.
    Directories exceeding the existing scan limit remain denied by callers.
    """
    if (type(entries) is not list or len(entries) > SCAN_LIMIT
        or type(project) is not str or type(relative) is not str
        or type(cursor) is not str):
        raise NativePageDenied('native_page_denied')
    raw = json.dumps([project, relative, entries], ensure_ascii=True,
                     separators=(',', ':')).encode('ascii')
    fingerprint = hashlib.sha256(raw).hexdigest()
    offset, claimed = parse_cursor(cursor)
    if cursor:
        if claimed != fingerprint:
            raise NativePageDenied('native_page_denied')
        if offset >= len(entries):
            raise NativePageDenied('native_page_denied')
    end = min(offset + PAGE_SIZE, len(entries))
    next_cursor = f'{end}:{fingerprint}' if end < len(entries) else ''
    return entries[offset:end], next_cursor
