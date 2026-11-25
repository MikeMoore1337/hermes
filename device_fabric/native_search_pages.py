"""Stateless, bounded continuation for already-authorized native searches.

The adapter remains the sole authority for listing and reading paths. Cursors
are untrusted progress hints: every directory and file is reopened through the
adapter on every call, and changed directory pages or partial files fail closed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import unicodedata

from device_fabric.native_list_pages import parse_cursor as parse_list_cursor

MAX_CURSOR = 2048
MAX_ENTRIES = 512
MAX_MATCHES = 64
MAX_BYTES = 512 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_DIR_CALLS = 2
MAX_SECONDS = 4.0
MAX_DEPTH = 64
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9_-]+\Z')


class SearchPageDenied(ValueError):
    pass


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _name(name: object) -> bool:
    return (type(name) is str and bool(name) and len(name) <= 255
            and name not in ('.', '..') and '/' not in name and '\\' not in name
            and all(ord(c) >= 32 for c in name))


def _frame(name: str) -> dict:
    return {'n': name, 'c': '', 'i': 0, 'h': '', 'l': 0, 'f': ''}


def parse_search_cursor(cursor: str) -> dict | None:
    if type(cursor) is not str or len(cursor) > MAX_CURSOR:
        raise SearchPageDenied('native_search_page_denied')
    if not cursor:
        return None
    if _TOKEN.fullmatch(cursor) is None:
        raise SearchPageDenied('native_search_page_denied')
    try:
        raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
        state = json.loads(raw.decode('ascii'))
        if base64.urlsafe_b64encode(_json(state)).decode('ascii').rstrip('=') != cursor:
            raise ValueError()
        if (type(state) is not dict or set(state) != {'v', 'q', 's', 'o'}
                or type(state['v']) is not int or state['v'] != 1
                or type(state['o']) is not bool
                or type(state['q']) is not str or not _HEX.fullmatch(state['q'])
                or type(state['s']) is not list or not 1 <= len(state['s']) <= MAX_DEPTH + 1):
            raise ValueError()
        for frame in state['s']:
            if (type(frame) is not dict or set(frame) != {'n', 'c', 'i', 'h', 'l', 'f'}
                    or type(frame['n']) is not str or len(frame['n']) > 1024
                    or ('/' in frame['n'] and '\\' in frame['n'])
                    or (frame['n'] and not all(_name(part) for part in re.split(r'[/\\]', frame['n'])))
                    or type(frame['i']) is not int or not 0 <= frame['i'] <= 64
                    or type(frame['l']) is not int or not 0 <= frame['l'] <= MAX_FILE_BYTES
                    or type(frame['h']) is not str or (frame['h'] and not _HEX.fullmatch(frame['h']))
                    or type(frame['f']) is not str or (frame['f'] and not _HEX.fullmatch(frame['f']))
                    or bool(frame['l']) != bool(frame['f'])
                    or ((frame['i'] or frame['l']) and not frame['h'])):
                raise ValueError()
            parse_list_cursor(frame['c'])
        return state
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error, RecursionError):
        raise SearchPageDenied('native_search_page_denied') from None


def _encode(state: dict) -> str:
    cursor = base64.urlsafe_b64encode(_json(state)).decode('ascii').rstrip('=')
    if len(cursor) > MAX_CURSOR:
        raise SearchPageDenied('native_search_page_denied')
    return cursor


def search_page(*, project: str, query: str, mode: str, relative_root: str,
                cursor: str, separator: str, list_dir, stat_file, read_file) -> dict:
    if (type(project) is not str or type(query) is not str or type(mode) is not str
            or type(relative_root) is not str or separator not in ('/', '\\')
            or mode not in ('names', 'content') or not query.strip()
            or unicodedata.normalize('NFC', query) != query
            or len(query.encode('utf-8')) > 96
            or any(unicodedata.category(c).startswith('C') for c in query)):
        raise SearchPageDenied('native_search_page_denied')
    identity = _digest([project, query, mode, relative_root, separator])
    state = parse_search_cursor(cursor) or {'v': 1, 'q': identity, 's': [_frame('')], 'o': False}
    if state['q'] != identity:
        raise SearchPageDenied('native_search_page_denied')
    stack = state['s']
    if any((separator == '/' and '\\' in f['n']) or
           (separator == '\\' and '/' in f['n']) for f in stack):
        raise SearchPageDenied('native_search_page_denied')
    found = []
    entries_scanned = bytes_scanned = calls = 0
    deadline = time.monotonic() + MAX_SECONDS
    wanted = query.casefold()
    while stack and calls < MAX_DIR_CALLS and time.monotonic() < deadline:
        frame = stack[-1]
        directory = separator.join(part for part in (relative_root, frame['n']) if part)
        listing = list_dir(directory, frame['c'])
        calls += 1
        if (type(listing) is not dict or type(listing.get('entries')) is not list
                or len(listing['entries']) > 64 or type(listing.get('next_cursor')) is not str):
            raise SearchPageDenied('native_search_page_denied')
        fingerprint = _digest([listing['entries'], listing['next_cursor']])
        if frame['h'] and frame['h'] != fingerprint:
            raise SearchPageDenied('native_search_page_denied')
        frame['h'] = fingerprint
        if frame['i'] > len(listing['entries']):
            raise SearchPageDenied('native_search_page_denied')
        descend = False
        while frame['i'] < len(listing['entries']):
            if entries_scanned >= MAX_ENTRIES or len(found) >= MAX_MATCHES or time.monotonic() >= deadline:
                break
            entry = listing['entries'][frame['i']]
            if (type(entry) is not dict or set(entry) != {'name', 'kind'}
                    or not _name(entry['name']) or entry['kind'] not in ('file', 'directory')):
                raise SearchPageDenied('native_search_page_denied')
            path = directory + separator + entry['name'] if directory else entry['name']
            entries_scanned += 1
            if entry['kind'] == 'directory':
                if frame['l']:
                    raise SearchPageDenied('native_search_page_denied')
                if len(path.split(separator)) > MAX_DEPTH:
                    state['o'] = True
                    frame['i'] += 1
                    continue
                if mode == 'names' and wanted in entry['name'].casefold():
                    found.append({'path': path, 'kind': 'directory'})
                frame['i'] += 1
                child = separator.join(part for part in (frame['n'], entry['name']) if part)
                # Do not retain completed ancestors in a single-child chain.
                # This keeps deep paths usable without storing one digest per level.
                if frame['i'] == len(listing['entries']):
                    if listing['next_cursor']:
                        frame.update(c=listing['next_cursor'], i=0, h='', l=0, f='')
                    else:
                        stack.pop()
                stack.append(_frame(child))
                descend = True
                break
            if mode == 'names':
                if frame['l']:
                    raise SearchPageDenied('native_search_page_denied')
                if wanted in entry['name'].casefold():
                    found.append({'path': path, 'kind': 'file'})
            else:
                meta = stat_file(path)
                size = meta.get('size_bytes') if type(meta) is dict else None
                if type(size) is not int or size < 0:
                    raise SearchPageDenied('native_search_page_denied')
                if size > MAX_FILE_BYTES:
                    state['o'] = True
                    frame['i'] += 1
                    continue
                if bytes_scanned + size > MAX_BYTES:
                    break
                payload = read_file(path)
                try:
                    data = base64.b64decode(payload['data'], validate=True)
                    digest = hashlib.sha256(data).hexdigest()
                    if (payload['sha256'] != digest or len(data) != payload['size_bytes']
                            or len(data) > MAX_FILE_BYTES or bytes_scanned + len(data) > MAX_BYTES):
                        raise ValueError()
                except (KeyError, TypeError, ValueError, binascii.Error):
                    raise SearchPageDenied('native_search_page_denied') from None
                if frame['f'] and frame['f'] != digest:
                    raise SearchPageDenied('native_search_page_denied')
                bytes_scanned += len(data)
                try:
                    lines = [] if b'\x00' in data else data.decode('utf-8').splitlines()
                except UnicodeError:
                    lines = []
                start_line = frame['l']
                if start_line > len(lines):
                    raise SearchPageDenied('native_search_page_denied')
                frame['l'], frame['f'] = 0, ''
                for number in range(start_line + 1, len(lines) + 1):
                    if wanted in lines[number - 1].casefold():
                        found.append({'path': path, 'line': number})
                        if len(found) == MAX_MATCHES:
                            frame['l'], frame['f'] = number, digest
                            break
                if frame['l']:
                    break
            frame['i'] += 1
        if descend:
            continue
        if frame['i'] < len(listing['entries']):
            break
        if listing['next_cursor']:
            frame.update(c=listing['next_cursor'], i=0, h='', l=0, f='')
        else:
            stack.pop()
    following = _encode(state) if stack else ''
    if following and following == cursor and not found:
        raise SearchPageDenied('native_search_page_denied')
    return {'status': 'ok', 'project': project, 'relative_root': relative_root,
            'mode': mode, 'matches': found, 'truncated': bool(following),
            'entries_scanned': entries_scanned, 'bytes_scanned': bytes_scanned,
            'next_cursor': following, 'incomplete': state['o']}
