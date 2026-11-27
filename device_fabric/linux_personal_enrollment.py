"""Owner-bound enrollment for separate personal Linux Commander devices.

This client does not approve codes, persist credentials, or start services.
The caller supplies an independently verified relay transport.
"""
from __future__ import annotations

import json
import time
from typing import Callable

from device_fabric.native_brc_enrollment import (
    DEVICE_CODE, MAX_INTERVAL, MAX_POLLS, MAX_TTL, TOKEN, USER_CODE,
    EnrollmentDenied, Paired, Pending, _json, _verified_ws_uri,
)
from device_fabric.linux_personal_status import IDENTITIES

NAMES = {'hermes-vps': 'H454 Hermes VPS personal Commander',
         'yfc-vps': 'H454 YFC VPS personal Commander'}


def start(target: str, *, post: Callable[[str, bytes], tuple[int, bytes]]) -> Pending:
    try:
        if type(target) is not str or target not in NAMES or not callable(post):
            raise ValueError()
        request = json.dumps({'client_name': NAMES[target]}, separators=(',', ':')).encode('ascii')
        code, raw = post('/device/start', request)
        data = _json(raw)
        if (code != 200 or set(data) != {'device_code', 'user_code', 'verification_uri',
                'verification_uri_complete', 'expires_in', 'interval'}
            or type(data['device_code']) is not str or DEVICE_CODE.fullmatch(data['device_code']) is None
            or type(data['user_code']) is not str or USER_CODE.fullmatch(data['user_code']) is None
            or type(data['verification_uri']) is not str or type(data['verification_uri_complete']) is not str
            or type(data['expires_in']) is not int or not 30 <= data['expires_in'] <= MAX_TTL
            or type(data['interval']) is not int or not 1 <= data['interval'] <= MAX_INTERVAL):
            raise ValueError()
        return Pending(target, data['device_code'], data['user_code'], data['interval'], data['expires_in'])
    except Exception:
        raise EnrollmentDenied('native_enrollment_denied') from None


def poll(pending: Pending, *, post: Callable[[str, bytes], tuple[int, bytes]],
         expected_ws_url: str, sleep: Callable[[float], object] = time.sleep,
         monotonic: Callable[[], float] = time.monotonic) -> Paired:
    try:
        if (type(pending) is not Pending or pending.target not in NAMES or
            type(pending.device_code) is not str or DEVICE_CODE.fullmatch(pending.device_code) is None or
            type(pending.user_code) is not str or USER_CODE.fullmatch(pending.user_code) is None or
            type(pending.interval) is not int or not 1 <= pending.interval <= MAX_INTERVAL or
            type(pending.expires_in) is not int or not 30 <= pending.expires_in <= MAX_TTL or
            not all(callable(fn) for fn in (post, sleep, monotonic)) or not _verified_ws_uri(expected_ws_url)):
            raise ValueError()
        deadline = monotonic() + pending.expires_in
        for _ in range(MAX_POLLS):
            if deadline - monotonic() <= 0:
                break
            request = json.dumps({'device_code': pending.device_code, 'name': NAMES[pending.target],
                                  'platform': 'linux'}, separators=(',', ':')).encode('ascii')
            code, raw = post('/device/poll', request)
            data = _json(raw)
            if code == 400 and data.get('error') == 'authorization_pending':
                if (set(data) - {'error', 'interval'} or type(data.get('interval')) is not int or
                        not 1 <= data['interval'] <= MAX_INTERVAL):
                    raise ValueError()
                delay = max(pending.interval, data['interval'])
                if delay >= deadline - monotonic():
                    break
                sleep(delay)
                continue
            if (code != 200 or set(data) != {'device_token', 'device_id', 'token_type', 'ws_url'} or
                type(data['device_id']) is not str or IDENTITIES[pending.target].fullmatch(data['device_id']) is None or
                type(data['device_token']) is not str or TOKEN.fullmatch(data['device_token']) is None or
                data['token_type'] != 'bearer' or data['ws_url'] != expected_ws_url):
                raise ValueError()
            return Paired(pending.target, data['device_id'], data['device_token'], data['ws_url'])
        raise ValueError()
    except Exception:
        raise EnrollmentDenied('native_enrollment_denied') from None
