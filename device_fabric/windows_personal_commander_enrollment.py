"""Separate owner-bound pairing for the personal Windows Commander.

The existing READ-only enrollment module remains byte-for-byte pinned. This
client does not approve codes, persist a credential, or start an agent.
"""
from __future__ import annotations

import json
import re
import time
from typing import Callable

from device_fabric.native_brc_enrollment import (
    DEVICE_CODE, MAX_INTERVAL, MAX_POLLS, MAX_TTL, TOKEN, USER_CODE,
    EnrollmentDenied, Paired, Pending, _json, _verified_ws_uri,
)

TARGET = "windows-personal"
NAME = "H454 Windows personal Commander"
DEVICE = re.compile(r"h454-win-personal-[0-9a-f]{32}\Z")


def start(*, post: Callable[[str, bytes], tuple[int, bytes]]) -> Pending:
    """Request one fresh code; the authenticated owner binds its device ID."""
    try:
        if not callable(post):
            raise ValueError()
        status, raw = post("/device/start", json.dumps({"client_name": NAME},
                           separators=(",", ":")).encode("ascii"))
        data = _json(raw)
        if (status != 200 or set(data) != {"device_code", "user_code", "verification_uri",
                "verification_uri_complete", "expires_in", "interval"}
            or type(data["device_code"]) is not str or DEVICE_CODE.fullmatch(data["device_code"]) is None
            or type(data["user_code"]) is not str or USER_CODE.fullmatch(data["user_code"]) is None
            or type(data["expires_in"]) is not int or not 30 <= data["expires_in"] <= MAX_TTL
            or type(data["interval"]) is not int or not 1 <= data["interval"] <= MAX_INTERVAL
            or type(data["verification_uri"]) is not str
            or type(data["verification_uri_complete"]) is not str):
            raise ValueError()
        return Pending(TARGET, data["device_code"], data["user_code"],
                       data["interval"], data["expires_in"])
    except Exception:
        raise EnrollmentDenied("native_enrollment_denied") from None


def poll(pending: Pending, *, post: Callable[[str, bytes], tuple[int, bytes]],
         expected_ws_url: str, sleep: Callable[[float], object] = time.sleep,
         monotonic: Callable[[], float] = time.monotonic) -> Paired:
    """Poll without an agent-supplied ID and accept only the new profile."""
    try:
        if (type(pending) is not Pending or pending.target != TARGET
            or type(pending.device_code) is not str or DEVICE_CODE.fullmatch(pending.device_code) is None
            or type(pending.user_code) is not str or USER_CODE.fullmatch(pending.user_code) is None
            or type(pending.interval) is not int or not 1 <= pending.interval <= MAX_INTERVAL
            or type(pending.expires_in) is not int or not 30 <= pending.expires_in <= MAX_TTL
            or not callable(post) or not callable(sleep) or not callable(monotonic)
            or not _verified_ws_uri(expected_ws_url)):
            raise ValueError()
        deadline = monotonic() + pending.expires_in
        for _ in range(MAX_POLLS):
            if deadline - monotonic() <= 0:
                break
            request = json.dumps({"device_code": pending.device_code, "name": NAME,
                                  "platform": "win32"}, separators=(",", ":")).encode("ascii")
            status, raw = post("/device/poll", request)
            data = _json(raw)
            if status == 400 and data.get("error") == "authorization_pending":
                if (set(data) - {"error", "interval"} or type(data.get("interval")) is not int
                    or not 1 <= data["interval"] <= MAX_INTERVAL):
                    raise ValueError()
                delay = max(pending.interval, data["interval"])
                if delay >= deadline - monotonic():
                    break
                sleep(delay)
                continue
            if (status != 200 or set(data) != {"device_token", "device_id", "token_type", "ws_url"}
                or type(data["device_id"]) is not str or DEVICE.fullmatch(data["device_id"]) is None
                or type(data["device_token"]) is not str or TOKEN.fullmatch(data["device_token"]) is None
                or data["token_type"] != "bearer" or data["ws_url"] != expected_ws_url):
                raise ValueError()
            return Paired(TARGET, data["device_id"], data["device_token"], data["ws_url"])
        raise ValueError()
    except Exception:
        raise EnrollmentDenied("native_enrollment_denied") from None
