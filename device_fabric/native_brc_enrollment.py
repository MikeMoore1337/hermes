"""Hermes #454: owner-bound native BRC /device/start + /device/poll client.

Uses the EXISTING relay's device-code pairing protocol, not a new MCP server.
Owner approval happens independently through the authenticated relay/owner
operator. The client supplies NO device_id to /device/poll: the relay must
return the exact fresh ID bound to the pending code by that owner.

This module does not save or log tokens, install services, open listeners,
or grant original-host filesystem/process access. An unverified local SSH
forward is NOT considered authenticated simply because it is loopback.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Callable, Any

NAME = {
    "windows": "H454 Windows native read-only",
    "hermes-vps": "H454 Hermes VPS native read-only",
    "yfc-vps": "H454 YFC VPS native read-only",
}
PLATFORM = {"windows": "win32", "hermes-vps": "linux", "yfc-vps": "linux"}
IDENTITY = {
    "windows": re.compile(r"h454-win-native-[a-f0-9]{32}\Z"),
    "hermes-vps": re.compile(r"h454-linux-hermes-[a-f0-9]{32}\Z"),
    "yfc-vps": re.compile(r"h454-linux-yfc-[a-f0-9]{32}\Z"),
}
OLD_WINDOWS = "h454-win-01335a1f6e6705b4"
TOKEN = re.compile(r"brc_dev_[A-Za-z0-9_-]{40,256}\Z")
DEVICE_CODE = re.compile(r"[A-Za-z0-9_-]{24,256}\Z")
USER_CODE = re.compile(r"[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}\Z")
MAX_BODY = 2048
MAX_POLLS = 90
MAX_INTERVAL = 20
MAX_TTL = 900


class EnrollmentDenied(ValueError):
    """Sanitized error - never surface HTTP response, token or code."""


@dataclass(frozen=True, slots=True, repr=False)
class Pending:
    target: str
    device_code: str
    user_code: str
    interval: int
    expires_in: int

    def __repr__(self) -> str:
        return "Pending([REDACTED])"


@dataclass(frozen=True, slots=True, repr=False)
class Paired:
    target: str
    device_id: str
    token: str
    ws_url: str

    def __repr__(self) -> str:
        return "Paired([REDACTED])"


def _unique(items):
    data = {}
    for key, value in items:
        if key in data:
            raise EnrollmentDenied("native_enrollment_denied")
        data[key] = value
    return data


def _json(raw: bytes) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY:
            raise EnrollmentDenied("native_enrollment_denied")
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(value) is not dict:
            raise EnrollmentDenied("native_enrollment_denied")
        return value
    except Exception:
        raise EnrollmentDenied("native_enrollment_denied") from None


def start(target: str, *, post: Callable[[str, bytes], tuple[int, bytes]]) -> Pending:
    """Start one relay-generated code (no device ID or token chosen by agent)."""
    try:
        if target not in NAME or not callable(post):
            raise EnrollmentDenied("native_enrollment_denied")
        status, body = post(
            "/device/start",
            json.dumps({"client_name": NAME[target]}, separators=(",", ":")).encode(),
        )
        result = _json(body)
        if (status != 200 or set(result) != {
            "device_code", "user_code", "verification_uri",
            "verification_uri_complete", "expires_in", "interval",
        } or type(result["device_code"]) is not str
            or DEVICE_CODE.fullmatch(result["device_code"]) is None
            or type(result["user_code"]) is not str
            or USER_CODE.fullmatch(result["user_code"]) is None
            or type(result["expires_in"]) is not int
            or not 30 <= result["expires_in"] <= MAX_TTL
            or type(result["interval"]) is not int
            or not 1 <= result["interval"] <= MAX_INTERVAL
            or type(result["verification_uri"]) is not str
            or type(result["verification_uri_complete"]) is not str):
            raise EnrollmentDenied("native_enrollment_denied")
        return Pending(target, result["device_code"], result["user_code"],
                       result["interval"], result["expires_in"])
    except Exception:
        raise EnrollmentDenied("native_enrollment_denied") from None


def poll(
    pending: Pending,
    *,
    post: Callable[[str, bytes], tuple[int, bytes]],
    sleep: Callable[[float], object] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    expected_ws_url: str,
) -> Paired:
    """Return owner-bound fresh ID/token in process memory. Never log them.

    The caller must authenticate the private relay and protect the token as
    the actual native service identity before allowing WSS connections.
    """
    try:
        if (type(pending) is not Pending or pending.target not in NAME
            or DEVICE_CODE.fullmatch(pending.device_code) is None
            or USER_CODE.fullmatch(pending.user_code) is None
            or not 1 <= pending.interval <= MAX_INTERVAL
            or not 30 <= pending.expires_in <= MAX_TTL
            or not callable(post) or not callable(sleep)
            or not callable(monotonic)
            or type(expected_ws_url) is not str
            or expected_ws_url not in (
                "wss://hermes.mikemoore.top/ws",
                "ws://127.0.0.1:38183/ws",
            )):
            raise EnrollmentDenied("native_enrollment_denied")
        deadline = monotonic() + pending.expires_in
        for _ in range(MAX_POLLS):
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            request = json.dumps({
                "device_code": pending.device_code,
                "name": NAME[pending.target],
                "platform": PLATFORM[pending.target],
                # CRITICAL: omit device_id; only the trusted owner operator
                # binds the new ID in device_codes before issuing bearer.
            }, separators=(",", ":")).encode("ascii")
            status, body = post("/device/poll", request)
            data = _json(body)
            if status == 400 and data.get("error") == "authorization_pending":
                if (set(data) - {"error", "interval"}
                    or type(data.get("interval")) is not int
                    or not 1 <= data["interval"] <= MAX_INTERVAL):
                    raise EnrollmentDenied("native_enrollment_denied")
                delay = max(pending.interval, data["interval"])
                if delay >= deadline - monotonic():
                    break
                sleep(delay)
                continue
            if (status != 200 or set(data) != {
                "device_token", "device_id", "token_type", "ws_url",
            } or type(data["device_id"]) is not str
                or IDENTITY[pending.target].fullmatch(data["device_id"]) is None
                or data["device_id"] == OLD_WINDOWS
                or type(data["device_token"]) is not str
                or TOKEN.fullmatch(data["device_token"]) is None
                or data["token_type"] != "bearer"
                or type(data["ws_url"]) is not str
                or data["ws_url"] != expected_ws_url):
                raise EnrollmentDenied("native_enrollment_denied")
            return Paired(pending.target, data["device_id"],
                          data["device_token"], data["ws_url"])
        raise EnrollmentDenied("native_enrollment_denied")
    except Exception:
        raise EnrollmentDenied("native_enrollment_denied") from None
