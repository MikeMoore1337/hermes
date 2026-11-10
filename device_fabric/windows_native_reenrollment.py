"""H454 Stage 2A: candidate for a NEW original-Windows read-only identity.

Pure source-only composition of the already tested handle-bound Win32 reader
and BRC outbound wire. This is NOT enrollment, a service, an installer, an
approval UI or permission to execute on the owner's Windows PC.

A trusted future installer must verify actual Windows service SID/ACLs, protect
the private DPAPI state and obtain a fresh owner-paired bearer. None of those
controls can be replaced with data supplied by an MCP request.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import sys
import time
from typing import Any, Callable

from device_fabric.native_install_preview import (
    InstallPlanDenied, SERVICE, WINDOWS_ROOTS, parse_candidate,
)
from scripts import h15_native_windows_outbound as outbound

SCHEMA = "h454-new-win32-read-session-v1"
RELAY = "wss://hermes.mikemoore.top/ws"
REVOKED_LEGACY_ID = "h454-win-01335a1f6e6705b4"
NEW_ID = re.compile(r"h454-win-native-[0-9a-f]{32}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_CONFIG_BYTES = 8192
MAX_SEALED_BYTES = 4096
MAX_BEARER_LIFETIME_SECONDS = 3600
EXPECTED_KEYS = frozenset({
    "schema", "target", "release_sha", "manifest_sha256",
    "device_id", "relay_url", "sealed_bearer_b64", "expires_at",
})


class WindowsNativeIdentityDenied(ValueError):
    """Sanitized refusal, never containing owner token, paths or host errors."""


@dataclass(frozen=True, slots=True, repr=False)
class PrivateWindowsSession:
    """Untrusted until future owner-only OS/relay controls verify it."""

    release_sha: str
    manifest_sha256: str
    device_id: str
    relay_url: str
    sealed_bearer: bytes
    expires_at: int

    def __repr__(self) -> str:
        return "PrivateWindowsSession([REDACTED])"


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")
        result[name] = value
    return result


def parse_local_session(
    manifest: bytes,
    config: bytes,
    *,
    expected_release: str,
    expected_manifest_sha256: str,
) -> PrivateWindowsSession:
    """Parse two *locally protected* snapshots, never remote MCP arguments.

    Parsing checks neither an owner's identity nor a Windows ACL. The future
    installer MUST independently supply and verify the expected hash and
    authenticated pairing and must not accept either as a client argument.
    """
    try:
        if (type(manifest) is not bytes or type(config) is not bytes
            or not 0 < len(config) <= MAX_CONFIG_BYTES
            or type(expected_release) is not str
            or SHA40.fullmatch(expected_release) is None
            or type(expected_manifest_sha256) is not str
            or SHA64.fullmatch(expected_manifest_sha256) is None
            or not hmac.compare_digest(
                hashlib.sha256(manifest).hexdigest(),
                expected_manifest_sha256)):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")

        candidate = parse_candidate(
            manifest, expected_release=expected_release,
            expected_target="windows",
        )
        if (candidate.service_name, candidate.service_identity) != SERVICE["windows"]
            or candidate.roots != tuple(sorted(WINDOWS_ROOTS.items()))):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")

        fields = json.loads(
            config.decode("ascii"), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (type(fields) is not dict or set(fields) != EXPECTED_KEYS
            or type(fields["schema"]) is not str or fields["schema"] != SCHEMA
            or type(fields["target"]) is not str or fields["target"] != "windows"
            or type(fields["release_sha"]) is not str
            or fields["release_sha"] != expected_release
            or type(fields["manifest_sha256"]) is not str
            or fields["manifest_sha256"] != expected_manifest_sha256
            or type(fields["device_id"]) is not str
            or NEW_ID.fullmatch(fields["device_id"]) is None
            or fields["device_id"] == REVOKED_LEGACY_ID
            or type(fields["relay_url"]) is not str
            or fields["relay_url"] != RELAY
            or type(fields["sealed_bearer_b64"]) is not str
            or type(fields["expires_at"]) is not int
            or fields["expires_at"] <= 0):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")

        if (json.dumps(fields, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode("ascii")
            != config):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")

        sealed = base64.b64decode(fields["sealed_bearer_b64"], validate=True)
        if not 32 <= len(sealed) <= MAX_SEALED_BYTES:
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")
        return PrivateWindowsSession(
            expected_release, expected_manifest_sha256, fields["device_id"],
            RELAY, sealed, fields["expires_at"],
        )
    except Exception:
        raise WindowsNativeIdentityDenied("native_win32_identity_denied") from None


def _strict_gate(
    candidate: PrivateWindowsSession,
    *,
    service_os_verified: Callable[[], bool],
    owner_pair_verified: Callable[[], bool],
    is_device_revoked: Callable[[], bool],
    utcnow: Callable[[], float],
) -> None:
    """All callbacks must originate from a future trusted local operator."""
    try:
        now = utcnow()
        if (type(candidate) is not PrivateWindowsSession
            or sys.platform != "win32"
            or type(now) not in (int, float) or not math.isfinite(now)
            or not 0 < candidate.expires_at - now <= MAX_BEARER_LIFETIME_SECONDS
            or service_os_verified() is not True
            or owner_pair_verified() is not True
            or is_device_revoked() is not False):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")
    except Exception:
        raise WindowsNativeIdentityDenied("native_win32_identity_denied") from None


class _GuardedSocket:
    """Recheck local revocation, OS identity and expiry on each wire IO."""

    def __init__(self, socket: Any, gate: Callable[[], None]) -> None:
        self._socket = socket
        self._gate = gate
        self._active: Any = None

    def __enter__(self) -> "_GuardedSocket":
        self._gate()
        self._active = self._socket.__enter__()
        self._gate()
        return self

    def __exit__(self, *args: Any) -> object:
        return self._socket.__exit__(*args)

    def send(self, message: str) -> None:
        self._gate()
        self._active.send(message)

    def recv(self, timeout: float | None = None) -> str | bytes:
        self._gate()
        result = self._active.recv(timeout=timeout)
        self._gate()
        return result


def run_once(
    candidate: PrivateWindowsSession,
    *,
    connector: Callable[..., Any],
    service_os_verified: Callable[[], bool],
    owner_pair_verified: Callable[[], bool],
    is_device_revoked: Callable[[], bool],
    unseal_bearer: Callable[[bytes], str],
    utcnow: Callable[[], float] = time.time,
) -> str:
    """A single future host session, deliberately NOT exposed as CLI/service.

    A sealed bearer cannot prove DPAPI protection or an owner-approved relay
    registration by itself. Only trusted installer/runtime callbacks can.
    The existing outbound module performs bounded native READ calls only.
    """
    if (not all(callable(x) for x in (
        connector, service_os_verified, owner_pair_verified,
        is_device_revoked, unseal_bearer, utcnow,
    )) or type(candidate) is not PrivateWindowsSession):
        raise WindowsNativeIdentityDenied("native_win32_identity_denied")

    def gate() -> None:
        _strict_gate(
            candidate, service_os_verified=service_os_verified,
            owner_pair_verified=owner_pair_verified,
            is_device_revoked=is_device_revoked, utcnow=utcnow,
        )

    try:
        gate()
        token = unseal_bearer(candidate.sealed_bearer)
        if (type(token) is not str
            or not 40 <= len(token) <= 256
            or outbound.TOKEN.fullmatch(token) is None):
            raise WindowsNativeIdentityDenied("native_win32_identity_denied")
        gate()
        settings = outbound.Settings(candidate.relay_url, candidate.device_id, token)

        def restricted_connector(*args: Any, **kwargs: Any) -> _GuardedSocket:
            gate()
            return _GuardedSocket(connector(*args, **kwargs), gate)

        return outbound.run_session(settings, restricted_connector)
    except Exception:
        # A DPAPI, transport or kernel exception might contain token/path data.
        raise WindowsNativeIdentityDenied("native_win32_identity_denied") from None
