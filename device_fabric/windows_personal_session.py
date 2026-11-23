"""Personal Windows READ session using the owner's Windows/DPAPI identity.

The owner has the same OS permissions as this process. Path restrictions are
enforced by the existing native READ broker, not by Windows isolation.
This module does not install, pair, launch, or persist credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any, Callable

from device_fabric.native_brc_status import PUBLIC, status_provider
from device_fabric.native_brc_enrollment import Paired, TOKEN
from device_fabric.native_install_preview import WINDOWS_ROOTS
from device_fabric.windows_native_dpapi import seal_for_current_user, unseal_for_current_user
from device_fabric.windows_native_reenrollment import (
    NEW_ID, MAX_CONFIG_BYTES, MAX_SEALED_BYTES, PrivateWindowsSession, RELAY, run_once,
)

SCHEMA = "h454-personal-windows-session-v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+){1,15}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
KEYS = {"schema", "release_sha", "owner_sid", "ca_sha256", "device_id", "sealed_bearer_b64", "expires_at"}


class PersonalSessionDenied(ValueError):
    """Sanitized denial without credentials or original paths."""


def policy_digest(ca_sha256: str) -> str:
    if type(ca_sha256) is not str or SHA64.fullmatch(ca_sha256) is None:
        raise PersonalSessionDenied("personal_windows_denied")
    policy = {"schema": SCHEMA, "access": "READ_ONLY", "roots": WINDOWS_ROOTS,
              "ca_sha256": ca_sha256}
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def prepare_config(paired: Paired, *, owner_sid: str, release_sha: str,
                   ca: bytes, now: int,
                   seal: Callable[..., bytes] = seal_for_current_user) -> bytes:
    """Encrypt a freshly owner-paired bearer in memory, never into argv/logs."""
    try:
        if (type(paired) is not Paired or paired.target != "windows"
            or type(paired.device_id) is not str or NEW_ID.fullmatch(paired.device_id) is None
            or type(paired.token) is not str or TOKEN.fullmatch(paired.token) is None
            or paired.ws_url not in ("wss://mcp.mikemoore.top/ws", RELAY)
            or type(owner_sid) is not str or len(owner_sid) > 184 or SID.fullmatch(owner_sid) is None
            or type(release_sha) is not str or SHA40.fullmatch(release_sha) is None
            or type(ca) is not bytes or not 0 < len(ca) <= 8192
            or not ca.startswith(b"-----BEGIN CERTIFICATE-----")
            or not ca.rstrip().endswith(b"-----END CERTIFICATE-----")
            or ca.count(b"-----BEGIN CERTIFICATE-----") != 1
            or type(now) is not int or now < 1 or not callable(seal)):
            raise ValueError()
        ca_hash = hashlib.sha256(ca).hexdigest()
        sealed = seal(paired.token, manifest_sha256=policy_digest(ca_hash), device_id=paired.device_id)
        if type(sealed) is not bytes or not 32 <= len(sealed) <= MAX_SEALED_BYTES:
            raise ValueError()
        config = {"schema": SCHEMA, "release_sha": release_sha, "owner_sid": owner_sid,
                  "ca_sha256": ca_hash, "device_id": paired.device_id,
                  "sealed_bearer_b64": base64.b64encode(sealed).decode("ascii"),
                  "expires_at": now + 3600}
        raw = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        parse_config(raw)
        return raw
    except Exception:
        raise PersonalSessionDenied("personal_windows_denied") from None


def parse_config(raw: bytes) -> tuple[PrivateWindowsSession, str, str]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONFIG_BYTES:
            raise ValueError()
        obj = json.loads(raw.decode("ascii"))
        if (type(obj) is not dict or set(obj) != KEYS or obj["schema"] != SCHEMA
            or type(obj["release_sha"]) is not str or SHA40.fullmatch(obj["release_sha"]) is None
            or type(obj["owner_sid"]) is not str or len(obj["owner_sid"]) > 184
            or SID.fullmatch(obj["owner_sid"]) is None
            or type(obj["ca_sha256"]) is not str or SHA64.fullmatch(obj["ca_sha256"]) is None
            or type(obj["device_id"]) is not str or NEW_ID.fullmatch(obj["device_id"]) is None
            or type(obj["sealed_bearer_b64"]) is not str or type(obj["expires_at"]) is not int
            or obj["expires_at"] <= 0
            or json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") != raw):
            raise ValueError()
        sealed = base64.b64decode(obj["sealed_bearer_b64"], validate=True)
        if not 32 <= len(sealed) <= MAX_SEALED_BYTES:
            raise ValueError()
        return (PrivateWindowsSession(obj["release_sha"], policy_digest(obj["ca_sha256"]), obj["device_id"],
                                      RELAY, sealed, obj["expires_at"]), obj["owner_sid"], obj["ca_sha256"])
    except Exception:
        raise PersonalSessionDenied("personal_windows_denied") from None


def run(config: bytes, *, user_verified: Callable[[], str], connector: Callable[..., Any],
        unseal: Callable[..., str] = unseal_for_current_user,
        owner_status: Callable[..., Callable[[], bool]] = status_provider,
        utcnow: Callable[[], float] = time.time) -> str:
    """Use DPAPI and live owner status with existing per-I/O READ safeguards."""
    try:
        candidate, owner_sid, _ca_sha256 = parse_config(config)
        if user_verified() != owner_sid:
            raise ValueError()
        # Keep the existing one-hour maximum before decrypting the bearer.
        now = utcnow()
        if type(now) not in (int, float) or not 0 < candidate.expires_at - now <= 3600:
            raise ValueError()
        token = unseal(candidate.sealed_bearer, manifest_sha256=candidate.manifest_sha256,
                       device_id=candidate.device_id)
        active = owner_status(target="windows", device_id=candidate.device_id,
                              bearer=token, base_url=PUBLIC)
        if not callable(active) or active() is not True:
            raise ValueError()
        return run_once(candidate, connector=connector, service_os_verified=lambda: user_verified() == owner_sid,
                        owner_pair_verified=active, is_device_revoked=lambda: active() is not True,
                        unseal_bearer=lambda value: token if value == candidate.sealed_bearer else "",
                        utcnow=utcnow, bounded_reconnect=True)
    except Exception:
        raise PersonalSessionDenied("personal_windows_denied") from None
