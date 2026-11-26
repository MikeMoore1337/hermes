"""Owner-scoped configuration for a separate personal Windows Commander.

This module only prepares and parses an in-memory configuration. It does not
pair a device, install a process, read project files, or connect to a relay.
The process using it has the Windows owner's ordinary OS permissions.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from typing import Callable

from device_fabric.native_brc_enrollment import TOKEN, Paired
from device_fabric.native_install_preview import WINDOWS_ROOTS
from device_fabric.windows_personal_commander_enrollment import DEVICE, TARGET
from device_fabric.windows_native_dpapi import (
    MAX_CIPHERTEXT, seal_personal_commander, unseal_personal_commander,
)
from device_fabric.windows_personal_session import SHA40, SHA64, SID

SCHEMA = "h454-windows-personal-commander-v1"
MAX_CONFIG_BYTES = 8192
PERSONAL_ROOTS = {name: WINDOWS_ROOTS[name] for name in
                  ("hermes", "your-fitness-coach", "financial-horizon")}
FIELDS = frozenset({"schema", "release_sha", "owner_sid", "ca_sha256",
                    "bundle_sha256", "device_id", "sealed_bearer_b64", "created_at"})


class PersonalCommanderDenied(ValueError):
    """Sanitized denial without paths, credentials or Windows error text."""


@dataclass(frozen=True, slots=True, repr=False)
class PersonalCommanderConfig:
    release_sha: str
    owner_sid: str
    ca_sha256: str
    bundle_sha256: str
    device_id: str
    sealed_bearer: bytes
    created_at: int

    def __repr__(self) -> str:
        return "PersonalCommanderConfig([REDACTED])"


def _encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PersonalCommanderDenied("personal_commander_denied")
        result[key] = value
    return result


def policy_digest(ca_sha256: str, bundle_sha256: str) -> str:
    if (type(ca_sha256) is not str or SHA64.fullmatch(ca_sha256) is None
        or type(bundle_sha256) is not str or SHA64.fullmatch(bundle_sha256) is None):
        raise PersonalCommanderDenied("personal_commander_denied")
    return hashlib.sha256(_encode({"schema": SCHEMA, "access": "PERSONAL_WRITE_PROCESS",
        "roots": PERSONAL_ROOTS, "ca_sha256": ca_sha256,
        "bundle_sha256": bundle_sha256})).hexdigest()


def prepare_config(paired: Paired, *, owner_sid: str, release_sha: str,
                   ca: bytes, bundle_sha256: str, now: int,
                   seal: Callable[..., bytes] = seal_personal_commander) -> bytes:
    """Bind a newly paired personal bearer to owner, code, CA and roots."""
    try:
        if (type(paired) is not Paired or paired.target != TARGET
            or type(paired.device_id) is not str
            or DEVICE.fullmatch(paired.device_id) is None
            or type(paired.token) is not str or TOKEN.fullmatch(paired.token) is None
            or paired.ws_url not in ("wss://mcp.mikemoore.top/ws", "wss://hermes.mikemoore.top/ws")
            or type(owner_sid) is not str or len(owner_sid) > 184 or SID.fullmatch(owner_sid) is None
            or type(release_sha) is not str or SHA40.fullmatch(release_sha) is None
            or type(ca) is not bytes or not 0 < len(ca) <= 8192
            or not ca.startswith(b"-----BEGIN CERTIFICATE-----")
            or not ca.rstrip().endswith(b"-----END CERTIFICATE-----")
            or ca.count(b"-----BEGIN CERTIFICATE-----") != 1
            or type(now) is not int or not 0 < now < 2**53 or not callable(seal)):
            raise ValueError()
        ca_hash = hashlib.sha256(ca).hexdigest()
        digest = policy_digest(ca_hash, bundle_sha256)
        sealed = seal(paired.token, manifest_sha256=digest, device_id=paired.device_id)
        if type(sealed) is not bytes or not 32 <= len(sealed) <= MAX_CIPHERTEXT:
            raise ValueError()
        raw = _encode({"schema": SCHEMA, "release_sha": release_sha, "owner_sid": owner_sid,
            "ca_sha256": ca_hash, "bundle_sha256": bundle_sha256, "device_id": paired.device_id,
            "sealed_bearer_b64": base64.b64encode(sealed).decode("ascii"), "created_at": now})
        parse_config(raw)
        return raw
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None


def parse_config(raw: bytes) -> PersonalCommanderConfig:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONFIG_BYTES:
            raise ValueError()
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(obj) is not dict or set(obj) != FIELDS or obj["schema"] != SCHEMA
            or type(obj["release_sha"]) is not str or SHA40.fullmatch(obj["release_sha"]) is None
            or type(obj["owner_sid"]) is not str or len(obj["owner_sid"]) > 184
            or SID.fullmatch(obj["owner_sid"]) is None
            or type(obj["device_id"]) is not str
            or DEVICE.fullmatch(obj["device_id"]) is None
            or type(obj["sealed_bearer_b64"]) is not str
            or type(obj["created_at"]) is not int or not 0 < obj["created_at"] < 2**53
            or _encode(obj) != raw):
            raise ValueError()
        policy_digest(obj["ca_sha256"], obj["bundle_sha256"])
        sealed = base64.b64decode(obj["sealed_bearer_b64"], validate=True)
        if not 32 <= len(sealed) <= MAX_CIPHERTEXT:
            raise ValueError()
        return PersonalCommanderConfig(obj["release_sha"], obj["owner_sid"], obj["ca_sha256"],
            obj["bundle_sha256"], obj["device_id"], sealed, obj["created_at"])
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None


def unseal(config: PersonalCommanderConfig, *, owner_sid: str, ca: bytes,
           bundle_sha256: str, decrypt: Callable[..., str] = unseal_personal_commander) -> str:
    """Refuse credential use if the actual owner, CA or installed bundle differ."""
    try:
        if (type(config) is not PersonalCommanderConfig
            or type(owner_sid) is not str or len(owner_sid) > 184 or SID.fullmatch(owner_sid) is None
            or owner_sid != config.owner_sid
            or type(config.release_sha) is not str or SHA40.fullmatch(config.release_sha) is None
            or type(config.device_id) is not str or DEVICE.fullmatch(config.device_id) is None
            or type(config.created_at) is not int or not 0 < config.created_at < 2**53
            or type(config.sealed_bearer) is not bytes
            or not 32 <= len(config.sealed_bearer) <= MAX_CIPHERTEXT
            or type(ca) is not bytes or hashlib.sha256(ca).hexdigest() != config.ca_sha256
            or type(bundle_sha256) is not str or bundle_sha256 != config.bundle_sha256
            or not callable(decrypt)):
            raise ValueError()
        bearer = decrypt(config.sealed_bearer,
            manifest_sha256=policy_digest(config.ca_sha256, config.bundle_sha256),
            device_id=config.device_id)
        if type(bearer) is not str or TOKEN.fullmatch(bearer) is None:
            raise ValueError()
        return bearer
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None
