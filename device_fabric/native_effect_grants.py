"""Dormant, cross-platform, one-operation native effect authorization contract.

The authenticated relay must independently verify an explicit owner approval
before signing. An agent must verify this envelope, check device revocation and
OS-enforced workspace confinement, and durably claim the operation ID before
executing any effect. This module deliberately executes no effect or network I/O.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import time
import unicodedata
from typing import Any

SCHEMA = "h454-native-effect-v1"
MAX_ENVELOPE_BYTES = 4096
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_GRANT_SECONDS = 600
ACTIONS = frozenset({"file_write", "file_edit", "file_delete", "process_run"})
DEVICE = re.compile(r"[a-z][a-z0-9_-]{1,39}\Z")
PROJECT = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WINDOWS_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?\Z", re.I)
BLOCKED_NAMES = frozenset({".git", ".ssh", ".aws", ".gnupg", ".kube", "vault", ".vault", "private-vault", "secrets", ".secrets", "credentials", ".env", ".env.local", ".env.production"})
BLOCKED_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".kdbx")
SENSITIVE_STEM = re.compile(r"^\.?(?:secrets?|credentials?|tokens?|passwords?|api[-_]?keys?|service[-_]?accounts?|private[-_]?keys?|config[._-]local)(?:[._-]|$)", re.I)
FIELDS = frozenset({"schema", "device_id", "project", "operation_id", "action", "relative", "payload_sha256", "expires_at"})
DOMAIN = b"hermes-native-effect-v1\x00"


class GrantDenied(ValueError):
    """Sanitized denial; never echo paths, commands, payloads or credentials."""


@dataclass(frozen=True, slots=True)
class NativeEffect:
    schema: str
    device_id: str
    project: str
    operation_id: str
    action: str
    relative: str
    payload_sha256: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class VerifiedEffect:
    effect: NativeEffect
    scope_sha256: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise GrantDenied("native_grant_denied")
        obj[key] = value
    return obj


def _validate_relative(relative: str, *, action: str) -> None:
    if type(relative) is not str or unicodedata.normalize("NFC", relative) != relative:
        raise GrantDenied("native_grant_denied")
    try:
        length = len(relative.encode("utf-8"))
    except UnicodeError as exc:
        raise GrantDenied("native_grant_denied") from exc
    if length > 1024 or (action == "process_run") != (relative == ""):
        raise GrantDenied("native_grant_denied")
    if action == "process_run":
        return
    if relative.startswith("/") or "\\" in relative:
        raise GrantDenied("native_grant_denied")
    for part in relative.split("/"):
        low = part.casefold()
        if (not part or part in {".", ".."} or part.endswith((" ", "."))
            or any(c in '<>:"|?*' or unicodedata.category(c).startswith("C") for c in part)
            or WINDOWS_DEVICE.fullmatch(part) or low in BLOCKED_NAMES
            or low.startswith(".env.") or SENSITIVE_STEM.match(part)
            or low.endswith(BLOCKED_SUFFIXES)):
            raise GrantDenied("native_grant_denied")


def _validate(effect: NativeEffect, now: int) -> None:
    if (type(effect) is not NativeEffect or type(now) is not int
        or effect.schema != SCHEMA
        or type(effect.device_id) is not str or not DEVICE.fullmatch(effect.device_id)
        or type(effect.project) is not str or not PROJECT.fullmatch(effect.project)
        or type(effect.operation_id) is not str or not UUID4.fullmatch(effect.operation_id)
        or type(effect.action) is not str or effect.action not in ACTIONS
        or type(effect.payload_sha256) is not str or not HEX64.fullmatch(effect.payload_sha256)
        or type(effect.expires_at) is not int
        or not now <= effect.expires_at <= now + MAX_GRANT_SECONDS):
        raise GrantDenied("native_grant_denied")
    _validate_relative(effect.relative, action=effect.action)


def _scope(effect: NativeEffect) -> bytes:
    return json.dumps(asdict(effect), sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _mac(key: bytes, scope: bytes) -> str:
    if type(key) is not bytes or not 32 <= len(key) <= 128:
        raise GrantDenied("native_grant_denied")
    return hmac.new(key, DOMAIN + scope, hashlib.sha256).hexdigest()


def sign_envelope(effect: NativeEffect, *, issuer_key: bytes,
                  now: int | None = None) -> bytes:
    """Trusted relay only, AFTER independently recorded one-action owner consent.

    No caller-supplied approved=True field or MCP operation may invoke issuance.
    Keys must be per-device and protected in separately provisioned storage.
    """
    timestamp = int(time.time()) if now is None else now
    _validate(effect, timestamp)
    scope = _scope(effect)
    mac = _mac(issuer_key, scope)
    return json.dumps({"effect": asdict(effect), "mac": mac},
                      sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def verify_envelope(frame: bytes, payload: bytes, *, verifier_key: bytes,
                    expected_device_id: str, allowed_projects: frozenset[str],
                    now: int | None = None) -> VerifiedEffect:
    """Verify a single signed scope and the EXACT opaque effect payload.

    The authenticated agent must additionally reject revoked devices/grants,
    verify OS-level confinement and atomically reserve operation_id in durable
    storage BEFORE executing anything. This function is not an execution gate.
    """
    if (type(frame) is not bytes or not 0 < len(frame) <= MAX_ENVELOPE_BYTES
        or type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES
        or type(expected_device_id) is not str
        or type(allowed_projects) is not frozenset):
        raise GrantDenied("native_grant_denied")
    try:
        parsed = json.loads(frame.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GrantDenied("native_grant_denied") from exc
    if (type(parsed) is not dict or set(parsed) != {"effect", "mac"}
        or type(parsed["effect"]) is not dict or set(parsed["effect"]) != FIELDS
        or type(parsed["mac"]) is not str or not HEX64.fullmatch(parsed["mac"])):
        raise GrantDenied("native_grant_denied")
    effect = NativeEffect(**parsed["effect"])
    timestamp = int(time.time()) if now is None else now
    _validate(effect, timestamp)
    if (effect.device_id != expected_device_id or effect.project not in allowed_projects
        or not hmac.compare_digest(effect.payload_sha256, hashlib.sha256(payload).hexdigest())
        or not hmac.compare_digest(parsed["mac"], _mac(verifier_key, _scope(effect)))):
        raise GrantDenied("native_grant_denied")
    return VerifiedEffect(effect, hashlib.sha256(_scope(effect)).hexdigest())
