"""Dormant owner-approval ticket verifier and single-use native grant issuer.

This is a SOURCE-ONLY library for a future authenticated Hermes relay.
It has no owner login, HTTP/MCP endpoint, key provisioning, listener, file
or process effect, and does not approve actions from client booleans.

An INDEPENDENT owner-authenticated authority must sign a single exact
decision using a protected authority key after verifying a real UI consent.
A locally confined issuer verifies that decision, atomically consumes its
operation UUID in the existing persistent ledger, then signs one native
device effect with a separate per-device key. It never retries an ambiguous
issuance. The native device must ALSO enforce replay and OS restrictions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Callable

from device_fabric.native_effect_grants import (
    NativeEffect, GrantDenied, HEX64, UUID4, FIELDS,
    MAX_PAYLOAD_BYTES, _validate as validate_effect, sign_envelope,
)
from scripts import h15_native_effect_receipts as ledger

SCHEMA = "h454-owner-decision-v1"
DOMAIN = b"hermes-owner-decision-v1\x00"
MAX_TICKET_BYTES = 4096
MAX_APPROVAL_AGE = 600
OWNER_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")
TICKET_FIELDS = frozenset({"schema", "owner_id", "approved_at", "effect"})


class OwnerIssuerDenied(ValueError):
    """Generic denial without approval content, paths, device keys or tokens."""


@dataclass(frozen=True, slots=True)
class OwnerDecision:
    """Exact immutable operation accepted by an independent owner authority."""

    schema: str
    owner_id: str
    approved_at: int
    effect: NativeEffect


@dataclass(frozen=True, slots=True)
class LocalOwnerIssuerConfig:
    """Trusted LOCAL config; never deserialized from an MCP request."""

    state_directory: Path
    owner_id: str
    device_id: str
    projects: frozenset[str]
    authority_verifier_key: bytes
    device_issuer_key: bytes


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        output[key] = value
    return output


def _key(key: bytes) -> bytes:
    if type(key) is not bytes or not 32 <= len(key) <= 128:
        raise OwnerIssuerDenied("native_owner_issuer_denied")
    return key


def _check_decision(decision: OwnerDecision) -> None:
    if (type(decision) is not OwnerDecision or decision.schema != SCHEMA
        or type(decision.owner_id) is not str
        or OWNER_ID.fullmatch(decision.owner_id) is None
        or type(decision.approved_at) is not int
        or type(decision.effect) is not NativeEffect):
        raise OwnerIssuerDenied("native_owner_issuer_denied")
    try:
        validate_effect(decision.effect, decision.approved_at)
    except (GrantDenied, UnicodeError, ValueError, TypeError):
        raise OwnerIssuerDenied("native_owner_issuer_denied") from None


def _decision_bytes(decision: OwnerDecision) -> bytes:
    return json.dumps(
        asdict(decision), sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")


def seal_owner_decision(decision: OwnerDecision, *,
                        authority_key: bytes) -> bytes:
    """Only the owner-authenticated authority can call with its secret key.

    This is pure serialization/HMAC. Calling the helper is NOT a proof that
    the owner saw the request, logged in or actually approved it.
    """
    _check_decision(decision)
    key = _key(authority_key)
    canonical = _decision_bytes(decision)
    mac = hmac.new(key, DOMAIN + canonical, hashlib.sha256).hexdigest()
    ticket = json.dumps(
        {"decision": asdict(decision), "mac": mac}, sort_keys=True,
        ensure_ascii=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    if len(ticket) > MAX_TICKET_BYTES:
        raise OwnerIssuerDenied("native_owner_issuer_denied")
    return ticket


def verify_owner_decision(ticket: bytes, *, authority_key: bytes,
                          expected_owner: str, now: int) -> OwnerDecision:
    """Reject forged, noncanonical, stale, expired or cross-owner decisions."""
    if (type(ticket) is not bytes or not 0 < len(ticket) <= MAX_TICKET_BYTES
        or type(expected_owner) is not str or type(now) is not int):
        raise OwnerIssuerDenied("native_owner_issuer_denied")
    key = _key(authority_key)
    try:
        obj = json.loads(ticket.decode("ascii"), object_pairs_hook=_unique_object)
        if (type(obj) is not dict or set(obj) != {"decision", "mac"}
            or type(obj["mac"]) is not str
            or HEX64.fullmatch(obj["mac"]) is None
            or type(obj["decision"]) is not dict
            or set(obj["decision"]) != TICKET_FIELDS):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        item = obj["decision"]
        eff = item["effect"]
        if type(eff) is not dict or set(eff) != FIELDS:
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        effect = NativeEffect(**eff)
        decision = OwnerDecision(
            item["schema"], item["owner_id"], item["approved_at"], effect)
        _check_decision(decision)
        expected = seal_owner_decision(decision, authority_key=key)
        # Exact compact canonical serialization disallows JSON malleability
        # and makes the durable scope digest stable across processes.
        if (decision.owner_id != expected_owner
            or decision.approved_at > now
            or now - decision.approved_at > MAX_APPROVAL_AGE
            or effect.expires_at < now
            or not hmac.compare_digest(ticket, expected)):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
    except (ValueError, UnicodeError, TypeError, RecursionError,
            OverflowError, KeyError):
        raise OwnerIssuerDenied("native_owner_issuer_denied") from None
    return decision


def _check_local_state(directory: Path) -> None:
    if (not isinstance(directory, Path) or not directory.is_absolute()
        or sys.platform != "linux" or not hasattr(os, "geteuid")
        or os.geteuid() == 0):
        raise OwnerIssuerDenied("native_owner_issuer_denied")
    try:
        # The state location and every ancestor must not redirect through
        # symlinks. The state directory itself must be owned by the
        # unprivileged issuer and private to the OS account.
        for item in (directory, *directory.parents):
            if stat.S_ISLNK(item.lstat().st_mode):
                raise OwnerIssuerDenied("native_owner_issuer_denied")
        meta = directory.lstat()
        if (not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid != os.geteuid() or meta.st_mode & 0o077):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
    except (OSError, ValueError):
        raise OwnerIssuerDenied("native_owner_issuer_denied") from None


class NativeOwnerGrantIssuer:
    """Consume one authentic owner decision to sign one native effect.

    Construct exclusively inside a separately OS-confined trusted relay
    worker using protected keys/config, not from client-provided fields.
    """

    def __init__(self, config: LocalOwnerIssuerConfig, *,
                 is_device_revoked: Callable[[], bool]):
        if (type(config) is not LocalOwnerIssuerConfig
            or not callable(is_device_revoked)
            or type(config.owner_id) is not str
            or OWNER_ID.fullmatch(config.owner_id) is None
            or type(config.device_id) is not str
            or type(config.projects) is not frozenset
            or not 1 <= len(config.projects) <= 12):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        authority_key = _key(config.authority_verifier_key)
        device_key = _key(config.device_issuer_key)
        if hmac.compare_digest(authority_key, device_key):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        try:
            scope = ledger.LocalLedgerScope(config.device_id, config.projects)
            probe = ledger.EffectIdentity(
                "7138d606-5cfb-41fb-8021-b0628b3e6e32",
                config.device_id, next(iter(config.projects), ""),
                "process_run", "a" * 64, 601)
            ledger.validate(probe, now=1, scope=scope)
        except (ledger.LedgerDenied, ValueError, TypeError):
            raise OwnerIssuerDenied("native_owner_issuer_denied") from None
        _check_local_state(config.state_directory)
        self._config = config
        self._scope = scope
        self._is_device_revoked = is_device_revoked

    def _active(self) -> None:
        try:
            revoked = self._is_device_revoked()
        except Exception:
            raise OwnerIssuerDenied("native_owner_issuer_denied") from None
        if type(revoked) is not bool or revoked:
            raise OwnerIssuerDenied("native_owner_issuer_denied")

    def issue(self, ticket: bytes, payload: bytes) -> bytes:
        """Verify, atomically consume and return a ONE-use signed envelope.

        On ambiguous SQLite outcome, signature error, revoked device or
        reconnect, the same owner decision may NEVER be reissued.
        """
        self._active()
        now = int(time.time())
        decision = verify_owner_decision(
            ticket, authority_key=self._config.authority_verifier_key,
            expected_owner=self._config.owner_id, now=now)
        effect = decision.effect
        if (effect.device_id != self._config.device_id
            or effect.project not in self._config.projects
            or type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES
            or not hmac.compare_digest(
                hashlib.sha256(payload).hexdigest(), effect.payload_sha256)):
            raise OwnerIssuerDenied("native_owner_issuer_denied")
        _check_local_state(self._config.state_directory)
        self._active()
        identity = ledger.EffectIdentity(
            effect.operation_id, effect.device_id, effect.project,
            effect.action, hashlib.sha256(_decision_bytes(decision)).hexdigest(),
            effect.expires_at,
        )
        claimed = False
        try:
            status = ledger.claim(
                self._config.state_directory, identity,
                scope=self._scope, now=now)
            if status != "RESERVED_ONCE":
                raise OwnerIssuerDenied("native_owner_issuer_denied")
            claimed = True
            self._active()
            # A long/faulty revocation callback can consume the TTL.
            # Never sign a native grant that has expired in the meantime.
            if int(time.time()) > effect.expires_at:
                raise OwnerIssuerDenied("native_owner_issuer_denied")
            frame = sign_envelope(
                effect, issuer_key=self._config.device_issuer_key)
            if ledger.complete(
                self._config.state_directory, identity,
                scope=self._scope, success=True) != "RECORDED":
                raise OwnerIssuerDenied("native_owner_issuer_denied")
            return frame
        except (OwnerIssuerDenied, ledger.LedgerDenied, GrantDenied,
                ValueError, TypeError, OSError):
            if claimed:
                try:
                    ledger.complete(
                        self._config.state_directory, identity,
                        scope=self._scope, success=False)
                except (ledger.LedgerDenied, OSError, ValueError):
                    pass
            raise OwnerIssuerDenied("native_owner_issuer_denied") from None
