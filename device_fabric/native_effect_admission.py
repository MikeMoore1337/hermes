"""Dormant native effect admission: signed envelope + durable one-use reservation.

This is a library only; no MCP endpoint, agent service, OS effect, key issuer
or shell. The authenticated Hermes relay must independently approve the
owner's *exact* action before signing. The native host must independently
enforce OS directory/process rights and live revocation before executing.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Callable

from device_fabric.native_effect_grants import (
    GrantDenied, verify_envelope,
)
from scripts import h15_native_effect_receipts as ledger


class AdmissionDenied(ValueError):
    """Generic denial; never expose keys, paths, prompts, tokens or payload."""


@dataclass(frozen=True, slots=True)
class LocalAdmissionConfig:
    """Protected local config, NEVER caller-supplied MCP or ChatGPT fields."""

    state_directory: Path
    device_id: str
    projects: frozenset[str]
    verifier_key: bytes


class NativeEffectAdmission:
    """Reserve signed effects once on an authorized original host.

    Construct only inside a restricted native agent with locally provisioned
    credentials, local approved-project names and owner-protected state.
    This class returns a receipt, NEVER a callable or execution permission.
    """

    def __init__(self, config: LocalAdmissionConfig, *,
                 is_revoked: Callable[[], bool]):
        if (type(config) is not LocalAdmissionConfig
            or not isinstance(config.state_directory, Path)
            or type(config.verifier_key) is not bytes
            or not 32 <= len(config.verifier_key) <= 128
            or not callable(is_revoked)):
            raise AdmissionDenied("native_admission_denied")
        scope = ledger.LocalLedgerScope(config.device_id, config.projects)
        # Validate the local host profile without touching files or network.
        probe = ledger.EffectIdentity(
            "7138d606-5cfb-41fb-8021-b0628b3e6e32",
            config.device_id, next(iter(config.projects), ""), "file_write",
            "a" * 64, 601)
        try:
            ledger.validate(probe, now=1, scope=scope)
        except (ledger.LedgerDenied, TypeError, ValueError) as exc:
            raise AdmissionDenied("native_admission_denied") from None
        self._config = config
        self._scope = scope
        self._is_revoked = is_revoked

    def _active(self) -> None:
        """Revocation source must be trusted and fail closed even on errors."""
        try:
            state = self._is_revoked()
        except Exception:
            raise AdmissionDenied("native_admission_denied") from None
        if type(state) is not bool or state:
            raise AdmissionDenied("native_admission_denied")

    def reserve(self, signed_frame: bytes, payload: bytes, *,
                now: int | None = None) -> ledger.EffectIdentity:
        """Verify then reserve exactly once, with no automatic retry.

        On reconnect, timeout or crash, any duplicate operation_id is refused
        even if the earlier operation might not have executed. An atomic
        committed receipt MUST precede any later OS effect.
        """
        self._active()
        timestamp = int(time.time()) if now is None else now
        try:
            verified = verify_envelope(
                signed_frame, payload, verifier_key=self._config.verifier_key,
                expected_device_id=self._scope.device_id,
                allowed_projects=self._scope.projects, now=timestamp)
            effect = verified.effect
            identity = ledger.EffectIdentity(
                effect.operation_id, effect.device_id, effect.project,
                effect.action, verified.scope_sha256, effect.expires_at)
            status = ledger.claim(self._config.state_directory, identity,
                                  now=timestamp, scope=self._scope)
        except (GrantDenied, ledger.LedgerDenied, TypeError, ValueError):
            raise AdmissionDenied("native_admission_denied") from None
        # A concurrent revoke at this point keeps the UUID consumed forever.
        # The actual OS effect must recheck revocation immediately before
        # execution and cannot treat this receipt as owner authorization.
        self._active()
        if status != "RESERVED_ONCE":
            raise AdmissionDenied("native_admission_denied")
        return identity

    def complete(self, identity: ledger.EffectIdentity, *, success: bool) -> str:
        """Record outcome without re-enabling or retrying any effect."""
        try:
            return ledger.complete(
                self._config.state_directory, identity,
                success=success, scope=self._scope)
        except (ledger.LedgerDenied, TypeError, ValueError):
            raise AdmissionDenied("native_admission_denied") from None
