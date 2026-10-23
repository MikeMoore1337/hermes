"""Synthetic signed grant and evidence handoff for Hermes #474 / #475.

Research-only: test-held HMAC keys DO NOT establish real owner identity.
No private key loading, model dispatch, native worker hooks or services.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re

from scripts.orchestration_pre_call_reservation_probe import reserve_once

SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
MAC = re.compile(r"[0-9a-f]{64}\Z")
AUDIENCE = "hermes-orchestration-research-v1"
ALLOWED_TOOLS = frozenset({"source_read", "evidence_read"})

GRANT_FIELDS = frozenset({
    "version", "audience", "operation_key", "revision", "approval_id",
    "producer", "consumer", "allowed_tools", "issued_at", "expires_at",
})
EVIDENCE_FIELDS = frozenset({
    "version", "audience", "operation_key", "revision", "producer",
    "consumer", "run_id", "receipt_id", "sha256", "issued_at", "expires_at",
})


class Rejected(ValueError):
    """A research fixture declined an unverifiable request."""


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _valid_key(key: bytes) -> None:
    if type(key) is not bytes or len(key) < 32:
        raise Rejected("test_key_invalid")


def _valid_ident(value) -> bool:
    return type(value) is str and bool(IDENT.fullmatch(value))


def _valid_times(payload, now: int):
    if (type(now) is not int
            or type(payload["issued_at"]) is not int
            or type(payload["expires_at"]) is not int
            or not payload["issued_at"] <= now < payload["expires_at"]):
        raise Rejected("time_invalid")


def _check_shared(payload, keys, now):
    if type(payload) is not dict or frozenset(payload) != keys:
        raise Rejected("schema_invalid")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise Rejected("version_invalid")
    if payload["audience"] != AUDIENCE:
        raise Rejected("audience_invalid")
    if type(payload["revision"]) is not str or not SHA.fullmatch(payload["revision"]):
        raise Rejected("revision_invalid")
    for field in ("operation_key", "producer", "consumer"):
        if not _valid_ident(payload[field]):
            raise Rejected("identity_invalid")
    if payload["producer"] == payload["consumer"]:
        raise Rejected("not_independent")
    _valid_times(payload, now)


def issue_synthetic_signature(payload: dict, *, test_key: bytes) -> str:
    """Test fixture signing helper, NOT an authenticated owner-grant issuer."""
    _valid_key(test_key)
    return hmac.new(test_key, _canonical(payload), hashlib.sha256).hexdigest()


def _verify_sig(payload: dict, signature: str, key: bytes):
    _valid_key(key)
    if type(signature) is not str or not MAC.fullmatch(signature):
        raise Rejected("signature_invalid")
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise Rejected("signature_mismatch")


def verify_synthetic_grant(payload, signature, *, test_grant_key: bytes, now: int,
                           requested_tools: tuple[str, ...]):
    _check_shared(payload, GRANT_FIELDS, now)
    if not _valid_ident(payload["approval_id"]):
        raise Rejected("approval_invalid")
    tools = payload["allowed_tools"]
    if (type(tools) is not list or not tools
            or any(type(t) is not str for t in tools)
            or len(tools) != len(set(tools))
            or not set(tools) <= ALLOWED_TOOLS):
        raise Rejected("toolset_invalid")
    if (type(requested_tools) is not tuple or not requested_tools
            or any(type(t) is not str for t in requested_tools)
            or not set(requested_tools) <= set(tools)):
        raise Rejected("requested_tool_escalation")
    _verify_sig(payload, signature, test_grant_key)
    return dict(payload)


def reserve_with_synthetic_grant(
    db_path: Path, grant: dict, signature: str, *, test_grant_key: bytes,
    now: int, requested_tools: tuple[str, ...],
) -> str:
    """Verify an offline signed grant BEFORE the irreversible test-only insert."""
    verified = verify_synthetic_grant(
        grant, signature, test_grant_key=test_grant_key, now=now,
        requested_tools=requested_tools)
    return reserve_once(
        db_path, operation_key=verified["operation_key"],
        revision=verified["revision"], approval_id=verified["approval_id"],
        grant_verified=True, grant_expires_at=verified["expires_at"], now=now)


def verify_synthetic_evidence(
    receipt, signature: str, payload: bytes, *,
    test_evidence_key: bytes, operation_key: str, revision: str,
    expected_producer: str, expected_consumer: str, expected_run_id: int,
    now: int, seen_receipts: set[str],
) -> str:
    """Verify a signed *test* receipt; never grant native Kanban permission.

    The caller supplies the separate evidence-verifier key. This does not
    query a model, verify its provider, or authenticate a real device.
    """
    _check_shared(receipt, EVIDENCE_FIELDS, now)
    if type(payload) is not bytes or type(seen_receipts) is not set:
        raise Rejected("evidence_input_invalid")
    if (type(expected_run_id) is not int or expected_run_id <= 0
            or type(receipt["run_id"]) is not int or receipt["run_id"] <= 0
            or receipt["run_id"] != expected_run_id):
        raise Rejected("run_id_mismatch")
    if (receipt["operation_key"] != operation_key or receipt["revision"] != revision
            or receipt["producer"] != expected_producer
            or receipt["consumer"] != expected_consumer):
        raise Rejected("evidence_binding_mismatch")
    if not _valid_ident(receipt["receipt_id"]):
        raise Rejected("receipt_id_invalid")
    if receipt["receipt_id"] in seen_receipts:
        raise Rejected("receipt_replay")
    if (type(receipt["sha256"]) is not str or not MAC.fullmatch(receipt["sha256"])
            or receipt["sha256"] != hashlib.sha256(payload).hexdigest()):
        raise Rejected("evidence_digest_invalid")
    _verify_sig(receipt, signature, test_evidence_key)
    seen_receipts.add(receipt["receipt_id"])
    return receipt["producer"]
