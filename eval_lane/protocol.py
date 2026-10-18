"""Offline-only admission contract for Hermes #349 / ADT #11.

This module is NOT part of the H-15 presence transport or H-01 agent.
It provides no remote command transport, CLI invocation or activation command.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import time

KIND = "adt_skill_eval_pilot_v1"
OWNER = "MikeMoore1337"
CASES = frozenset({"python-api", "javascript-ui", "go-cli"})
PROVIDERS = frozenset({"codex", "claude"})
FIELDS = frozenset({
    "schema_version", "kind", "job_id", "approval_id", "toolkit_sha",
    "provider", "model", "case_ids", "trials", "timeout_seconds",
    "resource_limits", "budget", "issued_at", "expires_at",
})
LIMIT_FIELDS = frozenset({"memory_mb", "cpu_seconds", "output_bytes"})
BUDGET_FIELDS = frozenset({"maximum_usd", "provider_hard_cap_id"})
GRANT_FIELDS = frozenset({
    "schema_version", "owner", "approval_id", "job_sha256",
    "issued_at", "expires_at", "signature",
})
_ID = re.compile(r"^[a-z][a-z0-9-]{11,63}$")
_MODEL = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,79}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class AdmissionDenied(ValueError):
    """Non-sensitive denial reason; never include raw payloads/secrets."""


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def timestamp(value: object) -> float:
    if type(value) is not str or len(value) > 40:
        raise AdmissionDenied("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        result = parsed.timestamp()
        if not math.isfinite(result) or not 0 < result < 4102444800:
            raise ValueError("out of range")
        return result
    except (OverflowError, ValueError) as exc:
        raise AdmissionDenied("invalid_timestamp") from exc


def _bounded_integer(value: object, low: int, high: int, reason: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise AdmissionDenied(reason)
    return value


def _id(value: object, reason: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise AdmissionDenied(reason)
    return value


def validate_job(value: object, *, clock: float | None = None) -> dict:
    """Reject unknown fields and arbitrary paths/argv/env/URLs fail-closed."""
    now = time.time() if clock is None else clock
    if type(value) is not dict or set(value) != FIELDS:
        raise AdmissionDenied("unknown_job_schema")
    job = value
    if job["schema_version"] != 1 or type(job["schema_version"]) is not int:
        raise AdmissionDenied("invalid_schema_version")
    if job["kind"] != KIND or type(job["kind"]) is not str:
        raise AdmissionDenied("job_kind_forbidden")
    _id(job["job_id"], "invalid_job_id")
    _id(job["approval_id"], "invalid_approval_id")
    if type(job["toolkit_sha"]) is not str or not _SHA.fullmatch(job["toolkit_sha"]):
        raise AdmissionDenied("toolkit_sha_required")
    if type(job["provider"]) is not str or job["provider"] not in PROVIDERS:
        raise AdmissionDenied("provider_forbidden")
    if type(job["model"]) is not str or not _MODEL.fullmatch(job["model"]):
        raise AdmissionDenied("model_invalid")
    cases = job["case_ids"]
    if (type(cases) is not list or not 1 <= len(cases) <= 3 or
            any(type(v) is not str or v not in CASES for v in cases) or
            len(set(cases)) != len(cases)):
        raise AdmissionDenied("cases_not_allowlisted")
    _bounded_integer(job["trials"], 1, 3, "trial_limit")
    _bounded_integer(job["timeout_seconds"], 30, 600, "timeout_limit")
    limits = job["resource_limits"]
    if type(limits) is not dict or set(limits) != LIMIT_FIELDS:
        raise AdmissionDenied("unknown_resource_limits")
    _bounded_integer(limits["memory_mb"], 256, 4096, "memory_limit")
    _bounded_integer(limits["cpu_seconds"], 30, 1800, "cpu_limit")
    _bounded_integer(limits["output_bytes"], 1024, 1048576, "output_limit")
    budget = job["budget"]
    if type(budget) is not dict or set(budget) != BUDGET_FIELDS:
        raise AdmissionDenied("unknown_budget_schema")
    # Decimal *string* only, to avoid binary floats and NaN/Infinity.
    amount = budget["maximum_usd"]
    if (type(amount) is not str or
            not re.fullmatch(r"(?:0|[1-9][0-9]?)(?:\.[0-9]{1,2})?", amount) or
            not 0 < int(amount.replace(".", "").ljust(2, "0"))):
        raise AdmissionDenied("positive_budget_cap_required")
    # Maximum allowed stated scope, not proof of a provider-enforced cap.
    from decimal import Decimal
    if Decimal(amount) > Decimal("10.00"):
        raise AdmissionDenied("budget_scope_excess")
    _id(budget["provider_hard_cap_id"], "provider_cap_reference_required")
    start, end = timestamp(job["issued_at"]), timestamp(job["expires_at"])
    if (start > now + 30 or now < start - 30 or end <= now or
            end <= start or end - start > 3600):
        raise AdmissionDenied("job_expired_or_unbounded")
    return json.loads(canonical(job))


def approval_message(grant: dict) -> bytes:
    return canonical({k: grant[k] for k in sorted(GRANT_FIELDS - {"signature"})})


def issue_test_grant(job: dict, key: bytes) -> dict:
    """Offline test-helper. Not a remote approval endpoint."""
    grant = {
        "schema_version": 1, "owner": OWNER,
        "approval_id": job["approval_id"], "job_sha256": digest(job),
        "issued_at": job["issued_at"], "expires_at": job["expires_at"],
    }
    grant["signature"] = hmac.new(key, approval_message(grant),
                                  hashlib.sha256).hexdigest()
    return grant


def verify_grant(value: object, job: dict, *, key: bytes,
                 revoked: frozenset[str] = frozenset(),
                 clock: float | None = None) -> None:
    if type(value) is not dict or set(value) != GRANT_FIELDS:
        raise AdmissionDenied("invalid_approval_schema")
    if type(key) is not bytes or len(key) < 32:
        raise AdmissionDenied("trusted_approval_key_unavailable")
    grant = value
    if (grant["schema_version"] != 1 or type(grant["schema_version"]) is not int or
            grant["owner"] != OWNER or grant["approval_id"] != job["approval_id"] or
            grant["job_sha256"] != digest(job) or
            grant["issued_at"] != job["issued_at"] or
            grant["expires_at"] != job["expires_at"]):
        raise AdmissionDenied("approval_scope_mismatch")
    if grant["approval_id"] in revoked:
        raise AdmissionDenied("approval_revoked")
    now = time.time() if clock is None else clock
    if timestamp(grant["expires_at"]) <= now:
        raise AdmissionDenied("approval_expired")
    signature = grant["signature"]
    if type(signature) is not str or not _HASH.fullmatch(signature):
        raise AdmissionDenied("invalid_approval_signature")
    expected = hmac.new(key, approval_message(grant), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AdmissionDenied("approval_signature_invalid")


@dataclass(frozen=True)
class OperatorGates:
    """Local trusted operator context, NEVER parsed from the job payload.

    These facts still require independent *OS/provider* evidence on activation.
    They are not, by themselves, enforcement of resource/network/cost caps.
    """
    isolated_identity_verified: bool = False
    os_sandbox_verified: bool = False
    egress_acl_verified: bool = False
    provider_cost_hard_stop_verified: bool = False
    artifact_scope_verified: bool = False
    owner_runtime_go: bool = False


def verify_operator_gates(gates: OperatorGates) -> None:
    if type(gates) is not OperatorGates or not all(
        type(getattr(gates, name)) is bool and getattr(gates, name)
        for name in OperatorGates.__dataclass_fields__
    ):
        raise AdmissionDenied("runtime_proofs_not_verified")


def safely_load_json(path: Path, *, max_bytes: int = 8192) -> dict:
    """Offline fixture reader; caller must enforce trusted ownership/ACL."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise AdmissionDenied("untrusted_input_file")
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise AdmissionDenied("invalid_json") from exc
    if type(result) is not dict:
        raise AdmissionDenied("invalid_json_root")
    return result
