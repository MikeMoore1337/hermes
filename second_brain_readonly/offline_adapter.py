"""H-05 synthetic metadata-only read boundary. NO live Second Brain transport.

Never connect this module to a live endpoint: mock credentials are forgeable by
design, and the real Second Brain service-to-service contract is NOT approved.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

SCHEMA = "hermes-h05-mock-status-v1"
MODE = "MOCK_ONLY"
MAX_RESPONSE_BYTES = 2048
MAX_MOCK_CALLS = 2
_ID = re.compile(r"F-demo-[a-z0-9]{1,16}\Z")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
_REASONS = frozenset({
    "INSUFFICIENT_PROVENANCE", "STALE_FACT", "STALE_SOURCE",
    "REVOKED_SOURCE", "MISSING_SOURCE", "ORPHAN_LINK", "CONTRADICTION",
    "LINKED_FACT_HOLD", "LINKED_FACT_UNKNOWN", "SOURCE_UNAVAILABLE",
})
_SERVICE = "hermes-h05-offline"
_AUDIENCE = "second-brain-mock-only"
_OPERATION = "status.read"
_SCOPE = "synthetic-status:read"


class ReadRejected(ValueError):
    """Fixed, non-sensitive reason code, with no original payload attached."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class MockGrant:
    service: str
    audience: str
    operation: str
    scope: str
    resource: str
    expires_at: str
    revoked: bool
    signature: str


class MockHttpFailure(Exception):
    """Synthetic HTTP condition, not a real HTTP client or response."""

    def __init__(self, status: int):
        self.status = status


class MockTransport:
    """Bounded, in-memory bytes. No URL, filesystem, sockets or callbacks."""

    def __init__(self, responses: dict[str, bytes | Exception]):
        if type(responses) is not dict or len(responses) > 8:
            raise ReadRejected("mock_transport_invalid")
        for key, value in responses.items():
            if not isinstance(key, str) or _ID.fullmatch(key) is None:
                raise ReadRejected("mock_transport_invalid")
            if type(value) is not bytes and type(value) not in (MockHttpFailure, TimeoutError):
                raise ReadRejected("mock_transport_invalid")
        self._responses = responses.copy()
        self.calls = 0
        self.resources: list[str] = []

    def get(self, resource: str) -> bytes:
        if self.calls >= MAX_MOCK_CALLS:
            raise ReadRejected("rate_limited")
        self.calls += 1
        self.resources.append(resource)
        result = self._responses.get(resource, MockHttpFailure(404))
        if isinstance(result, Exception):
            raise result
        return result


def _utc(value: str) -> dt.datetime:
    if type(value) is not str or _TIME.fullmatch(value) is None:
        raise ReadRejected("timestamp_invalid")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise ReadRejected("timestamp_invalid") from None


def _signed_part(grant: MockGrant) -> bytes:
    # Length-prefixed canonical fields prevent delimiter and ambiguity attacks.
    fields = (grant.service, grant.audience, grant.operation, grant.scope,
              grant.resource, grant.expires_at, str(grant.revoked))
    return b"".join(len(item.encode("utf-8")).to_bytes(2, "big") + item.encode("utf-8")
                    for item in fields)


def issue_mock_grant(*, key: bytes, resource: str, expires_at: str,
                     service: str = _SERVICE, audience: str = _AUDIENCE,
                     operation: str = _OPERATION, scope: str = _SCOPE,
                     revoked: bool = False) -> MockGrant:
    """Mint only a synthetic test capability; never a Second Brain credential."""
    provisional = MockGrant(service, audience, operation, scope, resource, expires_at, revoked, "")
    if type(key) is not bytes or len(key) < 32:
        raise ReadRejected("mock_key_invalid")
    try:
        payload = _signed_part(provisional)
    except (UnicodeError, OverflowError, AttributeError, TypeError):
        raise ReadRejected("grant_invalid") from None
    return MockGrant(service, audience, operation, scope, resource, expires_at, revoked,
                     hmac.new(key, payload, hashlib.sha256).hexdigest())


def _check_grant(grant: MockGrant | None, *, key: bytes, resource: str,
                 now: dt.datetime) -> None:
    if type(grant) is not MockGrant:
        raise ReadRejected("credential_missing")
    if type(key) is not bytes or len(key) < 32:
        raise ReadRejected("mock_key_invalid")
    if type(grant.signature) is not str or re.fullmatch(r"[0-9a-f]{64}", grant.signature) is None:
        raise ReadRejected("signature_invalid")
    try:
        expected = hmac.new(key, _signed_part(grant), hashlib.sha256).hexdigest()
    except (UnicodeError, OverflowError, AttributeError, TypeError):
        raise ReadRejected("grant_invalid") from None
    if not hmac.compare_digest(expected, grant.signature):
        raise ReadRejected("signature_invalid")
    if grant.service != _SERVICE:
        raise ReadRejected("service_denied")
    if grant.audience != _AUDIENCE:
        raise ReadRejected("audience_denied")
    if grant.operation != _OPERATION or grant.scope != _SCOPE:
        raise ReadRejected("scope_denied")
    if type(grant.revoked) is not bool or grant.revoked:
        raise ReadRejected("grant_revoked")
    if grant.resource != resource:
        raise ReadRejected("resource_denied")
    if _utc(grant.expires_at) <= now:
        raise ReadRejected("credential_expired")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise ReadRejected("duplicate_json_key")
        result[k] = v
    return result


def _bad_constant(_: str) -> None:
    raise ReadRejected("json_invalid")


def _parse_response(payload: bytes, *, resource: str, now: dt.datetime) -> dict[str, Any]:
    if type(payload) is not bytes or len(payload) > MAX_RESPONSE_BYTES:
        raise ReadRejected("response_too_large")
    try:
        response = json.loads(payload, object_pairs_hook=_strict_object,
                              parse_constant=_bad_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ReadRejected("json_invalid") from None
    if type(response) is not dict or set(response) != {"schema", "mode", "record"}:
        raise ReadRejected("schema_invalid")
    if response["schema"] != SCHEMA or response["mode"] != MODE:
        raise ReadRejected("schema_invalid")
    record = response["record"]
    fields = {"fact_id", "source_status", "provenance_status", "freshness_status",
              "permission_status", "quality_status", "checked_at", "expires_at", "reason_codes"}
    if type(record) is not dict or set(record) != fields:
        raise ReadRejected("record_schema_invalid")
    if record["fact_id"] != resource:
        raise ReadRejected("response_resource_mismatch")
    enums = {
        "source_status": {"VERIFIED", "REVOKED", "UNKNOWN"},
        "provenance_status": {"AVAILABLE", "MISSING", "UNKNOWN"},
        "freshness_status": {"CURRENT", "STALE", "UNKNOWN"},
        "permission_status": {"ALLOWED", "REVOKED"},
        "quality_status": {"READY", "HOLD", "UNKNOWN"},
    }
    if any(type(record[name]) is not str or record[name] not in values
           for name, values in enums.items()):
        raise ReadRejected("status_invalid")
    reasons = record["reason_codes"]
    if (type(reasons) is not list or len(reasons) > 8
            or any(type(r) is not str or r not in _REASONS for r in reasons)
            or len(set(reasons)) != len(reasons)):
        raise ReadRejected("reason_invalid")
    if _utc(record["checked_at"]) > now:
        raise ReadRejected("future_evidence")
    if record["expires_at"] is not None and _utc(record["expires_at"]) <= now:
        raise ReadRejected("response_expired")
    if record["permission_status"] != "ALLOWED":
        raise ReadRejected("permission_revoked")
    if record["quality_status"] == "READY":
        if (record["source_status"] != "VERIFIED"
                or record["provenance_status"] != "AVAILABLE"
                or record["freshness_status"] != "CURRENT" or reasons):
            raise ReadRejected("inconsistent_ready")
    elif not reasons:
        raise ReadRejected("unexplained_uncertainty")
    # Return only approved status metadata. No unknown/private response fields.
    return {
        "mode": MODE, "integration_verified": False, "access_status": "ALLOWED",
        "integration_status": "MOCK_SUCCESS",
        **{name: record[name] for name in sorted(fields)},
    }


def read_mock_status(*, allow_mock: bool = False, grant: MockGrant | None = None,
                     key: bytes = b"", resource: str = "",
                     transport: MockTransport | None = None,
                     now: dt.datetime | None = None) -> dict[str, Any]:
    """One synthetic read; fail before transport on every authorization error."""
    if allow_mock is not True:
        raise ReadRejected("integration_disabled")
    if type(now) is not dt.datetime or now.tzinfo is None or now.utcoffset() is None:
        raise ReadRejected("clock_invalid")
    now_utc = now.astimezone(dt.timezone.utc)
    if type(resource) is not str or _ID.fullmatch(resource) is None:
        raise ReadRejected("resource_denied")
    _check_grant(grant, key=key, resource=resource, now=now_utc)
    if type(transport) is not MockTransport:
        raise ReadRejected("mock_transport_required")
    try:
        payload = transport.get(resource)
    except MockHttpFailure as exc:
        if exc.status in (301, 302, 303, 307, 308):
            reason = "redirect_denied"
        elif exc.status in (401, 403, 404, 429, 500, 503):
            reason = f"mock_http_{exc.status}"
        else:
            reason = "mock_http_error"
        raise ReadRejected(reason) from None
    except TimeoutError:
        raise ReadRejected("mock_timeout") from None
    return _parse_response(payload, resource=resource, now=now_utc)
