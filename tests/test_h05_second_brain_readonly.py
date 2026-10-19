"""H-05 pure synthetic security and negative-contract tests; no private data."""
from __future__ import annotations

import copy
import datetime as dt
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from second_brain_readonly.offline_adapter import (
    MAX_RESPONSE_BYTES, MODE, SCHEMA, MockGrant, MockHttpFailure,
    MockTransport, ReadRejected, issue_mock_grant, read_mock_status,
)

KEY = b"synthetic-h05-test-only-signer-never-real-credential"
NOW = dt.datetime(2026, 10, 19, 12, 0, tzinfo=dt.timezone.utc)
RESOURCE = "F-demo-alpha"


def record() -> dict:
    return {
        "fact_id": RESOURCE, "source_status": "VERIFIED",
        "provenance_status": "AVAILABLE", "freshness_status": "CURRENT",
        "permission_status": "ALLOWED", "quality_status": "READY",
        "checked_at": "2026-10-18T12:00:00Z", "expires_at": None,
        "reason_codes": [],
    }


def payload(**overrides) -> bytes:
    current = record()
    current.update(overrides)
    return json.dumps({"schema": SCHEMA, "mode": MODE, "record": current}).encode()


def granted(**changes) -> MockGrant:
    opts = {"resource": RESOURCE, "expires_at": "2026-10-20T00:00:00Z"}
    opts.update(changes)
    return issue_mock_grant(key=KEY, **opts)


class H05OfflineAdapterTests(unittest.TestCase):
    def run_read(self, *, raw: bytes | Exception | None = None,
                 grant: MockGrant | None = None, resource: str = RESOURCE,
                 allow_mock: bool = True, transport: MockTransport | None = None,
                 key: bytes = KEY) -> tuple[dict, MockTransport]:
        transport = transport or MockTransport({RESOURCE: payload() if raw is None else raw})
        result = read_mock_status(
            allow_mock=allow_mock, grant=granted() if grant is None else grant,
            key=key, resource=resource, transport=transport, now=NOW)
        return result, transport

    def denied(self, reason: str, *, raw: bytes | Exception | None = None,
               grant: MockGrant | None = None, resource: str = RESOURCE,
               allow_mock: bool = True, key: bytes = KEY, before_transport: bool = False):
        mock = MockTransport({RESOURCE: payload() if raw is None else raw})
        with self.assertRaises(ReadRejected) as caught:
            self.run_read(raw=raw, grant=grant, resource=resource,
                          allow_mock=allow_mock, key=key, transport=mock)
        self.assertEqual(caught.exception.reason, reason)
        if before_transport:
            self.assertEqual(mock.calls, 0)
        self.assertNotIn("private", str(caught.exception))

    def test_01_authorized_current_synthetic_status(self):
        result, transport = self.run_read()
        self.assertEqual(result["quality_status"], "READY")
        self.assertEqual(result["access_status"], "ALLOWED")
        self.assertEqual(result["integration_status"], "MOCK_SUCCESS")
        self.assertEqual(result["mode"], "MOCK_ONLY")
        self.assertFalse(result["integration_verified"])
        self.assertEqual(transport.resources, [RESOURCE])
        self.assertNotIn("content", result)

    def test_02_insufficient_provenance_retains_unknown(self):
        result, _ = self.run_read(raw=payload(
            quality_status="UNKNOWN", provenance_status="MISSING",
            reason_codes=["INSUFFICIENT_PROVENANCE"]))
        self.assertEqual(result["quality_status"], "UNKNOWN")

    def test_03_stale_fact_remains_hold(self):
        result, _ = self.run_read(raw=payload(
            freshness_status="STALE", quality_status="HOLD",
            reason_codes=["STALE_FACT"]))
        self.assertEqual(result["quality_status"], "HOLD")

    def test_04_revoked_source_remains_hold(self):
        result, _ = self.run_read(raw=payload(
            source_status="REVOKED", quality_status="HOLD",
            reason_codes=["REVOKED_SOURCE"]))
        self.assertEqual(result["source_status"], "REVOKED")
        self.assertEqual(result["quality_status"], "HOLD")

    def test_05_contradiction_never_becomes_ready(self):
        result, _ = self.run_read(raw=payload(
            quality_status="HOLD", reason_codes=["CONTRADICTION"]))
        self.assertIn("CONTRADICTION", result["reason_codes"])
        self.denied("inconsistent_ready",
                    raw=payload(quality_status="READY",
                                reason_codes=["CONTRADICTION"]))

    def test_06_missing_fact_is_not_proof_of_absence(self):
        self.denied("mock_http_404", raw=MockHttpFailure(404))

    def test_07_expired_credentials_rejected_before_transport(self):
        self.denied("credential_expired", grant=granted(expires_at="2026-10-19T00:00:00Z"),
                    before_transport=True)

    def test_08_forged_grant_rejected_before_transport(self):
        self.denied("signature_invalid", grant=replace(granted(), scope="vault:*"),
                    before_transport=True)
        self.denied("signature_invalid", grant=replace(granted(), signature="0" * 64),
                    before_transport=True)

    def test_09_other_resource_rejected_before_transport(self):
        self.denied("resource_denied", grant=granted(),
                    resource="F-demo-other", before_transport=True)
        for path in ("../vault/secret", "/tmp/vault", "https://example.com",
                     "F-demo-alpha/notes", "F-demo-alpha?all=true", ""):
            with self.subTest(path=path):
                self.denied("resource_denied", resource=path, before_transport=True)

    def test_10_write_and_enumeration_rejected(self):
        for operation in ("note.write", "vault.list", "facts.export", "llm.forward"):
            with self.subTest(operation=operation):
                self.denied("scope_denied", grant=granted(operation=operation),
                            before_transport=True)

    def test_11_api_errors_and_timeout_without_retry(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status):
                mock = MockTransport({RESOURCE: MockHttpFailure(status)})
                with self.assertRaises(ReadRejected) as caught:
                    self.run_read(transport=mock)
                self.assertEqual(caught.exception.reason, f"mock_http_{status}")
                self.assertEqual(mock.calls, 1)
        self.denied("mock_timeout", raw=TimeoutError())

    def test_12_unexpected_private_field_is_rejected_not_redacted_silently(self):
        data = json.loads(payload())
        data["record"]["private_content"] = "private-text-canary"
        self.denied("record_schema_invalid", raw=json.dumps(data).encode())

    def test_default_disabled_and_missing_credentials(self):
        self.denied("integration_disabled", allow_mock=False, before_transport=True)
        mock = MockTransport({RESOURCE: payload()})
        with self.assertRaises(ReadRejected) as caught:
            read_mock_status(allow_mock=True, key=KEY, grant=None,
                             resource=RESOURCE, transport=mock, now=NOW)
        self.assertEqual(caught.exception.reason, "credential_missing")
        self.assertEqual(mock.calls, 0)

    def test_signed_scope_identity_audience_revocation(self):
        for overrides, reason in (
            ({"scope": "status:write"}, "scope_denied"),
            ({"service": "other-service"}, "service_denied"),
            ({"audience": "other-app"}, "audience_denied"),
            ({"revoked": True}, "grant_revoked"),
        ):
            with self.subTest(reason=reason):
                self.denied(reason, grant=granted(**overrides),
                            before_transport=True)

    def test_response_expiry_and_revoked_permissions(self):
        self.denied("response_expired",
                    raw=payload(expires_at="2026-10-19T00:00:00Z"))
        self.denied("permission_revoked",
                    raw=payload(permission_status="REVOKED", quality_status="HOLD",
                                reason_codes=["REVOKED_SOURCE"]))

    def test_unknown_fields_versions_duplicate_keys_and_invalid_json(self):
        self.denied("schema_invalid", raw=json.dumps({
            "schema": "unsupported", "mode": MODE, "record": record()}).encode())
        self.denied("json_invalid", raw=b"{")
        self.denied("json_invalid", raw=payload().replace(
            b'"fact_id":', b'"fact_id":"F-demo-malice","fact_id":', 1))
        self.denied("record_schema_invalid", raw=payload(note_path="../private"))
        self.denied("response_resource_mismatch", raw=payload(fact_id="F-demo-other"))
        self.denied("response_too_large", raw=b"x" * (MAX_RESPONSE_BYTES + 1))

    def test_redirect_and_http_codes(self):
        for status in (301, 302, 303, 307, 308):
            self.denied("redirect_denied", raw=MockHttpFailure(status))
        self.denied("mock_http_error", raw=MockHttpFailure(418))

    def test_nonready_without_reasons_or_ready_from_unknown_rejected(self):
        self.denied("unexplained_uncertainty", raw=payload(quality_status="UNKNOWN"))
        self.denied("inconsistent_ready", raw=payload(source_status="UNKNOWN"))
        self.denied("inconsistent_ready", raw=payload(freshness_status="STALE"))
        self.denied("inconsistent_ready", raw=payload(provenance_status="MISSING"))
        self.denied("future_evidence", raw=payload(checked_at="2026-10-20T00:00:00Z"))

    def test_closed_schema_rejects_types_and_uncontrolled_reasons(self):
        self.denied("status_invalid", raw=payload(quality_status=True))
        self.denied("reason_invalid", raw=payload(quality_status="HOLD",
                    reason_codes=["PRIVATE_NOTE_HERE"]))
        self.denied("timestamp_invalid", raw=payload(checked_at="2026-10-18"))
        self.denied("mock_http_404", raw=MockHttpFailure(404))

    def test_transport_is_in_memory_and_call_budget_is_bounded(self):
        mock = MockTransport({RESOURCE: payload()})
        for _ in range(2):
            result, _ = self.run_read(transport=mock)
            self.assertEqual(result["quality_status"], "READY")
        self.assertEqual(mock.calls, 2)
        with self.assertRaises(ReadRejected) as caught:
            self.run_read(transport=mock)
        self.assertEqual(caught.exception.reason, "rate_limited")
        self.assertEqual(mock.calls, 2)

    def test_no_files_sockets_processes_or_model_invocation(self):
        mock = MockTransport({RESOURCE: payload()})
        with (patch("builtins.open", side_effect=AssertionError("filesystem")),
              patch("socket.socket", side_effect=AssertionError("network")),
              patch("subprocess.Popen", side_effect=AssertionError("process"))):
            result, _ = self.run_read(transport=mock)
        self.assertEqual(result["mode"], MODE)
        self.assertEqual(mock.calls, 1)
        self.assertFalse(result["integration_verified"])

    def test_determinism_and_no_side_effect_on_fixture(self):
        raw = payload()
        fixture = {RESOURCE: raw}
        before = copy.deepcopy(fixture)
        r1, _ = self.run_read(transport=MockTransport(fixture))
        r2, _ = self.run_read(transport=MockTransport(fixture))
        self.assertEqual(r1, r2)
        self.assertEqual(fixture, before)


if __name__ == "__main__":
    unittest.main()
