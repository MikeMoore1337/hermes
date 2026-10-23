"""Test-only owner-like HMAC and handoff evidence checks for #474/#475."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.orchestration_offline_checks import eligible_after_verified_evidence
from scripts.orchestration_pre_call_reservation_probe import (
    FIRST_ONLY, REPLAY_BLOCKED, initialize_temporary_fixture, read_record,
)
from scripts.orchestration_authenticated_handoff_probe import (
    AUDIENCE, Rejected, issue_synthetic_signature, reserve_with_synthetic_grant,
    verify_synthetic_evidence, verify_synthetic_grant,
)

GRANT_TEST_KEY = b"owner-test-key-not-a-production-secret" * 2
EVIDENCE_TEST_KEY = b"evidence-test-key-independent-of-owner" * 2
REV = "a" * 40
REV2 = "b" * 40


def signed_grant():
    return dict(
        version=1, audience=AUDIENCE, operation_key="stable-operation-1",
        revision=REV, approval_id="synthetic-owner-approval",
        producer="safety-review", consumer="qa-review",
        allowed_tools=["source_read", "evidence_read"],
        issued_at=1000, expires_at=2000,
    )


def signed_receipt(contents=b"verified synthetic payload"):
    return dict(
        version=1, audience=AUDIENCE, operation_key="stable-operation-1",
        revision=REV, producer="safety-review", consumer="qa-review",
        run_id=21, receipt_id="evidence-21",
        sha256=hashlib.sha256(contents).hexdigest(),
        issued_at=1010, expires_at=1600,
    )


class SignedResearchContracts(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="hermes-474-475-signed-")
        self.addCleanup(d.cleanup)
        self.db = Path(d.name) / "reservation.sqlite"
        initialize_temporary_fixture(self.db)

    @staticmethod
    def sign_grant(g):
        return issue_synthetic_signature(g, test_key=GRANT_TEST_KEY)

    @staticmethod
    def sign_receipt(r):
        return issue_synthetic_signature(r, test_key=EVIDENCE_TEST_KEY)

    def reserve(self, grant=None, signature=None, **kwargs):
        g = signed_grant() if grant is None else grant
        sig = signature if signature is not None else self.sign_grant(g)
        values = dict(
            db_path=self.db, grant=g, signature=sig,
            test_grant_key=GRANT_TEST_KEY, now=1200,
            requested_tools=("source_read",))
        values.update(kwargs)
        return reserve_with_synthetic_grant(**values)

    def evidence(self, receipt=None, signature=None, contents=b"verified synthetic payload",
                 **kwargs):
        r = signed_receipt(contents) if receipt is None else receipt
        sig = signature if signature is not None else self.sign_receipt(r)
        values = dict(
            receipt=r, signature=sig, payload=contents,
            test_evidence_key=EVIDENCE_TEST_KEY,
            operation_key="stable-operation-1", revision=REV,
            expected_producer="safety-review", expected_consumer="qa-review",
            expected_run_id=21, now=1200, seen_receipts=set())
        values.update(kwargs)
        return verify_synthetic_evidence(**values)

    def test_signed_grant_reserves_once_only(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.reserve(), REPLAY_BLOCKED)

    def test_signed_grant_rejects_tampered_revision_without_insert(self):
        g = signed_grant()
        sig = self.sign_grant(g)
        g["revision"] = REV2
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.reserve(g, sig)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_signed_grant_rejects_changed_operation_key_without_insert(self):
        g = signed_grant()
        sig = self.sign_grant(g)
        g["operation_key"] = "other-operation"
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.reserve(g, sig)
        self.assertFalse(self.db.stat().st_size == 0)
        self.assertIsNone(read_record(self.db, "other-operation"))

    def test_signed_grant_rejects_wrong_key_without_insert(self):
        g = signed_grant()
        sig = issue_synthetic_signature(g, test_key=EVIDENCE_TEST_KEY)
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.reserve(g, sig)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_expired_grant_rejected_before_reservation(self):
        with self.assertRaisesRegex(Rejected, "time_invalid"):
            self.reserve(now=2000)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_future_grant_rejected_before_reservation(self):
        with self.assertRaisesRegex(Rejected, "time_invalid"):
            self.reserve(now=999)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_requested_write_tool_does_not_get_an_approval(self):
        with self.assertRaisesRegex(Rejected, "requested_tool_escalation"):
            self.reserve(requested_tools=("source_write",))
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_grant_with_write_tool_rejected_even_when_signed(self):
        g = signed_grant()
        g["allowed_tools"] = ["source_read", "source_write"]
        with self.assertRaisesRegex(Rejected, "toolset_invalid"):
            self.reserve(g)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_unsupported_audience_rejected(self):
        g = signed_grant()
        g["audience"] = "unrelated-service"
        with self.assertRaisesRegex(Rejected, "audience_invalid"):
            self.reserve(g)

    def test_extra_fields_and_boolean_times_rejected(self):
        for change, expected in [
            ({"extra": "bypass"}, "schema_invalid"),
            ({"expires_at": True}, "time_invalid"),
            ({"issued_at": True}, "time_invalid"),
            ({"version": True}, "version_invalid"),
        ]:
            with self.subTest(change=change):
                g = signed_grant()
                g.update(change)
                with self.assertRaisesRegex(Rejected, expected):
                    self.reserve(g)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_same_producer_and_consumer_rejected(self):
        g = signed_grant()
        g["consumer"] = "safety-review"
        with self.assertRaisesRegex(Rejected, "not_independent"):
            self.reserve(g)

    def test_grant_key_strength_checked(self):
        g = signed_grant()
        with self.assertRaisesRegex(Rejected, "test_key_invalid"):
            verify_synthetic_grant(g, self.sign_grant(g), test_grant_key=b"small",
                                   now=1200, requested_tools=("source_read",))

    def test_valid_evidence_then_replay_rejected(self):
        r = signed_receipt()
        seen = set()
        self.assertEqual(self.evidence(r, seen_receipts=seen), "safety-review")
        with self.assertRaisesRegex(Rejected, "receipt_replay"):
            self.evidence(r, seen_receipts=seen)

    def test_modified_evidence_bytes_rejected(self):
        r = signed_receipt()
        with self.assertRaisesRegex(Rejected, "evidence_digest_invalid"):
            self.evidence(r, contents=b"modified")

    def test_evidence_tampered_receipt_rejected(self):
        r = signed_receipt()
        sig = self.sign_receipt(r)
        r["receipt_id"] = "evidence-99"
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.evidence(r, signature=sig)

    def test_evidence_bound_to_run_and_consumer(self):
        with self.assertRaisesRegex(Rejected, "run_id_mismatch"):
            self.evidence(expected_run_id=20)
        with self.assertRaisesRegex(Rejected, "evidence_binding_mismatch"):
            self.evidence(expected_consumer="other-review")

    def test_expired_evidence_rejected(self):
        with self.assertRaisesRegex(Rejected, "time_invalid"):
            self.evidence(now=1600)

    def test_evidence_rejects_signature_by_owner_key(self):
        r = signed_receipt()
        wrong = issue_synthetic_signature(r, test_key=GRANT_TEST_KEY)
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.evidence(r, signature=wrong)

    def test_signed_evidence_not_archived_status_unlocks_synthetic_dag(self):
        # The real native Kanban archive status is NOT a signed success
        # receipt. Only verified evidence may be passed to this helper.
        plan = dict(
            revision=REV, approval_id="synthetic-owner-approval",
            nodes=[{"id": "safety-review"}, {"id": "qa-review"}],
            edges=[["safety-review", "qa-review"]],
        )
        self.assertEqual(
            eligible_after_verified_evidence(plan, frozenset()),
            ("safety-review",))
        signed_parent = self.evidence()
        self.assertEqual(signed_parent, "safety-review")
        self.assertEqual(
            eligible_after_verified_evidence(plan, frozenset({signed_parent})),
            ("qa-review",))

    def test_nonstring_grant_tool_fails_closed(self):
        grant = signed_grant()
        grant["allowed_tools"] = ["source_read", ["nested_invalid_tool"]]
        with self.assertRaisesRegex(Rejected, "toolset_invalid"):
            self.reserve(grant)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_receipt_rejects_forged_signature_after_payload_change(self):
        receipt = signed_receipt()
        signature = self.sign_receipt(receipt)
        receipt["sha256"] = hashlib.sha256(b"forged").hexdigest()
        with self.assertRaisesRegex(Rejected, "evidence_digest_invalid"):
            self.evidence(receipt, signature=signature)
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.evidence(receipt, signature=signature, contents=b"forged")

    def test_valid_evidence_not_sufficient_for_a_new_model_call(self):
        r = signed_receipt()
        self.assertEqual(self.evidence(r), "safety-review")
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.reserve(), REPLAY_BLOCKED)


if __name__ == "__main__":
    unittest.main()
