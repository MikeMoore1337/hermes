"""Test-only owner-like HMAC and handoff evidence checks for #474/#475."""
import copy
import hashlib
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from scripts.orchestration_offline_checks import eligible_after_verified_evidence
from scripts.orchestration_pre_call_reservation_probe import (
    FIRST_ONLY, REPLAY_BLOCKED, InvalidFixture, initialize_temporary_fixture,
    read_record, read_evidence_record,
)
from scripts.orchestration_authenticated_handoff_probe import (
    AUDIENCE, Rejected, accept_signed_evidence_once, issue_synthetic_signature,
    reserve_with_synthetic_grant,
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
        scopes=["source:hermes", "evidence:hermes"],
        device="research-linux", max_steps=3,
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
            requested_tools=("source_read",),
            requested_scopes=("source:hermes",),
            requested_device="research-linux", requested_steps=1)
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

    def durable_evidence(self, receipt=None, signature=None,
                         contents=b"verified synthetic payload", **kwargs):
        r = signed_receipt(contents) if receipt is None else receipt
        sig = signature if signature is not None else self.sign_receipt(r)
        values = dict(
            db_path=self.db, receipt=r, signature=sig, payload=contents,
            test_evidence_key=EVIDENCE_TEST_KEY,
            operation_key="stable-operation-1", revision=REV,
            expected_producer="safety-review", expected_consumer="qa-review",
            expected_run_id=21, now=1200)
        values.update(kwargs)
        return accept_signed_evidence_once(**values)

    def test_durable_receipt_requires_matching_reserved_operation(self):
        with self.assertRaisesRegex(InvalidFixture,
                                    "missing_matching_reservation"):
            self.durable_evidence()
        self.assertIsNone(read_evidence_record(self.db, "evidence-21"))

    def test_durable_receipt_accepted_once_even_after_reopen(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.assertEqual(self.durable_evidence(), "safety-review")
        record = read_evidence_record(self.db, "evidence-21")
        self.assertEqual(record[0:2], ("evidence-21", "stable-operation-1"))
        with self.assertRaisesRegex(Rejected, "receipt_replay_durable"):
            self.durable_evidence()
        self.assertEqual(read_evidence_record(self.db, "evidence-21"), record)

    def test_second_signed_receipt_same_operation_rejected(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        self.durable_evidence()
        alternative = signed_receipt()
        alternative["receipt_id"] = "another-evidence-id"
        with self.assertRaisesRegex(Rejected, "receipt_replay_durable"):
            self.durable_evidence(alternative)
        self.assertIsNone(read_evidence_record(self.db, "another-evidence-id"))

    def test_unauthenticated_receipt_leaves_no_durable_record(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        valid = signed_receipt()
        bad_sig = self.sign_receipt(valid)
        valid["receipt_id"] = "tampered-receipt-id"
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.durable_evidence(valid, bad_sig)
        self.assertIsNone(read_evidence_record(self.db, "tampered-receipt-id"))
        self.assertEqual(self.durable_evidence(), "safety-review")

    def test_concurrent_durable_receipt_has_one_winner(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        barrier = threading.Barrier(8)
        def worker(_):
            barrier.wait(timeout=8)
            try:
                return self.durable_evidence()
            except Rejected as error:
                return str(error)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(results.count("safety-review"), 1)
        self.assertEqual(results.count("receipt_replay_durable"), 7)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM synthetic_evidence_acceptances"
            ).fetchone()[0], 1)

    def test_evidence_crash_after_commit_blocks_second_process(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        child_source = (
            "import os,sys\n"
            "from pathlib import Path\n"
            "from scripts.orchestration_authenticated_handoff_probe import "
            "accept_signed_evidence_once,issue_synthetic_signature\n"
            "import hashlib\n"
            "content=b'verified synthetic payload'\n"
            "receipt=dict(version=1,audience='hermes-orchestration-research-v1',"
            "operation_key='stable-operation-1',revision='a'*40,"
            "producer='safety-review',consumer='qa-review',run_id=21,"
            "receipt_id='evidence-21',sha256=hashlib.sha256(content).hexdigest(),"
            "issued_at=1010,expires_at=1600)\n"
            "key=b'evidence-test-key-independent-of-owner'*2\n"
            "sign=issue_synthetic_signature(receipt,test_key=key)\n"
            "assert accept_signed_evidence_once(Path(sys.argv[1]),"
            "receipt,sign,content,test_evidence_key=key,"
            "operation_key='stable-operation-1',revision='a'*40,"
            "expected_producer='safety-review',expected_consumer='qa-review',"
            "expected_run_id=21,now=1200)=='safety-review'\n"
            "os._exit(29)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", child_source, str(self.db)],
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True, timeout=12, check=False,
        )
        self.assertEqual(completed.returncode, 29,
                         completed.stderr.decode(errors="replace"))
        self.assertIsNotNone(read_evidence_record(self.db, "evidence-21"))
        with self.assertRaisesRegex(Rejected, "receipt_replay_durable"):
            self.durable_evidence()

    def test_expired_receipt_does_not_create_persistent_acceptance(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        with self.assertRaisesRegex(Rejected, "time_invalid"):
            self.durable_evidence(now=1600)
        self.assertIsNone(read_evidence_record(self.db, "evidence-21"))

    def test_durable_acceptance_fails_closed_without_ledger(self):
        self.assertEqual(self.reserve(), FIRST_ONLY)
        with sqlite3.connect(self.db) as db:
            db.execute("DROP TABLE synthetic_evidence_acceptances")
        with self.assertRaises(sqlite3.OperationalError):
            self.durable_evidence()

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

    def test_requested_scope_escalation_rejected(self):
        with self.assertRaisesRegex(Rejected, "requested_scope_escalation"):
            self.reserve(requested_scopes=("source:other",))
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_grant_scope_escalation_rejected(self):
        g = signed_grant()
        g["scopes"] = ["source:hermes", "source:foreign-repo"]
        with self.assertRaisesRegex(Rejected, "scopes_invalid"):
            self.reserve(g)

    def test_wrong_device_rejected(self):
        with self.assertRaisesRegex(Rejected, "device_mismatch"):
            self.reserve(requested_device="unknown-device")
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_over_budget_and_bool_steps_rejected(self):
        for requested in (4, True, 0):
            with self.subTest(requested=requested):
                with self.assertRaisesRegex(Rejected, "step_budget_escalation"):
                    self.reserve(requested_steps=requested)
        self.assertIsNone(read_record(self.db, "stable-operation-1"))

    def test_signed_device_change_rejected(self):
        g = signed_grant()
        original_signature = self.sign_grant(g)
        g["device"] = "other-device"
        with self.assertRaisesRegex(Rejected, "signature_mismatch"):
            self.reserve(g, original_signature, requested_device="other-device")

    def test_same_producer_and_consumer_rejected(self):
        g = signed_grant()
        g["consumer"] = "safety-review"
        with self.assertRaisesRegex(Rejected, "not_independent"):
            self.reserve(g)

    def test_grant_key_strength_checked(self):
        g = signed_grant()
        with self.assertRaisesRegex(Rejected, "test_key_invalid"):
            verify_synthetic_grant(g, self.sign_grant(g), test_grant_key=b"small",
                                   now=1200, requested_tools=("source_read",),
                                   requested_scopes=("source:hermes",),
                                   requested_device="research-linux", requested_steps=1)

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
