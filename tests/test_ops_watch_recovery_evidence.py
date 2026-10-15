"""H-02: recorded ACK sequence is NOT proof of a natural incident."""
from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ops_watch.core import InputError
from ops_watch.delivery_contract import claim_one, confirm_one
from ops_watch.recovery_evidence import inspect_receipts, main
from ops_watch import recovery_evidence as audit
from ops_watch.state_store import DATABASE, persist

NOW = datetime(2026, 10, 15, 13, tzinfo=UTC)
CODE = "timer_inactive"
ACTIVE = [{"code": CODE, "fingerprint": "ops:" + CODE}]


class RecordedRecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hermes-receipt-evidence-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.directory.chmod(0o700)
        persist(self.directory, [], lambda: [], observed=NOW)

    def raise_event(self):
        persist(self.directory, ACTIVE, lambda: [], observed=NOW)

    def confirmed_pair(self):
        self.raise_event()
        first = claim_one(self.directory, now=NOW)
        confirm_one(self.directory, event_id=first["event_id"],
                    lease_token=first["lease_token"], telegram_message_id=101,
                    now=NOW + timedelta(seconds=1))
        persist(self.directory, [], lambda: [], observed=NOW + timedelta(seconds=2))
        second = claim_one(self.directory, now=NOW + timedelta(seconds=3))
        confirm_one(self.directory, event_id=second["event_id"],
                    lease_token=second["lease_token"], telegram_message_id=102,
                    now=NOW + timedelta(seconds=4))

    def test_full_local_pair_never_claims_natural_or_independent_delivery(self):
        self.confirmed_pair()
        before = (self.directory / DATABASE).read_bytes()
        result = inspect_receipts(self.directory, code=CODE)
        self.assertEqual(result["status"], "RECORDED_ACK_PAIR_UNVERIFIED")
        self.assertEqual((result["new_event_id"], result["resolved_event_id"]), (1, 2))
        self.assertEqual((result["new_telegram_message_id"],
                          result["resolved_telegram_message_id"]), (101, 102))
        self.assertFalse(result["natural_incident_origin_verified"])
        self.assertFalse(result["telegram_acceptance_independently_verified"])
        self.assertFalse(result["current_service_health_verified"])
        self.assertFalse(result["database_modified"])
        self.assertEqual((self.directory / DATABASE).read_bytes(), before)

    def test_empty_queue_does_not_claim_success_or_create_receipts(self):
        result = inspect_receipts(self.directory, code=CODE)
        self.assertEqual(result["status"], "NO_RECORDED_ACK_PAIR")
        with sqlite3.connect(self.directory / DATABASE) as db:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("delivery_receipts", tables)

    def test_missing_recovery_receipt_does_not_complete_pair(self):
        self.raise_event()
        claimed = claim_one(self.directory, now=NOW)
        confirm_one(self.directory, event_id=claimed["event_id"],
                    lease_token=claimed["lease_token"], telegram_message_id=10,
                    now=NOW + timedelta(seconds=1))
        persist(self.directory, [], lambda: [], observed=NOW + timedelta(seconds=2))
        result = inspect_receipts(self.directory, code=CODE)
        self.assertEqual(result["status"], "NO_RECORDED_ACK_PAIR")

    def test_wrong_recipient_metadata_is_not_read_or_reported(self):
        self.confirmed_pair()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE events SET title='SECRET_PRIVATE_CONTENT' WHERE id=1")
        with self.assertRaises(InputError) as raised:
            inspect_receipts(self.directory, code=CODE)
        self.assertNotIn("SECRET_PRIVATE_CONTENT", str(raised.exception))

    def test_forged_early_ack_timestamp_fails_closed(self):
        self.confirmed_pair()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE delivery_receipts SET acknowledged_at=? WHERE event_id=1",
                       ((NOW - timedelta(days=1)).isoformat(),))
        with self.assertRaisesRegex(InputError, "evidence_receipt_invalid"):
            inspect_receipts(self.directory, code=CODE)

    def test_invalid_confirmed_telegram_id_is_rejected(self):
        self.confirmed_pair()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE delivery_receipts SET telegram_message_id=0 WHERE event_id=2")
        with self.assertRaisesRegex(InputError, "evidence_receipt_invalid"):
            inspect_receipts(self.directory, code=CODE)

    def test_same_telegram_message_id_cannot_prove_both_events(self):
        self.confirmed_pair()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE delivery_receipts SET telegram_message_id=101 WHERE event_id=2")
        with self.assertRaisesRegex(InputError, "evidence_receipt_invalid"):
            inspect_receipts(self.directory, code=CODE)

    def test_reversed_event_timestamps_cannot_prove_recovery(self):
        self.confirmed_pair()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE events SET created_at=? WHERE id=2",
                       ((NOW - timedelta(minutes=1)).isoformat(),))
        with self.assertRaisesRegex(InputError, "evidence_receipt_invalid"):
            inspect_receipts(self.directory, code=CODE)

    def test_hardlink_rejected_and_existing_history_unchanged(self):
        self.confirmed_pair()
        other = self.directory / "alias.sqlite3"
        other.hardlink_to(self.directory / DATABASE)
        with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
            inspect_receipts(self.directory, code=CODE)
        self.assertTrue(other.is_file())

    def test_encoded_directory_url_parameters_are_not_executed(self):
        with tempfile.TemporaryDirectory(prefix="hermes-evidence-parent-") as temp:
            path = Path(temp) / "outbox?mode=memory#fragment"
            path.mkdir(mode=0o700)
            persist(path, [], lambda: [], observed=NOW)
            result = inspect_receipts(path, code=CODE)
            self.assertEqual(result["status"], "NO_RECORDED_ACK_PAIR")

    def test_limit_is_bounded_and_never_claims_partial_history(self):
        self.confirmed_pair()
        with patch.object(audit, "MAX_ROWS", 1):
            with self.assertRaisesRegex(InputError, "evidence_window_exceeded"):
                inspect_receipts(self.directory, code=CODE)

    def test_unapproved_code_fails_before_reading_any_database(self):
        with self.assertRaisesRegex(InputError, "unapproved_incident_code"):
            inspect_receipts(self.directory, code="../etc/passwd")
        with self.assertRaisesRegex(InputError, "unapproved_incident_code"):
            inspect_receipts(self.directory, code=123)

    def test_cli_requires_explicit_execute_and_does_not_expose_raw_errors(self):
        with patch.object(audit, "inspect_receipts") as reader:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main(["--code", CODE]), 0)
        reader.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")
        with patch.object(audit, "inspect_receipts",
                          side_effect=InputError("SECRET NEVER OUTPUT")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main(["--execute", "--code", CODE]), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
        self.assertNotIn("SECRET", out.getvalue())


if __name__ == "__main__":
    unittest.main()
