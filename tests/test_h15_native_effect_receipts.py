"""Reboot-proof, fail-closed native effect ledger contracts (no host commands).

Run on Linux and Windows GitHub CI against disposable private temp dirs only.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import h15_native_effect_receipts as ledger


def identity(*, opid: str = "7138d606-5cfb-41fb-8021-b0628b3e6e32",
             device: str = ledger.DEVICE, project: str = "hermes",
             operation: str = "file_write", digest: str = "a" * 64,
             expiry: int = 1730000090) -> ledger.EffectIdentity:
    return ledger.EffectIdentity(opid, device, project, operation, digest, expiry)


class NativeEffectLedgerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-effect-ledger-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_claim_persists_across_process_connection_restarts(self):
        record = identity()
        self.assertEqual(ledger.claim(self.root, record, now=1730000000), "RESERVED_ONCE")
        # No in-memory state, no active connection: a second process or after
        # reboot sees the same on-disk ID as permanently consumed.
        self.assertEqual(ledger.inspect(self.root, record.operation_id), "reserved")
        self.assertEqual(ledger.claim(self.root, record, now=1730000001), "ALREADY_RESERVED")
        self.assertEqual(ledger.complete(self.root, record, success=True), "RECORDED")
        self.assertEqual(ledger.inspect(self.root, record.operation_id), "completed")
        self.assertEqual(ledger.claim(self.root, record, now=1730000002), "ALREADY_RESERVED")

    def test_failed_or_ambiguous_operation_cannot_auto_retry(self):
        record = identity()
        ledger.claim(self.root, record, now=1730000000)
        ledger.complete(self.root, record, success=False)
        self.assertEqual(ledger.inspect(self.root, record.operation_id), "failed")
        self.assertEqual(ledger.claim(self.root, record, now=1730000002), "ALREADY_RESERVED")
        with self.assertRaisesRegex(ledger.LedgerDenied, "receipt_identity_or_state_mismatch"):
            ledger.complete(self.root, record, success=True)

    def test_simulated_process_crash_reservation_remains_consumed(self):
        record = identity()
        ledger.claim(self.root, record, now=1730000000)
        # No completion callback happens in a process crash or timeout.
        self.assertEqual(ledger.inspect(self.root, record.operation_id), "reserved")
        self.assertEqual(ledger.claim(self.root, record, now=1730000003), "ALREADY_RESERVED")

    def test_parallel_identical_ids_only_one_reserved(self):
        record = identity()
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(
                lambda _: ledger.claim(self.root, record, now=1730000000),
                range(16)
            ))
        self.assertEqual(results.count("RESERVED_ONCE"), 1)
        self.assertEqual(results.count("ALREADY_RESERVED"), 15)

    def test_cross_scope_id_collision_does_not_reserve_twice(self):
        one = identity()
        ledger.claim(self.root, one, now=1730000000)
        for variant in [
            identity(project="your-fitness-coach"),
            identity(operation="process_run"),
            identity(digest="b" * 64),
        ]:
            self.assertEqual(ledger.claim(self.root, variant, now=1730000001),
                             "ALREADY_RESERVED")
            with self.assertRaisesRegex(ledger.LedgerDenied, "receipt_identity_or_state_mismatch"):
                ledger.complete(self.root, variant, success=False)

    def test_owner_grant_cannot_be_forged_by_a_boolean(self):
        record = identity()
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            ledger.claim(self.root, record, owner_approved=True)
        self.assertEqual(ledger.inspect(self.root, record.operation_id), "unknown")

    def test_device_project_action_digest_and_time_are_strict(self):
        bad = [
            identity(device="h15-win-05be75515428"),
            identity(project="private-vault"),
            identity(operation="powershell_arbitrary"),
            identity(digest="too-short"),
            identity(opid="not-a-uuid"),
            identity(expiry=1730000000 - 1),
            identity(expiry=1730000000 + 601),
        ]
        for item in bad:
            with self.subTest(item=item):
                with self.assertRaisesRegex(ledger.LedgerDenied, "effect_identity_denied"):
                    ledger.claim(self.root, item, now=1730000000)

    def test_invalid_completion_or_receipt_id_refused(self):
        item = identity()
        ledger.claim(self.root, item, now=1730000000)
        with self.assertRaisesRegex(ledger.LedgerDenied, "invalid_completion"):
            ledger.complete(self.root, item, success="true")
        with self.assertRaisesRegex(ledger.LedgerDenied, "invalid_operation_id"):
            ledger.inspect(self.root, "../vault")

    def test_no_auto_gc_even_if_receipts_older_than_grant(self):
        item = identity()
        ledger.claim(self.root, item, now=1730000000)
        with self.assertRaisesRegex(ledger.LedgerDenied, "effect_identity_denied"):
            ledger.claim(self.root, item, now=1730000500)
        self.assertEqual(ledger.inspect(self.root, item.operation_id), "reserved")

    def test_fail_closed_without_precreated_trusted_dir(self):
        missing = self.root / "missing-state"
        with self.assertRaisesRegex(ledger.LedgerDenied, "state_dir_not_trusted"):
            ledger.claim(missing, identity(), now=1730000000)
        self.assertFalse(missing.exists())

    def test_symlink_state_and_database_denied(self):
        target = self.root / "actual"
        target.mkdir()
        redirect = self.root / "link"
        redirect.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ledger.LedgerDenied, "state_dir_not_trusted"):
            ledger.claim(redirect, identity(), now=1730000000)
        db = self.root / "native-effects.sqlite3"
        db.symlink_to(self.root / "secret-outside")
        with self.assertRaisesRegex(ledger.LedgerDenied, "unsafe_ledger_file"):
            ledger.claim(self.root, identity(), now=1730000000)
        db.unlink()

    def test_ledger_stores_only_hash_and_identifiers_not_paths_or_commands(self):
        item = identity()
        ledger.claim(self.root, item, now=1730000000)
        rows = sqlite3.connect(self.root / "native-effects.sqlite3").execute(
            "SELECT * FROM effects"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], (item.operation_id, item.device_id, item.project,
                                   item.operation, item.scope_sha256, item.expires_at,
                                   "reserved"))
        self.assertNotIn("D:\\", str(rows))
        self.assertNotIn("powershell.exe", str(rows))
        self.assertNotIn("bearer", str(rows))

    def test_database_unavailable_does_not_return_reservation(self):
        db = self.root / "native-effects.sqlite3"
        db.write_bytes(b"not a SQLite database")
        with self.assertRaises(ledger.LedgerDenied):
            ledger.claim(self.root, identity(), now=1730000000)

    def test_full_ledger_never_prunes_old_receipts(self):
        item = identity()
        with patch.object(ledger, "MAX_RECORDS", 0):
            with self.assertRaisesRegex(ledger.LedgerDenied, "receipt_capacity_exhausted"):
                ledger.claim(self.root, item, now=1730000000)
        self.assertEqual(ledger.inspect(self.root, item.operation_id), "unknown")

    def test_schema_typed_outputs_no_command_or_file_content(self):
        self.assertEqual(ledger.SCHEMA, "h454-native-effect-ledger-v1")
        self.assertEqual(ledger.OPERATIONS, frozenset({
            "file_write", "file_edit", "file_delete", "process_run",
        }))
        self.assertEqual(len(ledger.PROJECTS), 4)


if __name__ == "__main__":
    unittest.main()
