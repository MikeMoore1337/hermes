"""H454 restored-pair re-arm: real temporary inode tests, no live Docker."""
from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from scripts import h454_native3_restored_rearm as rearm


SOURCE = "a" * 40
CANDIDATE = "b" * 40
ARCHIVE = "c" * 64
IMAGE = "sha256:" + "d" * 64
RUNTIME = "sha256:" + "e" * 64
RELAY_ID = "f" * 64
PROXY_ID = "1" * 64
PINNED = b'{"synthetic":"restored-owner-pair"}\n'


class RestoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-restored-rearm-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "owner-private"
        self.root.mkdir(mode=0o700)
        self.original = self.root / "native3-original-pins.json"
        self.current = self.root / "pins.json"
        for path in (self.original, self.current):
            path.write_bytes(PINNED)
            path.chmod(0o600)
        self.archive = self.root / "native3-rearm-evidence"
        self.proof = rearm.Verified(
            SOURCE, CANDIDATE, hashlib.sha256(PINNED).hexdigest(),
            PINNED, RELAY_ID, PROXY_ID, RUNTIME, 3,
        )

    def variables(self):
        return (
            patch.object(rearm, "ROOT", self.root),
            patch.object(rearm, "RETAINED", self.original),
            patch.object(rearm, "EVIDENCE", self.archive),
        )

    def attest_context(self):
        return (
            patch.object(rearm.pair, "verify_installed_source"),
            patch.object(rearm.pair.legacy, "lock",
                         side_effect=lambda: nullcontext()),
            patch.object(rearm.pair.legacy, "check_files"),
            patch.object(rearm.pair.stage1, "protected"),
            patch.object(rearm.pair.candidate, "admit",
                         return_value={
                             "status": "PREFLIGHT_PASS",
                             "bundle_verified": True,
                             "changes_performed": False,
                             "deployment_approved": False,
                             "current_image": rearm.pair.stage1.FORK_IMAGE,
                             "candidate_image": RUNTIME,
                         }),
            patch.object(rearm.pair.stage1, "load_existing_wss",
                         return_value=Mock()),
            patch.object(rearm.pair, "verify_pair",
                         return_value=(
                             {"Id": RELAY_ID,
                              "Image": rearm.pair.stage1.FORK_IMAGE},
                             {"Id": PROXY_ID,
                              "Image": rearm.pair.stage1.LEGACY_IMAGE},
                         )),
            patch.object(rearm.pair, "check_free_checkpoints"),
            patch.object(rearm.pair.stage1, "locked_pins",
                         side_effect=lambda: nullcontext(
                             self.current.read_bytes()
                         )),
            patch.object(rearm.pair.legacy, "devices", return_value=3),
            patch.object(rearm.pair.stage1, "PINS", self.current),
            patch.object(rearm.pair.stage1, "PENDING",
                         self.root / "reconcile.pending"),
            patch.object(rearm.pair, "PAIR_PENDING",
                         self.root / "native3-pair.pending"),
            patch.object(rearm.os, "geteuid", return_value=0),
        )

    def with_all_contexts(self, action, *, mocks=()):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for ctx in (*self.variables(), *self.attest_context(), *mocks):
                stack.enter_context(ctx)
            return action()

    def args(self):
        return dict(
            source_sha=SOURCE, candidate_sha=CANDIDATE,
            bundle=Path("/synthetic-offline-artifact"),
            image=IMAGE, archive_sha=ARCHIVE,
        )

    def test_restored_pair_plan_is_read_only_and_marker_stays(self):
        def check():
            proof = rearm.plan(**self.args())
            self.assertEqual(proof.digest, self.proof.digest)
            self.assertEqual(proof.relay_id, RELAY_ID)
            self.assertFalse(self.archive.exists())
            self.assertEqual(self.original.read_bytes(), PINNED)
        self.with_all_contexts(check)

    def test_exact_tty_rearm_archives_bytes_and_receipt_without_docker_mutation(self):
        confirm = Mock()
        def check():
            proof = rearm.rearm(**self.args())
            self.assertEqual(proof, self.proof)
            self.assertFalse(self.original.exists())
            self.assertEqual(self.current.read_bytes(), PINNED)
            evidence = self.archive / (
                "native3-original-pins-" + proof.digest + ".json"
            )
            receipt = self.archive / (
                "native3-rearm-" + proof.digest + ".receipt.json"
            )
            self.assertEqual(evidence.read_bytes(), PINNED)
            doc = json.loads(receipt.read_bytes())
            self.assertEqual(doc["status"], "PREVIOUS_ROLLBACK_EVIDENCE_RETAINED")
            self.assertEqual(doc["original_pins_sha256"], proof.digest)
            self.assertEqual(doc["original_relay_id"], RELAY_ID)
            self.assertEqual(doc["original_proxy_id"], PROXY_ID)
            self.assertIs(doc["cutover_authorized"], False)
            self.assertIs(doc["native_service_activation_authorized"], False)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.archive.stat().st_mode & 0o777, 0o700)
        self.with_all_contexts(check, mocks=(
            patch.object(rearm, "_owner_confirmation", confirm),
        ))
        confirm.assert_called_once()

    def test_missing_and_loose_or_symlinked_marker_fail_without_archive(self):
        for variant in ("missing", "loose", "symlink"):
            with self.subTest(variant=variant):
                self.original.unlink(missing_ok=True)
                if variant == "loose":
                    self.original.write_bytes(PINNED)
                    self.original.chmod(0o644)
                if variant == "symlink":
                    self.original.symlink_to(self.current)
                if variant == "missing":
                    pass
                with self.variables()[0], self.variables()[1], self.variables()[2]:
                    with self.assertRaises(rearm.RearmDenied):
                        rearm._archive_restored(self.proof)
                self.assertFalse(self.archive.exists())
        # Restore the normal synthetic marker for later independent tests.
        self.original.unlink(missing_ok=True)

    def test_mismatched_retained_bytes_fail_without_evidence(self):
        self.original.write_bytes(b"synthetic-drift\n")
        with self.variables()[0], self.variables()[1], self.variables()[2]:
            with self.assertRaises(rearm.RearmDenied):
                rearm._archive_restored(self.proof)
        self.assertFalse(self.archive.exists())
        self.assertTrue(self.original.exists())

    def test_occupied_evidence_never_overwritten(self):
        self.archive.mkdir(mode=0o700)
        evidence = self.archive / (
            "native3-original-pins-" + self.proof.digest + ".json"
        )
        evidence.write_bytes(b"existing-evidence")
        evidence.chmod(0o600)
        with self.variables()[0], self.variables()[1], self.variables()[2]:
            with self.assertRaisesRegex(
                rearm.RearmDenied, "RECOVERY_ALREADY_ARCHIVED_OR_INTERRUPTED"
            ):
                rearm._archive_restored(self.proof)
        self.assertEqual(evidence.read_bytes(), b"existing-evidence")
        self.assertEqual(self.original.read_bytes(), PINNED)

    def test_interrupted_archive_does_not_clear_marker(self):
        original_write = rearm._write_once
        def fail_receipt(path, contents):
            if path.name.endswith(".receipt.json"):
                raise OSError("synthetic disk full")
            return original_write(path, contents)
        with self.variables()[0], self.variables()[1], self.variables()[2], \
             patch.object(rearm, "_write_once", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                rearm._archive_restored(self.proof)
        self.assertEqual(self.original.read_bytes(), PINNED)
        self.assertEqual(self.current.read_bytes(), PINNED)
        self.assertTrue(any(self.archive.iterdir()))

    def test_changed_live_pin_during_approval_is_denied(self):
        def change_without_approval(_):
            self.current.write_bytes(b'{"synthetic":"drift"}\n')
        def check():
            with self.assertRaises(rearm.RearmDenied):
                rearm.rearm(**self.args())
        self.with_all_contexts(check, mocks=(
            patch.object(rearm, "_owner_confirmation",
                         side_effect=change_without_approval),
        ))
        self.assertEqual(self.original.read_bytes(), PINNED)
        self.assertFalse(self.archive.exists())

    def test_present_pending_marker_refuses_and_does_not_archive(self):
        marker = self.root / "native3-pair.pending"
        marker.write_bytes(b"synthetic-inflight")
        def check():
            with self.assertRaisesRegex(
                rearm.RearmDenied, "RECOVERY_PENDING_TRANSACTION"
            ):
                rearm.plan(**self.args())
        self.with_all_contexts(check)
        self.assertTrue(marker.is_file())
        self.assertFalse(self.archive.exists())

    def test_mutating_cli_requires_execute_and_tty(self):
        args = [
            "rearm", "--release-sha", SOURCE,
            "--candidate-sha", CANDIDATE,
            "--bundle-dir", "/synthetic",
            "--image", IMAGE,
            "--archive-sha", ARCHIVE,
        ]
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(rearm.main(args), 2)
        self.assertIn("RECOVERY_EXPLICIT_EXECUTE_REQUIRED", out.getvalue())
        with patch.object(rearm.os, "geteuid", return_value=0), \
             patch.object(rearm.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(
                rearm.RearmDenied, "RECOVERY_INTERACTIVE_ROOT_TTY_REQUIRED"
            ):
                rearm._owner_confirmation(self.proof)
        self.assertEqual(self.original.read_bytes(), PINNED)


if __name__ == "__main__":
    unittest.main()
