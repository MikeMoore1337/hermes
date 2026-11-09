"""Hermes #454: signed native grant + persistent one-use receipt (synthetic only).

Exercises the real sqlite3 transactions on disposable filesystem state on
both Windows/Linux CI; never starts processes or alters original projects.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from device_fabric.native_effect_grants import NativeEffect, SCHEMA, sign_envelope
from device_fabric.native_effect_admission import (
    AdmissionDenied, LocalAdmissionConfig, NativeEffectAdmission,
)
from scripts import h15_native_effect_receipts as ledger

NOW = 1_800_000_000
KEY = b"test-only-local-key-0123456789-0123456789-0123456789"
DEVICE = "hermes-vps-native-ci"
PROJECT = "financial-horizon"
UUID = "7138d606-5cfb-41fb-8021-b0628b3e6e32"
PAYLOAD = b"fixture contents; never a real command"


def effect(*, device: str = DEVICE, project: str = PROJECT,
           action: str = "file_write", relative: str = "docs/safe.md",
           payload: bytes = PAYLOAD, uuid: str = UUID,
           expiry: int = NOW + 90) -> NativeEffect:
    return NativeEffect(SCHEMA, device, project, uuid, action, relative,
                        hashlib.sha256(payload).hexdigest(), expiry)


class AdmissionContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="h454-admission-ci-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.config = LocalAdmissionConfig(
            state_directory=self.root,
            device_id=DEVICE,
            projects=frozenset({PROJECT, "hermes"}),
            verifier_key=KEY)
        self.admission = NativeEffectAdmission(self.config, is_revoked=lambda: False)

    def signed(self, item: NativeEffect | None = None) -> bytes:
        return sign_envelope(effect() if item is None else item,
                             issuer_key=KEY, now=NOW)

    def test_verified_signed_effect_reserves_exact_scope_once(self):
        original = effect()
        receipt = self.admission.reserve(self.signed(original), PAYLOAD, now=NOW)
        self.assertEqual(receipt.device_id, DEVICE)
        self.assertEqual(receipt.project, PROJECT)
        self.assertEqual(receipt.operation, "file_write")
        self.assertEqual(receipt.operation_id, UUID)
        self.assertNotEqual(receipt.scope_sha256, original.payload_sha256)
        self.assertEqual(ledger.inspect(self.root, UUID), "reserved")
        self.assertEqual(self.admission.complete(receipt, success=True), "RECORDED")
        self.assertEqual(ledger.inspect(self.root, UUID), "completed")

    def test_replay_fails_after_completion_and_does_not_call_effect(self):
        wire = self.signed()
        receipt = self.admission.reserve(wire, PAYLOAD, now=NOW)
        self.admission.complete(receipt, success=True)
        with self.assertRaisesRegex(AdmissionDenied, "^native_admission_denied$"):
            self.admission.reserve(wire, PAYLOAD, now=NOW + 1)

    def test_replay_fails_after_failure_and_ambiguous_crash(self):
        wire = self.signed()
        receipt = self.admission.reserve(wire, PAYLOAD, now=NOW)
        self.assertEqual(ledger.inspect(self.root, UUID), "reserved")
        reconnected = NativeEffectAdmission(self.config, is_revoked=lambda: False)
        with self.assertRaises(AdmissionDenied):
            reconnected.reserve(wire, PAYLOAD, now=NOW + 1)
        self.admission.complete(receipt, success=False)
        with self.assertRaises(AdmissionDenied):
            reconnected.reserve(wire, PAYLOAD, now=NOW + 2)
        self.assertEqual(ledger.inspect(self.root, UUID), "failed")

    def test_same_uuid_cross_scope_cannot_change_project_or_payload(self):
        self.admission.reserve(self.signed(), PAYLOAD, now=NOW)
        changes = [
            effect(project="hermes"), effect(relative="docs/other.md"),
            effect(action="file_edit"), effect(payload=b"different"),
        ]
        for item in changes:
            with self.subTest(item=item), self.assertRaises(AdmissionDenied):
                self.admission.reserve(self.signed(item),
                                       b"different" if item.payload_sha256 != effect().payload_sha256 else PAYLOAD,
                                       now=NOW + 1)

    def test_wrong_device_project_key_and_tampered_payload_denied(self):
        wrong_devices = (effect(device="yfc-vps-native-ci"),
                         effect(project="not-allowed"))
        for item in wrong_devices:
            with self.assertRaises(AdmissionDenied):
                self.admission.reserve(self.signed(item), PAYLOAD, now=NOW)
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(self.signed(), b"other payload", now=NOW)
        other_config = replace(self.config, verifier_key=b"Z"*48)
        wrong_key_agent = NativeEffectAdmission(other_config, is_revoked=lambda: False)
        with self.assertRaises(AdmissionDenied):
            wrong_key_agent.reserve(self.signed(), PAYLOAD, now=NOW)

    def test_invalid_signature_and_expired_grant_denied(self):
        frame = json.loads(self.signed())
        frame["effect"]["relative"] = "docs/different.md"
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(json.dumps(frame).encode(), PAYLOAD, now=NOW)
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(self.signed(), PAYLOAD, now=NOW + 91)

    def test_revoked_identity_refuses_without_creating_effect(self):
        agent = NativeEffectAdmission(self.config, is_revoked=lambda: True)
        with self.assertRaises(AdmissionDenied):
            agent.reserve(self.signed(), PAYLOAD, now=NOW)
        self.assertFalse((self.root / "native-effects.sqlite3").exists())

    def test_revocation_error_and_nonboolean_result_fail_closed(self):
        def errors():
            raise RuntimeError("private bearer must not be printed")
        for callback in (errors, lambda: "false", lambda: None, lambda: 0):
            with self.subTest(callback=callback), self.assertRaisesRegex(
                AdmissionDenied, "^native_admission_denied$"
            ):
                NativeEffectAdmission(self.config, is_revoked=callback).reserve(
                    self.signed(), PAYLOAD, now=NOW)
        self.assertFalse((self.root / "native-effects.sqlite3").exists())

    def test_revoked_after_reservation_consumes_uuid_without_execution(self):
        outcomes = iter((False, True))
        agent = NativeEffectAdmission(self.config, is_revoked=lambda: next(outcomes))
        with self.assertRaises(AdmissionDenied):
            agent.reserve(self.signed(), PAYLOAD, now=NOW)
        self.assertEqual(ledger.inspect(self.root, UUID), "reserved")
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(self.signed(), PAYLOAD, now=NOW + 1)

    def test_parallel_identical_grants_only_one_admitted(self):
        wire = self.signed()
        def attempt(_index):
            try:
                self.admission.reserve(wire, PAYLOAD, now=NOW)
            except AdmissionDenied:
                return "refused"
            return "reserved"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(results.count("reserved"), 1)
        self.assertEqual(results.count("refused"), 15)

    def test_trusted_local_device_profile_is_not_legacy_windows_id(self):
        item = ledger.EffectIdentity(UUID, DEVICE, PROJECT, "file_write", "a"*64, NOW + 90)
        with self.assertRaisesRegex(ledger.LedgerDenied, "^effect_identity_denied$"):
            ledger.claim(self.root, item, now=NOW)
        profile = ledger.LocalLedgerScope(DEVICE, frozenset({PROJECT}))
        self.assertEqual(ledger.claim(self.root, item, now=NOW, scope=profile),
                         "RESERVED_ONCE")
        self.assertEqual(ledger.complete(self.root, item, success=True, scope=profile),
                         "RECORDED")

    def test_invalid_local_scope_and_missing_protected_state_fail_closed(self):
        for config in (
            replace(self.config, device_id="bad/device"),
            replace(self.config, projects=frozenset()),
            replace(self.config, projects=frozenset({"private/vault"})),
            replace(self.config, verifier_key=b"short"),
        ):
            with self.subTest(config=config.device_id), self.assertRaises(AdmissionDenied):
                NativeEffectAdmission(config, is_revoked=lambda: False)
        missing = replace(self.config, state_directory=self.root / "absent")
        agent = NativeEffectAdmission(missing, is_revoked=lambda: False)
        with self.assertRaises(AdmissionDenied):
            agent.reserve(self.signed(), PAYLOAD, now=NOW)

    def test_corrupt_state_is_denial_not_permission(self):
        (self.root / "native-effects.sqlite3").write_bytes(b"invalid sqlite bytes")
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(self.signed(), PAYLOAD, now=NOW)

    def test_client_boolean_cannot_approve_authorization(self):
        with self.assertRaises(TypeError):
            self.admission.reserve(self.signed(), PAYLOAD, now=NOW,
                                   approved=True)

    def test_process_command_digest_binds_without_running_shell(self):
        payload = b'["git","status","--short"]'
        item = effect(action="process_run", relative="", payload=payload)
        receipt = self.admission.reserve(self.signed(item), payload, now=NOW)
        self.assertEqual(receipt.operation, "process_run")
        self.assertEqual(ledger.inspect(self.root, receipt.operation_id), "reserved")
        with self.assertRaises(AdmissionDenied):
            self.admission.reserve(self.signed(item), b'["git","push"]', now=NOW + 1)


if __name__ == "__main__":
    unittest.main()
