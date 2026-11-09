"""H454 owner-decision issuance: synthetic OS-private SQLite; NO owner login.

Tests exercise a source-only verifier using disposable unsigned fixtures
and synthetic HMAC keys. No real owner approval, MCP, host or secrets.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_owner_issuer import (
    SCHEMA, OwnerDecision, LocalOwnerIssuerConfig,
    OwnerIssuerDenied, NativeOwnerGrantIssuer,
    seal_owner_decision, verify_owner_decision,
)
from device_fabric.native_effect_grants import (
    SCHEMA as EFFECT_SCHEMA, NativeEffect, verify_envelope,
)
from scripts import h15_native_effect_receipts as ledger

NOW = 1_800_000_000
AUTHORITY_KEY = b"synthetic-owner-authority-key-0123456789abcdef"
DEVICE_KEY = b"synthetic-native-device-signer-key-0123456789abcdef"
BAD_KEY = b"z" * 48
DEVICE = "h454-vps-issuer-ci"
OWNER = "owner-h454-test"
PROJECT = "hermes"
OPID = "7138d606-5cfb-41fb-8021-b0628b3e6e32"
PAYLOAD = b"test-only owner reviewed file contents"


@unittest.skipUnless(sys.platform == "linux"
                     and hasattr(os, "geteuid") and os.geteuid() != 0,
                     "one-time owner issuer requires unprivileged Linux")
class OwnerGrantIssuerContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-owner-decision-ci-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "private-issuer-state"
        self.state.mkdir(mode=0o700)
        self.config = LocalOwnerIssuerConfig(
            state_directory=self.state,
            owner_id=OWNER, device_id=DEVICE,
            projects=frozenset({PROJECT, "financial-horizon"}),
            authority_verifier_key=AUTHORITY_KEY,
            device_issuer_key=DEVICE_KEY,
        )
        self.issuer = NativeOwnerGrantIssuer(
            self.config, is_device_revoked=lambda: False)

    def effect(self, *, payload=PAYLOAD, device=DEVICE, project=PROJECT,
               opid=OPID, action="file_write", relative="docs/new.md",
               expiry=NOW + 90):
        return NativeEffect(
            EFFECT_SCHEMA, device, project, opid, action, relative,
            hashlib.sha256(payload).hexdigest(), expiry)

    def ticket(self, effect=None, *, owner=OWNER, approved_at=NOW,
               key=AUTHORITY_KEY):
        item = self.effect() if effect is None else effect
        return seal_owner_decision(
            OwnerDecision(SCHEMA, owner, approved_at, item),
            authority_key=key)

    def issue(self, ticket=None, payload=PAYLOAD, *, now=NOW, issuer=None):
        with patch("device_fabric.native_owner_issuer.time.time", return_value=now):
            return (self.issuer if issuer is None else issuer).issue(
                self.ticket() if ticket is None else ticket, payload)

    def test_exact_owner_approval_consumed_and_native_grant_signed(self):
        decision = self.ticket()
        self.assertEqual(
            verify_owner_decision(
                decision, authority_key=AUTHORITY_KEY,
                expected_owner=OWNER, now=NOW).effect,
            self.effect())
        frame = self.issue(decision)
        verified = verify_envelope(
            frame, PAYLOAD, verifier_key=DEVICE_KEY,
            expected_device_id=DEVICE, allowed_projects=frozenset({PROJECT}),
            now=NOW)
        self.assertEqual(verified.effect.operation_id, OPID)
        self.assertEqual(verified.effect.project, PROJECT)
        self.assertEqual(verified.effect.action, "file_write")
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")
        self.assertNotIn(PAYLOAD, frame)
        self.assertNotIn(AUTHORITY_KEY, frame)
        self.assertNotIn(DEVICE_KEY, frame)

    def test_issue_cannot_repeat_same_ticket_even_with_fresh_issuer(self):
        self.issue()
        newer = NativeOwnerGrantIssuer(
            self.config, is_device_revoked=lambda: False)
        with self.assertRaisesRegex(OwnerIssuerDenied, "^native_owner_issuer_denied$"):
            self.issue(issuer=newer)
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")

    def test_distinct_approvals_one_device_are_independent(self):
        first = self.issue()
        other = self.effect(
            payload=b"second", opid="6138d606-5cfb-41fb-8021-b0628b3e6e33",
            relative="docs/second.md")
        second = self.issue(self.ticket(other), b"second")
        self.assertNotEqual(first, second)
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")
        self.assertEqual(ledger.inspect(self.state, other.operation_id), "completed")

    def test_sixteen_concurrent_issuers_consume_ticket_once(self):
        wire = self.ticket()
        def attempt(_):
            try:
                self.issue(wire)
                return "issued"
            except OwnerIssuerDenied:
                return "denied"
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(16)))
        self.assertEqual(outcomes.count("issued"), 1)
        self.assertEqual(outcomes.count("denied"), 15)
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")

    def test_forged_client_approved_flag_cannot_authorize(self):
        original = self.ticket()
        wire = json.loads(original)
        for altered in (
                {"decision": dict(wire["decision"], approved=True),
                 "mac": wire["mac"]},
                {"owner_approved": True, **wire},
                {"decision": wire["decision"],
                 "mac": BAD_KEY.hex()[:64]},
        ):
            with self.subTest(altered=str(altered)[:25]):
                candidate = json.dumps(altered, separators=(",", ":")).encode()
                with self.assertRaises(OwnerIssuerDenied):
                    self.issue(candidate)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_owner_device_scope_and_secret_mismatch_denied(self):
        attempts = (
            self.ticket(owner="other-owner"),
            self.ticket(self.effect(device="h454-other-device")),
            self.ticket(self.effect(project="second-brain")),
            self.ticket(key=BAD_KEY),
        )
        for wire in attempts:
            with self.subTest(which=wire[:30]):
                with self.assertRaisesRegex(OwnerIssuerDenied, "^native_owner_issuer_denied$"):
                    self.issue(wire)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_wrong_payload_or_tampered_path_does_not_consume(self):
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(payload=b"different")
        decoded = json.loads(self.ticket())
        decoded["decision"]["effect"]["relative"] = "docs/evil.md"
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(json.dumps(decoded, sort_keys=True,
                                  separators=(",", ":")).encode())
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_duplicate_fields_and_noncanonical_json_denied(self):
        valid = self.ticket()
        obj = json.loads(valid)
        duplicate = valid.replace(b'"owner_id":', b'"owner_id":"wrong","owner_id":', 1)
        padded = b" " + valid
        reordered = json.dumps(obj).encode()
        for wire in (duplicate, padded, reordered, b"{}", b"[]", b"", b"\xff"):
            with self.subTest(wire=wire[:20]), self.assertRaises(OwnerIssuerDenied):
                self.issue(wire)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_expired_owner_decision_and_effect_denied(self):
        expired_effect = self.effect(expiry=NOW - 4)
        older = self.ticket(expired_effect, approved_at=NOW - 602)
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(older)
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(self.ticket(), now=NOW + 91)
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(self.ticket(), now=NOW - 1)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_revocation_before_issuance_never_touches_ledger(self):
        denied = NativeOwnerGrantIssuer(
            self.config, is_device_revoked=lambda: True)
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(issuer=denied)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_revocation_after_durable_reservation_consumes_uuid_forever(self):
        sequence = iter((False, False, True))
        issuer = NativeOwnerGrantIssuer(
            self.config, is_device_revoked=lambda: next(sequence))
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(issuer=issuer)
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")
        with self.assertRaises(OwnerIssuerDenied):
            self.issue()
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_untrusted_state_permissions_or_symlink_denied(self):
        self.state.chmod(0o755)
        with self.assertRaises(OwnerIssuerDenied):
            NativeOwnerGrantIssuer(self.config, is_device_revoked=lambda: False)
        self.state.chmod(0o700)
        redirect = self.root / "symlink-to-state"
        redirect.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(OwnerIssuerDenied):
            NativeOwnerGrantIssuer(
                replace(self.config, state_directory=redirect),
                is_device_revoked=lambda: False)

    def test_identical_owner_authority_and_device_keys_denied(self):
        with self.assertRaises(OwnerIssuerDenied):
            NativeOwnerGrantIssuer(
                replace(self.config, device_issuer_key=AUTHORITY_KEY),
                is_device_revoked=lambda: False)

    def test_issuer_does_not_store_absolute_paths_payload_or_signing_keys(self):
        self.issue()
        db = self.state / "native-effects.sqlite3"
        with sqlite3.connect(db) as connection:
            row = connection.execute(
                "SELECT operation_id,device_id,project,operation,"
                "scope_sha256,expires_at,state FROM effects"
            ).fetchone()
        self.assertEqual(row[0], OPID)
        self.assertEqual(row[2], PROJECT)
        self.assertEqual(row[-1], "completed")
        self.assertNotIn(b"docs/new.md", db.read_bytes())
        self.assertNotIn(PAYLOAD, db.read_bytes())
        self.assertNotIn(AUTHORITY_KEY, db.read_bytes())
        self.assertNotIn(DEVICE_KEY, db.read_bytes())

    def test_process_ticket_can_bind_exact_argv_payload(self):
        payload = b'{"argv":["/usr/bin/git","status","--short"],"timeout_seconds":5}'
        effect = self.effect(
            payload=payload, action="process_run", relative="")
        frame = self.issue(self.ticket(effect), payload)
        result = verify_envelope(
            frame, payload, verifier_key=DEVICE_KEY,
            expected_device_id=DEVICE,
            allowed_projects=frozenset({PROJECT}), now=NOW)
        self.assertEqual(result.effect.action, "process_run")
        self.assertEqual(result.effect.relative, "")

    def test_oversize_payload_is_never_issued(self):
        huge = b"X" * (256 * 1024 + 1)
        with self.assertRaises(OwnerIssuerDenied):
            self.issue(self.ticket(self.effect(payload=huge)), huge)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
