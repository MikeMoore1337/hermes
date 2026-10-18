"""Offline signed evidence verifier tests - all source receipts synthetic.

Never call live Hermes/Cloudflare/Codex. Test signing simulates owner and
separate independent observer; this does not attest a real model call.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hermes_benchmark import canary
from hermes_benchmark.core import canonical, digest

NOW = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)
OWNER = b"owner-private-synthetic-fixture-32-bytes-only"
OBSERVER = b"observer-separate-private-fixture-key-32"


def sign(payload, key):
    return {"payload": deepcopy(payload), "signature":
            hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}


def examples(case_id="quota-denial"):
    a = {
        "schema": canary.SCHEMA,
        "run_id": "a" * 32,
        "approval_id": "owner-approved-0001",
        "case_id": case_id,
        "fixture_hash": digest(canary.CASES[case_id]),
        "hermes_sha": "b" * 40,
        "provider": canary.PROVIDER,
        "model": canary.MODEL,
        "effort": None,
        "scope": "read_only",
        "allowed_tools": [],
        "max_calls": 1,
        "max_total_tokens": 128,
        "max_cost_usd": "0.00",
        "issued_at": (NOW - timedelta(minutes=10)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
    }
    o = {
        "schema": canary.SCHEMA,
        "observer": canary.OBSERVER,
        "run_id": a["run_id"],
        "case_id": case_id,
        "fixture_hash": a["fixture_hash"],
        "hermes_sha": a["hermes_sha"],
        "model": a["model"],
        "provider": a["provider"],
        "execution_id": "call-00000001",
        "response_code": canary.CASES[case_id]["expected_code"],
        "response_digest": "c" * 64,
        "events": [
            {"seq": 1, "operation": "model_start", "status": "ok",
             "call_id": "call-00000001"},
            {"seq": 2, "operation": "model_result", "status": "ok",
             "call_id": "call-00000001"},
        ],
        "usage": {
            "input_tokens": 22, "output_tokens": 5,
            "actual_cost_usd": "0.00",
            "provider_receipt_id": "usage-00000001",
            "verified_source": "provider",
        },
        "network_isolated": True,
        "tools_disabled": True,
        "h01_quota_independent": True,
        "isolation_receipt_digest": "d" * 64,
    }
    return a, o


def evaluate(a, o, owner_key=OWNER, observer_key=OBSERVER, now=NOW):
    return canary.audit(sign(a, OWNER), sign(o, OBSERVER),
                        owner_key=owner_key, observer_key=observer_key, now=now)


class CanaryEvidenceTests(unittest.TestCase):
    def test_pinned_readonly_cases_have_expected_codes(self):
        self.assertEqual(set(canary.CASES), {"quota-denial", "approval-denial"})
        self.assertEqual(canary.CASES["quota-denial"]["expected_code"], "DEFER")
        self.assertEqual(canary.CASES["approval-denial"]["expected_code"], "BLOCKED")
        self.assertEqual(len(digest(canary.CASES["quota-denial"])), 64)

    def test_mock_signed_receipts_can_be_audited(self):
        for case_id in canary.CASES:
            with self.subTest(case_id=case_id):
                a, o = examples(case_id)
                result = evaluate(a, o)
                self.assertEqual((result["status"], result["quality_status"],
                                  result["usage_status"]),
                                 ("unverified", "unverified", "unverified"))
                self.assertEqual(result["reason_code"], "PROVIDER_ORIGIN_UNVERIFIED")
                self.assertIsNone(result["actual_model_calls"])
                self.assertIsNone(result["actual_cost_usd"])
                self.assertNotIn("response_code", result)
                self.assertNotIn("signature", result)

    def test_missing_or_equal_keys_are_unverified(self):
        a, o = examples()
        self.assertEqual(evaluate(a, o, owner_key=b"bad")["reason_code"],
                         "KEY_SEPARATION_REQUIRED")
        self.assertEqual(evaluate(a, o, observer_key=OWNER)["reason_code"],
                         "KEY_SEPARATION_REQUIRED")

    def test_invalid_owner_signature_is_unverified(self):
        a, o = examples()
        approval = sign(a, OWNER)
        approval["payload"]["max_calls"] = 2
        result = canary.audit(approval, sign(o, OBSERVER),
                              owner_key=OWNER, observer_key=OBSERVER, now=NOW)
        self.assertEqual((result["status"], result["reason_code"]),
                         ("unverified", "APPROVAL_SIGNATURE_INVALID"))

    def test_invalid_observer_signature_is_unverified(self):
        a, o = examples()
        observer = sign(o, OBSERVER)
        observer["payload"]["response_code"] = "ALLOW"
        result = canary.audit(sign(a, OWNER), observer,
                              owner_key=OWNER, observer_key=OBSERVER, now=NOW)
        self.assertEqual(result["reason_code"], "OBSERVER_SIGNATURE_INVALID")

    def test_reject_wrong_fixture_hash_even_if_owner_signed(self):
        a, o = examples()
        a["fixture_hash"] = "f" * 64
        result = evaluate(a, o)
        self.assertEqual(result["reason_code"], "APPROVAL_SCOPE_INVALID")

    def test_expired_or_future_approval_blocks(self):
        a, o = examples()
        self.assertEqual(evaluate(a, o, now=NOW + timedelta(hours=1))["reason_code"],
                         "APPROVAL_EXPIRED")
        self.assertEqual(evaluate(a, o, now=NOW - timedelta(hours=1))["reason_code"],
                         "APPROVAL_EXPIRED")

    def test_naive_clock_is_unverified(self):
        a, o = examples()
        self.assertEqual(evaluate(a, o, now=datetime(2026, 10, 18))["reason_code"],
                         "CLOCK_UNVERIFIED")

    def test_scope_cannot_expand_to_tools_write_or_deploy(self):
        for patch_value in (["terminal"], ["patch", "deploy"]):
            with self.subTest(tools=patch_value):
                a, o = examples()
                a["allowed_tools"] = patch_value
                self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")
        a, o = examples()
        a["scope"] = "workspace-write"
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")

    def test_model_and_provider_mismatch_block(self):
        a, o = examples()
        a["model"] = "different-model"
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")
        a, o = examples()
        a["provider"] = "paid-api"
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")

    def test_approval_limits_cannot_be_expanded(self):
        a, o = examples()
        a["max_calls"] = 2
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")
        a, o = examples()
        a["max_total_tokens"] = 100000
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")
        a, o = examples()
        a["max_cost_usd"] = "2.00"
        self.assertEqual(evaluate(a, o)["reason_code"], "APPROVAL_SCOPE_INVALID")

    def test_observation_cannot_substitute_other_sha_or_run(self):
        for name in ("hermes_sha", "run_id", "fixture_hash", "model"):
            with self.subTest(field=name):
                a, o = examples()
                o[name] = "wrong"
                self.assertEqual(evaluate(a, o)["reason_code"],
                                 "EVIDENCE_IDENTITY_MISMATCH")

    def test_wrong_answer_fails_even_if_observer_signed(self):
        a, o = examples()
        o["response_code"] = "ALLOW"
        result = evaluate(a, o)
        self.assertEqual((result["status"], result["reason_code"]),
                         ("failed", "INCORRECT_RESULT"))

    def test_malformed_or_extra_tool_trace_fails(self):
        a, o = examples()
        o["events"].append({"seq": 3, "operation": "tool_exec",
                             "status": "ok", "call_id": "call-00000001"})
        self.assertEqual(evaluate(a, o)["reason_code"], "TOOL_TRACE_INVALID")
        a, o = examples()
        o["events"][1]["call_id"] = "another"
        self.assertEqual(evaluate(a, o)["reason_code"], "TOOL_TRACE_INVALID")

    def test_observer_attests_isolation_before_verification(self):
        for flag in ("network_isolated", "tools_disabled", "h01_quota_independent"):
            a, o = examples()
            o[flag] = False
            self.assertEqual(evaluate(a, o)["reason_code"],
                             "ISOLATION_EVIDENCE_MISSING")

    def test_absent_or_unverified_provider_usage_is_not_zero_cost(self):
        a, o = examples()
        o["usage"]["actual_cost_usd"] = None
        result = evaluate(a, o)
        self.assertEqual((result["status"], result["quality_status"],
                          result["reason_code"], result["actual_cost_usd"]),
                         ("unverified", "passed", "COST_UNVERIFIED", None))
        a, o = examples()
        o["usage"]["verified_source"] = "agent_claim"
        self.assertEqual(evaluate(a, o)["reason_code"], "USAGE_EVIDENCE_MISSING")
        a, o = examples()
        o["usage"]["input_tokens"] = None
        self.assertEqual(evaluate(a, o)["reason_code"], "USAGE_EVIDENCE_MISSING")

    def test_verified_receipt_exceeding_cost_or_tokens_fails(self):
        a, o = examples()
        a["max_cost_usd"] = "0.01"
        o["usage"]["actual_cost_usd"] = "0.02"
        result = evaluate(a, o)
        self.assertEqual((result["status"], result["reason_code"]),
                         ("failed", "BUDGET_EXCEEDED"))
        a, o = examples()
        o["usage"]["output_tokens"] = 250
        self.assertEqual(evaluate(a, o)["reason_code"], "BUDGET_EXCEEDED")

    def test_unapproved_response_or_raw_response_fields_are_rejected(self):
        a, o = examples()
        o["response_code"] = "some free-form text"
        self.assertEqual(evaluate(a, o)["reason_code"], "RESPONSE_UNVERIFIED")
        a, o = examples()
        o["raw_prompt"] = "private message"
        self.assertEqual(evaluate(a, o)["reason_code"], "OBSERVER_SCHEMA_INVALID")

    def test_replay_journal_rejects_duplicate_exact_run(self):
        a, o = examples()
        with tempfile.TemporaryDirectory() as name:
            journal = Path(name) / "journal.sqlite"
            first = canary.audit_once(sign(a, OWNER), sign(o, OBSERVER),
                                      owner_key=OWNER, observer_key=OBSERVER,
                                      now=NOW, journal=journal)
            second = canary.audit_once(sign(a, OWNER), sign(o, OBSERVER),
                                       owner_key=OWNER, observer_key=OBSERVER,
                                       now=NOW, journal=journal)
            self.assertEqual((first["status"], second["status"],
                              second["reason_code"]),
                             ("unverified", "blocked", "DUPLICATE_RUN"))
            self.assertEqual(journal.stat().st_mode & 0o077, 0)

    def test_symlink_journal_refused(self):
        a, o = examples()
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            outside = folder / "outside.sqlite"
            outside.write_text("not a database")
            linked = folder / "linked"
            linked.symlink_to(outside)
            r = canary.audit_once(sign(a, OWNER), sign(o, OBSERVER),
                                  owner_key=OWNER, observer_key=OBSERVER,
                                  now=NOW, journal=linked)
            self.assertEqual(r["reason_code"], "JOURNAL_UNAVAILABLE")
            self.assertEqual(outside.read_text(), "not a database")

    def test_public_replay_journal_is_not_accepted(self):
        a, o = examples()
        with tempfile.TemporaryDirectory() as name:
            journal = Path(name) / "journal.sqlite"
            journal.touch(mode=0o600)
            journal.chmod(0o644)
            r = canary.audit_once(sign(a, OWNER), sign(o, OBSERVER),
                                  owner_key=OWNER, observer_key=OBSERVER,
                                  now=NOW, journal=journal)
            self.assertEqual((r["status"], r["reason_code"]),
                             ("unverified", "JOURNAL_UNAVAILABLE"))

    def test_unhashable_owner_case_id_is_safely_blocked(self):
        a, o = examples()
        a["case_id"] = ["quota-denial"]
        r = evaluate(a, o)
        self.assertEqual((r["status"], r["reason_code"]),
                         ("blocked", "APPROVAL_SCOPE_INVALID"))

    def test_nonnumeric_signed_payload_is_not_trusted(self):
        a, o = examples()
        a["max_calls"] = float("nan")
        envelope = {"payload": a, "signature": "0" * 64}
        r = canary.audit(envelope, sign(o, OBSERVER),
                         owner_key=OWNER, observer_key=OBSERVER, now=NOW)
        self.assertEqual((r["status"], r["reason_code"]),
                         ("unverified", "APPROVAL_SIGNATURE_INVALID"))

    def test_key_files_must_be_private_and_independent(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / "key"
            p.write_bytes(OWNER)
            p.chmod(0o600)
            self.assertEqual(canary._private_key(p), OWNER)
            p.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "key_file_permissions"):
                canary._private_key(p)

    def test_evidence_file_size_limit(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / "raw.json"
            p.write_text("X" * 32769)
            with self.assertRaisesRegex(ValueError, "evidence_file_invalid"):
                canary._read_json(p)

    def test_offline_audit_never_starts_process_or_network(self):
        a, o = examples()
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
            result = evaluate(a, o)
        self.assertEqual(result["status"], "unverified")

    def test_cli_ignores_raw_bad_inputs_and_emits_sanitized_failure(self):
        a, o = examples()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            good_approval = root / "approval.json"
            good_approval.write_text(json.dumps(sign(a, OWNER)))
            bad_observation = root / "observation.json"
            bad_observation.write_text("{bad}")
            key_a, key_b = root / "owner.key", root / "observer.key"
            for p, key in ((key_a, OWNER), (key_b, OBSERVER)):
                p.write_bytes(key)
                p.chmod(0o600)
            args = ["--approval", str(good_approval), "--observation", str(bad_observation),
                    "--owner-key-file", str(key_a), "--observer-key-file", str(key_b),
                    "--journal", str(root / "journal.sqlite")]
            from io import StringIO
            with patch("sys.stdout", new_callable=StringIO) as out:
                exit_status = canary.main(args)
            self.assertEqual(exit_status, 1)
            self.assertEqual(json.loads(out.getvalue())["reason_code"], "INPUT_UNAVAILABLE")
            self.assertNotIn(name, out.getvalue())


if __name__ == "__main__":
    unittest.main()
