"""H-480: offline-only typed tool contract and negative effect oracle."""
from __future__ import annotations

from copy import deepcopy
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_toolperf.call_cases import load_cases, run_negative_corpus
from hermes_toolperf.call_contract import (
    ContractDenied, MAX_DEPTH, MAX_STEPS, SCHEMA, SyntheticSession,
    canonical, fixture,
)


def call(session, payload=None, **kwargs):
    return session.dispatch(json.dumps(fixture() if payload is None else payload),
                            **kwargs)


class ToolCallContracts(unittest.TestCase):
    def test_pinned_negative_corpus_denies_all_without_effects(self):
        report = run_negative_corpus()
        self.assertEqual(report["schema"], "h480-contract-eval-v1")
        self.assertEqual((report["total"], report["passed"]), (18, 18))
        self.assertEqual(len({x["fixture_sha256"] for x in report["results"]}), 18)
        self.assertEqual(report["live_tool_enforcement"], "NOT_VERIFIED")
        self.assertIsNone(report["model_cost"])
        self.assertEqual(load_cases()["schema_version"], 1)

    def test_allowed_write_produces_one_trusted_effect(self):
        session = SyntheticSession()
        receipt = call(session)
        self.assertEqual(receipt, {"status": "OK", "reason": "OK"})
        self.assertEqual(session.files["docs/note.txt"], "new\n")
        self.assertEqual(len(session.effects), 1)
        self.assertEqual(session.ledger["call-test-0001"]["status"], "OK")
        raw_response = json.dumps({
            "schema_version": SCHEMA, "tool_call_id": "call-test-0001",
            "status": "ok", "output": "written",
        })
        self.assertEqual(session.verify_response(raw_response),
                         {"status": "VERIFIED"})

    def test_allowed_read_requires_null_approval_and_no_effect(self):
        session = SyntheticSession()
        receipt = call(session, fixture(tool="mock.read_file"))
        self.assertEqual(receipt["status"], "OK")
        self.assertEqual(session.ledger["call-test-0001"]["output"], "old\n")
        self.assertEqual(session.effects, [])
        self.assertEqual(session.files["docs/note.txt"], "old\n")

    def test_expired_approval_denies_without_mutation(self):
        session = SyntheticSession(approval_expires_at=1699999999)
        self.assertEqual(call(session)["reason"], "APPROVAL_DENIED")
        self.assertEqual(session.effects, [])
        self.assertEqual(session.files["docs/note.txt"], "old\n")

    def test_duplicate_call_idempotency_and_ambiguous_ack_no_retry(self):
        session = SyntheticSession()
        self.assertEqual(call(session, ack_lost=True)["status"], "UNKNOWN")
        self.assertEqual(len(session.effects), 1)
        self.assertEqual(session.ledger["call-test-0001"]["status"], "UNKNOWN")

        duplicate = fixture(step=2)
        self.assertEqual(call(session, duplicate)["reason"], "DUPLICATE_TOOL_CALL")
        repeat_with_new_call = fixture(
            step=3, tool_call_id="call-test-0002")
        self.assertEqual(call(session, repeat_with_new_call)["reason"],
                         "DUPLICATE_IDEMPOTENCY")
        bypass = fixture(step=4, tool_call_id="call-test-0003",
                         idempotency_key="idem-test-0003")
        self.assertEqual(call(session, bypass)["reason"],
                         "UNRESOLVED_WRITE_BLOCKS_DISPATCH")
        self.assertEqual(len(session.effects), 1)
        self.assertEqual(session.files["docs/note.txt"], "new\n")

    def test_step_overflow_cannot_write(self):
        session = SyntheticSession()
        for n in range(1, MAX_STEPS + 1):
            p = fixture(tool="mock.read_file", step=n,
                        tool_call_id=f"call-test-{n:04d}",
                        idempotency_key=f"idem-test-{n:04d}")
            self.assertEqual(call(session, p)["status"], "OK")
        extra = fixture(step=MAX_STEPS + 1,
                        tool_call_id="call-test-last",
                        idempotency_key="idem-test-last")
        self.assertEqual(call(session, extra)["reason"], "STEP_BUDGET")
        self.assertEqual(session.effects, [])
        self.assertEqual(session.files["docs/note.txt"], "old\n")

    def test_cancel_before_effect_is_durable_and_no_replay(self):
        session = SyntheticSession()
        self.assertEqual(call(session, cancelled=True)["status"], "CANCELLED")
        self.assertEqual(session.effects, [])
        again = fixture(step=2, tool_call_id="call-test-0002")
        self.assertEqual(call(session, again)["reason"], "DUPLICATE_IDEMPOTENCY")
        self.assertEqual(session.effects, [])

    def test_depth_guard_and_boolean_type_denied(self):
        for invalid_depth in (MAX_DEPTH + 1, True, -1, "1"):
            with self.subTest(depth=invalid_depth):
                session = SyntheticSession()
                p = fixture(depth=invalid_depth)
                self.assertEqual(call(session, p)["reason"], "DEPTH_LIMIT")
                self.assertFalse(session.effects)

    def test_suspicious_paths_are_refused(self):
        for path in ("../secret", "/etc/passwd", "docs/../outside",
                     "docs/%2e%2e/foo", "docs\\note.txt",
                     "docs/.hidden", "docs//note.txt", "docs/note.txt\x00"):
            with self.subTest(path=repr(path)):
                session = SyntheticSession()
                p = fixture(arguments={"path": path, "content": "new\n"})
                self.assertEqual(call(session, p)["reason"], "INVALID_PATH")
                self.assertFalse(session.effects)

    def test_unknown_tool_alias_and_nested_arguments_denied(self):
        for tool in ("sudo", "mock.read_file.fake", "Mock.write_file", None):
            with self.subTest(tool=tool):
                session = SyntheticSession()
                p = fixture(tool=tool)
                self.assertEqual(call(session, p)["reason"], "TOOL_NOT_ALLOWLISTED")
                self.assertFalse(session.effects)
        session = SyntheticSession()
        p = fixture(arguments={"path": "docs/note.txt", "content": "new\n",
                               "unknown": {"shell": True}})
        self.assertEqual(call(session, p)["reason"], "ARGUMENT_SCHEMA")
        self.assertFalse(session.effects)

    def test_json_malformed_duplicate_unknown_and_nonfinite(self):
        for raw, reason in (
            ("{bad", "MALFORMED_JSON"),
            ("", "MALFORMED_JSON"),
            ("[]", "INVALID_ENVELOPE"),
            ('{"x":1,"x":2}', "DUPLICATE_JSON_KEY"),
            ('{"x":NaN}', "INVALID_NUMBER"),
        ):
            with self.subTest(reason=reason):
                session = SyntheticSession()
                self.assertEqual(session.dispatch(raw)["reason"], reason)
                self.assertFalse(session.effects)

    def test_false_and_forged_responses_cannot_override_trusted_ledger(self):
        session = SyntheticSession()
        self.assertEqual(call(session, ack_lost=True)["status"], "UNKNOWN")
        for response in (
            {"schema_version": 1, "tool_call_id": "call-test-0001",
             "status": "ok", "output": "written"},
            {"schema_version": 1, "tool_call_id": "call-fake-0001",
             "status": "ok", "output": "written"},
        ):
            with self.assertRaisesRegex(ContractDenied,
                                        "RESPONSE_WITHOUT_TRUSTED_RECEIPT"):
                session.verify_response(json.dumps(response))
        self.assertEqual(len(session.effects), 1)
        self.assertEqual(session.ledger["call-test-0001"]["status"], "UNKNOWN")

    def test_valid_receipt_refuses_untrusted_mismatch_extra_and_oversize(self):
        session = SyntheticSession()
        self.assertEqual(call(session)["status"], "OK")
        base = {"schema_version": 1, "tool_call_id": "call-test-0001",
                "status": "ok", "output": "written"}
        for change, reason in (
            ({"output": "forged"}, "RESPONSE_MISMATCH"),
            ({"output": "X" * 129}, "OUTPUT_LIMIT"),
            ({"status": True}, "RESPONSE_TYPE"),
            ({"schema_version": 2}, "RESPONSE_SCHEMA"),
            ({"extra": "yes"}, "RESPONSE_SCHEMA"),
        ):
            with self.subTest(change=change):
                response = {**base, **change}
                with self.assertRaisesRegex(ContractDenied, reason):
                    session.verify_response(json.dumps(response))
        self.assertEqual(len(session.effects), 1)

    def test_new_valid_read_after_write_keeps_scope_and_call_count(self):
        session = SyntheticSession()
        self.assertEqual(call(session)["status"], "OK")
        second = fixture(tool="mock.read_file", step=2,
                         tool_call_id="call-test-0002",
                         idempotency_key="idem-test-0002")
        self.assertEqual(call(session, second)["status"], "OK")
        self.assertEqual(session.ledger["call-test-0002"]["output"], "new\n")
        self.assertEqual(len(session.effects), 1)

    def test_no_network_process_device_or_filesystem_commands(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network attempted")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("subprocess attempted")):
            report = run_negative_corpus()
            session = SyntheticSession()
            self.assertEqual(call(session)["status"], "OK")
        self.assertEqual(report["passed"], 18)
        self.assertEqual(len(session.effects), 1)


if __name__ == "__main__":
    unittest.main()
