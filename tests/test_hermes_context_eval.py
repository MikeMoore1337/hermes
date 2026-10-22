"""Independent negative oracles for H-29 contextual fact preservation."""
from __future__ import annotations

from copy import deepcopy
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_context_eval import core
from hermes_context_eval.cases import CASES, SHA, STALE_SHA, URL_CI


class ContextRetentionTests(unittest.TestCase):
    def setUp(self):
        self.cases = {c["case_id"]: deepcopy(c) for c in core.load_cases()}

    def test_nine_independent_pinned_cases_and_negative_baselines(self):
        report = core.run(sha="c" * 40)
        self.assertEqual((report["total"], report["passed"],
                          report["negative_baseline_detected"]), (9, 9, 9))
        self.assertEqual(len({r["fixture_sha256"] for r in report["cases"]}), 9)
        self.assertEqual(report["real_context_compression"], "NOT_MEASURED")
        self.assertEqual(report["model_quality"], "NOT_MEASURED")
        self.assertIsNone(report["provider_cost"])
        self.assertEqual({r["candidate"] for r in report["cases"]}, {"PASS"})

    def test_no_unproved_deploy_or_owner_approval(self):
        for ident in ("cx-01-pending-release", "cx-02-owner-revoked",
                      "cx-03-failed-ci", "cx-08-fake-deploy"):
            with self.subTest(ident=ident):
                case = self.cases[ident]
                state = core.extract(case["events"])
                self.assertEqual(state["deployed"], "NOT_VERIFIED")
                self.assertTrue(core.verify(state, case["expected"]))
        self.assertEqual(core.extract(self.cases["cx-02-owner-revoked"]["events"])["owner"],
                         "DENIED")

    def test_claimed_deployment_does_not_become_evidence(self):
        case = self.cases["cx-08-fake-deploy"]
        state = core.extract(case["events"])
        self.assertEqual(state["warnings"], ["UNVERIFIED_DEPLOY_CLAIM"])
        self.assertNotIn("https://github.com/MikeMoore1337/hermes/actions/runs/8803",
                         state["evidence"])
        self.assertNotEqual(state["deployed"], "DEPLOYED")

    def test_positive_deploy_requires_all_proofs_and_exact_sha(self):
        case = self.cases["cx-09-valid-deployment"]
        state = core.extract(case["events"])
        self.assertEqual(state["deployed"], "DEPLOYED")
        self.assertTrue(core.verify(state, case["expected"]))
        for change in (
            {"deployed_sha": STALE_SHA},
            {"sha": STALE_SHA},
            {"result": "failure"},
        ):
            with self.subTest(change=change):
                mutated = deepcopy(case["events"])
                mutated[-2].update(change)
                actual = core.extract(mutated)
                self.assertEqual(actual["deployed"], "NOT_VERIFIED")
                self.assertIn("UNVERIFIED_DEPLOY_EVENT", actual["warnings"])
                self.assertFalse(core.verify(actual, case["expected"]))

    def test_stale_ci_receipt_cannot_set_pass(self):
        state = core.extract(self.cases["cx-06-stale-ci-sha"]["events"])
        self.assertEqual(state["ci"], "UNKNOWN")
        self.assertEqual(state["warnings"], ["STALE_CI_SHA"])
        self.assertEqual(state["evidence"], [])

    def test_conflicting_denied_approval_is_never_overridden_by_claim(self):
        state = core.extract(self.cases["cx-07-contradictory-owner"]["events"])
        self.assertEqual(state["owner"], "DENIED")
        self.assertEqual(state["warnings"], ["UNVERIFIED_OWNER_CLAIM"])
        self.assertTrue(core.verify(state, self.cases["cx-07-contradictory-owner"]["expected"]))

    def test_device_interruption_is_not_completion(self):
        state = core.extract(self.cases["cx-04-device-interrupted"]["events"])
        self.assertEqual(state["device"], "INTERRUPTED")
        self.assertEqual(state["ci"], "UNKNOWN")
        self.assertEqual(state["deployed"], "NOT_VERIFIED")

    def test_mutation_drops_must_fail_independent_oracle(self):
        case = self.cases["cx-01-pending-release"]
        original = core.extract(case["events"])
        self.assertTrue(core.verify(original, case["expected"]))
        for key, forged in (
            ("sha", "f" * 40),
            ("ci", "UNKNOWN"),
            ("deployed", "DEPLOYED"),
            ("owner", "DENIED"),
            ("forbidden", []),
            ("outstanding", []),
            ("evidence", []),
            ("branch", "test/other"),
        ):
            with self.subTest(key=key):
                bad = deepcopy(original)
                bad[key] = forged
                self.assertFalse(core.verify(bad, case["expected"]))

    def test_truncated_and_invalid_serialized_state_denied(self):
        for payload in (
            b"", b"{not-json", b"{\"x\":1,\"x\":2}",
            b"{\"x\":NaN}", b"[]" * 5000,
        ):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(core.ContextError):
                    core._decode(payload)

    def test_event_schema_scope_and_missing_baseline_denied(self):
        good = deepcopy(self.cases["cx-05-policy-budget"]["events"])
        for ev in (
            {"op": "claim", "kind": "scope", "value": "private_vault"},
            {"op": "ci", "result": "success", "sha": SHA},
            {"op": "remote_exec", "cmd": "rm"},
        ):
            with self.subTest(ev=ev):
                with self.assertRaises(core.ContextError):
                    core.extract(good + [ev])
        with self.assertRaises(core.ContextError):
            core.extract(good[1:])
        wrong = deepcopy(good)
        wrong[2]["max_extra_cost"] = 2
        with self.assertRaises(core.ContextError):
            core.extract(wrong)

    def test_missing_or_unsupported_receipts_refuse_success(self):
        case = self.cases["cx-09-valid-deployment"]
        events = deepcopy(case["events"])
        events.remove(next(x for x in events if x["op"] == "merge"))
        output = core.extract(events)
        self.assertEqual(output["merged"], "NO")
        self.assertEqual(output["deployed"], "NOT_VERIFIED")
        self.assertFalse(core.verify(output, case["expected"]))

    def test_fixture_hash_is_sensitive_to_any_change(self):
        case = deepcopy(self.cases["cx-01-pending-release"])
        original = core.checksum(case)
        case["expected"]["deployed"] = "DEPLOYED"
        self.assertNotEqual(core.checksum(case), original)
        self.assertNotEqual(core.checksum(core.load_cases()), original)

    def test_invalid_repo_sha_is_refused(self):
        with self.assertRaises(core.ContextError):
            core.run(sha="not-a-sha")

    def test_no_network_subprocess_or_real_device(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("process")):
            report = core.run()
        self.assertEqual(report["passed"], 9)


if __name__ == "__main__":
    unittest.main()
