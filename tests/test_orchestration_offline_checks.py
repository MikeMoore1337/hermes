"""Synthetic offline checks for Hermes delegation and Kanban DAG (#474/#475)."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import unittest

from scripts.orchestration_offline_checks import (
    Rejected, check_handoff, check_plan, eligible_after_verified_evidence,
    synthetic_one_shot_recovery_gate,
)

REV = "a" * 40
GRANT = {
    "revision": REV, "approval_id": "synthetic-review",
    "scopes": ["source/hermes"], "tools": ["source_read", "evidence_read"],
    "expires": 2000, "max_steps": 8,
}
NODES = [
    {"id": "signal", "device": "sandbox-a", "scopes": ["source/hermes"],
     "tools": ["source_read"], "expires": 1700, "max_steps": 4},
    {"id": "safety", "device": "sandbox-b", "scopes": ["source/hermes"],
     "tools": ["source_read"], "expires": 1700, "max_steps": 4},
    {"id": "review", "device": "sandbox-a", "scopes": ["source/hermes"],
     "tools": ["evidence_read"], "expires": 1900, "max_steps": 5},
]
PLAN = {
    "revision": REV, "approval_id": "synthetic-review", "nodes": NODES,
    "edges": [["signal", "review"], ["safety", "review"]],
}
DEVICES = frozenset({"sandbox-a", "sandbox-b"})


class ContractTests(unittest.TestCase):
    def plan(self):
        return copy.deepcopy(PLAN)

    def rejects(self, change, reason, *, grant=None, devices=DEVICES, now=1000):
        plan = self.plan()
        change(plan)
        with self.assertRaisesRegex(Rejected, "^" + reason + "$"):
            check_plan(plan, GRANT if grant is None else grant, now, devices)


    def test_one_shot_first_reservation_only(self):
        state = {"approval_verified": True, "attempt_count": 0,
                 "invocation_state": "never", "lease_expired": False}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "ELIGIBLE_FIRST_RESERVATION_ONLY")

    def test_recovery_missing_approval_denied(self):
        state = {"approval_verified": False, "attempt_count": 0,
                 "invocation_state": "never", "lease_expired": False}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "DENY_NO_APPROVAL")

    def test_expired_claim_never_implies_safe_retry(self):
        state = {"approval_verified": True, "attempt_count": 0,
                 "invocation_state": "never", "lease_expired": True}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_reserved_not_retryable(self):
        state = {"approval_verified": True, "attempt_count": 0,
                 "invocation_state": "reserved", "lease_expired": False}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_started_not_retryable(self):
        state = {"approval_verified": True, "attempt_count": 1,
                 "invocation_state": "started", "lease_expired": True}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_uncertain_not_retryable(self):
        state = {"approval_verified": True, "attempt_count": 1,
                 "invocation_state": "uncertain", "lease_expired": True}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_finished_not_retryable(self):
        state = {"approval_verified": True, "attempt_count": 1,
                 "invocation_state": "finished", "lease_expired": True}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_any_prior_attempt_blocks_even_if_state_claims_never(self):
        state = {"approval_verified": True, "attempt_count": 1,
                 "invocation_state": "never", "lease_expired": False}
        self.assertEqual(synthetic_one_shot_recovery_gate(state),
                         "BLOCK_MANUAL_REVIEW")

    def test_invalid_bool_attempts_rejected(self):
        state = {"approval_verified": True, "attempt_count": True,
                 "invocation_state": "never", "lease_expired": False}
        with self.assertRaisesRegex(Rejected, "^recovery_attempts$"):
            synthetic_one_shot_recovery_gate(state)

    def test_unknown_invocation_state_rejected(self):
        state = {"approval_verified": True, "attempt_count": 0,
                 "invocation_state": "automatically_retry", "lease_expired": False}
        with self.assertRaisesRegex(Rejected, "^recovery_invocation_state$"):
            synthetic_one_shot_recovery_gate(state)

    def test_untrusted_extra_recovery_field_rejected(self):
        state = {"approval_verified": True, "attempt_count": 0,
                 "invocation_state": "never", "lease_expired": False,
                 "override_force_retry": True}
        with self.assertRaisesRegex(Rejected, "^recovery_schema$"):
            synthetic_one_shot_recovery_gate(state)

    def test_proper_order(self):
        self.assertEqual(check_plan(self.plan(), GRANT, 1000, DEVICES),
                         ("safety", "signal", "review"))

    def test_two_synthetic_readers_feed_evidence_review(self):
        # These are ordinary deterministic Python functions, NOT LLM subagents.
        plan = self.plan()
        order = check_plan(plan, GRANT, 1000, DEVICES)
        self.assertEqual(order[-1], "review")
        def read_only_job(node):
            return node, (node + ":public-synthetic").encode()
        with ThreadPoolExecutor(max_workers=2) as pool:
            worker_outputs = list(pool.map(read_only_job, ("signal", "safety")))
        receipts = []
        seen = set()
        for node_id, payload in worker_outputs:
            evidence_id = "proof-" + node_id
            receipt = {
                "node_id": node_id, "revision": REV, "evidence_id": evidence_id,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "expires": 1500, "accepted": True,
            }
            receipts.append(check_handoff(payload, receipt, node_id=node_id,
                                          revision=REV, evidence_id=evidence_id,
                                          now=1000, seen=seen))
        self.assertEqual(set(receipts), {"signal", "safety"})
        self.assertEqual(len(seen), 2)
        self.assertNotIn("review", receipts)  # QA input ready; QA not executed

    def test_evidence_gate_blocks_archived_parent(self):
        # Native Kanban marks an archived parent terminal; acceptance must
        # still require that parent's independent evidence before QA is eligible.
        plan = self.plan()
        self.assertEqual(eligible_after_verified_evidence(plan, frozenset()),
                         ("safety", "signal"))
        self.assertEqual(eligible_after_verified_evidence(plan, frozenset({"safety"})),
                         ("signal",))
        self.assertEqual(eligible_after_verified_evidence(
            plan, frozenset({"safety", "signal"})), ("review",))

    def test_evidence_gate_rejects_unknown_task(self):
        with self.assertRaisesRegex(Rejected, "unknown_evidence_node"):
            eligible_after_verified_evidence(self.plan(), frozenset({"unknown"}))

    def test_evidence_gate_requires_verified_set_type(self):
        with self.assertRaisesRegex(Rejected, "eligibility_schema"):
            eligible_after_verified_evidence(self.plan(), {"signal"})

    def test_cycle(self):
        self.rejects(lambda p: p["edges"].append(["review", "signal"]), "cycle")

    def test_self_edge(self):
        self.rejects(lambda p: p["edges"].append(["signal", "signal"]), "edge_invalid")

    def test_unknown_parent(self):
        self.rejects(lambda p: p["edges"].append(["missing", "review"]), "edge_invalid")

    def test_duplicate_edge(self):
        self.rejects(lambda p: p["edges"].append(["signal", "review"]), "edge_duplicate")

    def test_boolean_parent(self):
        self.rejects(lambda p: p["edges"].append([True, "review"]), "edge_schema")

    def test_bad_grant(self):
        self.rejects(lambda p: p.update(approval_id="other"), "grant_mismatch")

    def test_old_grant(self):
        self.rejects(lambda p: None, "grant_expired", now=2000)

    def test_sha_mismatch(self):
        self.rejects(lambda p: p.update(revision="b" * 40), "grant_mismatch")

    def test_extra_scope(self):
        self.rejects(lambda p: p["nodes"][0].update(scopes=["other/source"]),
                     "scope_or_tool_escalation")

    def test_extra_tool(self):
        self.rejects(lambda p: p["nodes"][0].update(tools=["write_source"]),
                     "scope_or_tool_escalation")

    def test_non_read_only_grant(self):
        grant = dict(GRANT, tools=["source_read", "write_source"])
        self.rejects(lambda p: None, "not_read_only", grant=grant)

    def test_unreachable(self):
        self.rejects(lambda p: p["nodes"][0].update(device="unknown"),
                     "device_unavailable")

    def test_expired_node(self):
        self.rejects(lambda p: p["nodes"][0].update(expires=1000), "node_expired")

    def test_node_exceeds_grant_expiration(self):
        self.rejects(lambda p: p["nodes"][0].update(expires=2300), "node_expired")

    def test_budget(self):
        self.rejects(lambda p: p["nodes"][0].update(max_steps=99), "node_budget")

    def test_boolean_budget(self):
        self.rejects(lambda p: p["nodes"][0].update(max_steps=True), "node_budget")

    def test_more_than_three(self):
        self.rejects(lambda p: p["nodes"].append(dict(NODES[0], id="extra")), "child_limit")

    def test_duplicate_id(self):
        self.rejects(lambda p: p["nodes"][1].update(id="signal"), "node_id")

    def test_undefined_node_field(self):
        self.rejects(lambda p: p["nodes"][0].update(extra="unexpected"), "node_schema")

    def test_duplicate_replay(self):
        seen = set()
        receipt = self.receipt()
        check_handoff(b"proof", receipt, node_id="signal", revision=REV,
                      evidence_id="proof1", now=1000, seen=seen)
        with self.assertRaisesRegex(Rejected, "handoff_duplicate"):
            check_handoff(b"proof", receipt, node_id="signal", revision=REV,
                          evidence_id="proof1", now=1000, seen=seen)

    @staticmethod
    def receipt():
        return {"node_id": "signal", "revision": REV, "evidence_id": "proof1",
                "sha256": hashlib.sha256(b"proof").hexdigest(),
                "expires": 1500, "accepted": True}

    def test_bad_digest(self):
        with self.assertRaisesRegex(Rejected, "handoff_digest"):
            check_handoff(b"other", self.receipt(), node_id="signal", revision=REV,
                          evidence_id="proof1", now=1000, seen=set())

    def test_unauthorized_receipt(self):
        receipt = self.receipt()
        receipt["accepted"] = False
        with self.assertRaisesRegex(Rejected, "handoff_unverified"):
            check_handoff(b"proof", receipt, node_id="signal", revision=REV,
                          evidence_id="proof1", now=1000, seen=set())

    def test_stale_receipt(self):
        with self.assertRaisesRegex(Rejected, "handoff_expired"):
            check_handoff(b"proof", self.receipt(), node_id="signal", revision=REV,
                          evidence_id="proof1", now=1500, seen=set())

    def test_wrong_sender(self):
        receipt = self.receipt()
        receipt["node_id"] = "unknown"
        with self.assertRaisesRegex(Rejected, "handoff_unverified"):
            check_handoff(b"proof", receipt, node_id="signal", revision=REV,
                          evidence_id="proof1", now=1000, seen=set())

    def test_incomplete_receipt(self):
        receipt = self.receipt()
        receipt.pop("sha256")
        with self.assertRaisesRegex(Rejected, "receipt_schema"):
            check_handoff(b"proof", receipt, node_id="signal", revision=REV,
                          evidence_id="proof1", now=1000, seen=set())


if __name__ == "__main__":
    unittest.main()
