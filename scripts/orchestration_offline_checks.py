"""Offline-only synthetic admission checks for Hermes #474 and #475.

This module does not spawn agents, authorize live calls, persist state, or
enforce operating-system rights. It is a deterministic contract fixture.
"""
from __future__ import annotations
import hashlib
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
READ_ONLY = frozenset({"source_read", "evidence_read"})


class Rejected(ValueError):
    pass


def check_plan(plan, grant, now, available_devices):
    """Validate a flat three-node synthetic DAG, not a live dispatcher."""
    required = {"revision", "approval_id", "nodes", "edges"}
    required_grant = {"revision", "approval_id", "scopes", "tools", "expires", "max_steps"}
    if type(plan) is not dict or set(plan) != required:
        raise Rejected("plan_schema")
    if type(grant) is not dict or set(grant) != required_grant:
        raise Rejected("grant_schema")
    if type(now) is not int or type(available_devices) is not frozenset:
        raise Rejected("input_schema")
    if type(plan["revision"]) is not str or not SHA.fullmatch(plan["revision"]):
        raise Rejected("revision_invalid")
    if plan["revision"] != grant["revision"] or plan["approval_id"] != grant["approval_id"]:
        raise Rejected("grant_mismatch")
    if type(grant["expires"]) is not int or grant["expires"] <= now:
        raise Rejected("grant_expired")
    if type(grant["max_steps"]) is not int or grant["max_steps"] < 1:
        raise Rejected("grant_budget_invalid")
    if any(type(grant[key]) is not list or not grant[key]
           or any(type(v) is not str or not v for v in grant[key])
           for key in ("scopes", "tools")):
        raise Rejected("grant_sets_invalid")
    if not set(grant["tools"]) <= READ_ONLY:
        raise Rejected("not_read_only")
    nodes = plan["nodes"]
    if type(nodes) is not list or not 1 <= len(nodes) <= 3:
        raise Rejected("child_limit")
    node_ids = set()
    total_child_steps = 0
    for node in nodes:
        if type(node) is not dict or set(node) != {
            "id", "device", "scopes", "tools", "expires", "max_steps"
        }:
            raise Rejected("node_schema")
        nid = node["id"]
        if type(nid) is not str or not IDENT.fullmatch(nid) or nid in node_ids:
            raise Rejected("node_id")
        node_ids.add(nid)
        if type(node["device"]) is not str or node["device"] not in available_devices:
            raise Rejected("device_unavailable")
        for field in ("scopes", "tools"):
            subset = node[field]
            if type(subset) is not list or not subset or any(type(v) is not str for v in subset):
                raise Rejected("node_set_invalid")
            if not set(subset) <= set(grant[field]):
                raise Rejected("scope_or_tool_escalation")
        if type(node["expires"]) is not int or not now < node["expires"] <= grant["expires"]:
            raise Rejected("node_expired")
        if type(node["max_steps"]) is not int or not 1 <= node["max_steps"] <= grant["max_steps"]:
            raise Rejected("node_budget")
        total_child_steps += node["max_steps"]
    if total_child_steps > grant["max_steps"]:
        raise Rejected("aggregate_budget_escalation")
    if type(plan["edges"]) is not list:
        raise Rejected("edge_schema")
    incoming = {node_id: set() for node_id in node_ids}
    edges = set()
    for edge in plan["edges"]:
        if type(edge) is not list or len(edge) != 2 or any(type(x) is not str for x in edge):
            raise Rejected("edge_schema")
        parent, child = edge
        if parent not in node_ids or child not in node_ids or parent == child:
            raise Rejected("edge_invalid")
        if (parent, child) in edges:
            raise Rejected("edge_duplicate")
        edges.add((parent, child))
        incoming[child].add(parent)
    order = []
    while incoming:
        ready = sorted(n for n, parents in incoming.items() if not parents)
        if not ready:
            raise Rejected("cycle")
        for n in ready:
            order.append(n)
            del incoming[n]
            for parents in incoming.values():
                parents.discard(n)
    return tuple(order)


def check_handoff(payload, receipt, *, node_id, revision, evidence_id, now, seen):
    """Check a caller-supplied trusted receipt. Does not authenticate its origin."""
    if type(payload) is not bytes or type(now) is not int or type(seen) is not set:
        raise Rejected("handoff_schema")
    if type(receipt) is not dict or set(receipt) != {
        "node_id", "revision", "evidence_id", "sha256", "expires", "accepted"
    }:
        raise Rejected("receipt_schema")
    if (type(evidence_id) is not str or not IDENT.fullmatch(evidence_id)
            or evidence_id in seen):
        raise Rejected("handoff_duplicate")
    if (receipt["node_id"] != node_id or receipt["revision"] != revision
            or receipt["evidence_id"] != evidence_id or receipt["accepted"] is not True):
        raise Rejected("handoff_unverified")
    if type(receipt["expires"]) is not int or now >= receipt["expires"]:
        raise Rejected("handoff_expired")
    if receipt["sha256"] != hashlib.sha256(payload).hexdigest():
        raise Rejected("handoff_digest")
    seen.add(evidence_id)
    return node_id


def eligible_after_verified_evidence(plan, verified_nodes):
    """Return synthetically eligible nodes using externally verified evidence.

    An upstream Kanban parent with state 'archived' is terminal for its DAG,
    but that alone is NOT an accepted proof of successful task completion.
    This helper does not authenticate receipts or dispatch work; its caller
    must validate the plan and each evidence record independently.
    """
    if (type(plan) is not dict or set(plan) !=
            {"revision", "approval_id", "nodes", "edges"}
            or type(verified_nodes) is not frozenset
            or any(type(n) is not str for n in verified_nodes)):
        raise Rejected("eligibility_schema")
    nodes = plan["nodes"]
    edges = plan["edges"]
    if type(nodes) is not list or type(edges) is not list:
        raise Rejected("eligibility_schema")
    ids = {node["id"] for node in nodes}
    if not verified_nodes <= ids:
        raise Rejected("unknown_evidence_node")
    dependencies = {node_id: set() for node_id in ids}
    for parent, child in edges:
        dependencies[child].add(parent)
    return tuple(sorted(node for node in ids - verified_nodes
                        if dependencies[node] <= verified_nodes))


def synthetic_one_shot_recovery_gate(state):
    """Return a *simulated* decision, never permission to call a model.

    Native Kanban may reclaim an expired run to the ready/review phase. A
    model-capable adapter must maintain a separate durable, atomic pre-call
    reservation and independently prove that NO prior inference was started.
    This function does not read provider receipts, grant approvals, or a DB.
    """
    if type(state) is not dict or set(state) != {
        "approval_verified", "attempt_count", "invocation_state", "lease_expired"
    }:
        raise Rejected("recovery_schema")
    if type(state["approval_verified"]) is not bool:
        raise Rejected("recovery_approval_type")
    if type(state["attempt_count"]) is not int or state["attempt_count"] < 0:
        raise Rejected("recovery_attempts")
    if type(state["lease_expired"]) is not bool:
        raise Rejected("recovery_lease_type")
    if type(state["invocation_state"]) is not str or state["invocation_state"] not in {
        "never", "reserved", "started", "uncertain", "finished"
    }:
        raise Rejected("recovery_invocation_state")
    if not state["approval_verified"]:
        return "DENY_NO_APPROVAL"
    if (state["attempt_count"] != 0
            or state["invocation_state"] != "never"
            or state["lease_expired"]):
        return "BLOCK_MANUAL_REVIEW"
    return "ELIGIBLE_FIRST_RESERVATION_ONLY"
