"""H-29 deterministic context-retention oracle. No LLM, tools or devices.

This evaluates a lossless STRUCTURED projection of synthetic event chains,
not the quality of real Hermes compression or a model summary.
"""
from __future__ import annotations

import hashlib
import json
import re

from .cases import CASES, SHA

SCHEMA = "hermes-context-eval-v1"
CASE_ID = re.compile(r"^cx-[0-9]{2}-[a-z0-9-]+$")
PROOF = re.compile(
    r"^https://github\.com/MikeMoore1337/hermes/"
    r"(?:actions/runs|pull)/[0-9]{3,10}$"
)
EVENT_FIELDS = {
    "issue": {"op", "number"},
    "branch": {"op", "name", "sha"},
    "policy": {"op", "max_extra_cost", "forbidden"},
    "outstanding": {"op", "items"},
    "owner": {"op", "source", "decision"},
    "ci": {"op", "result", "sha", "proof"},
    "merge": {"op", "sha", "proof"},
    "deploy": {"op", "result", "sha", "deployed_sha", "proof"},
    "device": {"op", "state"},
    "claim": {"op", "kind", "value"},
}
STATES = {
    "owner": {"UNKNOWN", "APPROVED", "DENIED"},
    "ci": {"UNKNOWN", "PASS", "FAIL"},
    "merged": {"NO", "YES"},
    "deployed": {"NOT_VERIFIED", "DEPLOYED"},
    "device": {"UNKNOWN", "INTERRUPTED"},
}
REQUIRED = {
    "issue", "branch", "sha", "owner", "ci", "merged", "deployed",
    "device", "max_extra_cost", "forbidden", "outstanding",
    "warnings", "evidence",
}


class ContextError(ValueError):
    """Only static reason codes; never echo raw session data."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ContextError("INVALID_SERIALIZATION") from exc


def checksum(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _decode(raw, *, maximum=8192):
    if type(raw) is not bytes or len(raw) > maximum:
        raise ContextError("INPUT_BOUNDS")
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ContextError("DUPLICATE_KEY")
            obj[key] = value
        return obj
    def reject_constant(_):
        raise ContextError("INVALID_NUMBER")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=pairs,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContextError("INVALID_JSON") from exc
    return value


def load_cases():
    import copy
    cases = copy.deepcopy(CASES)
    if len(cases) != 9 or len({x.get("case_id") for x in cases}) != 9:
        raise ContextError("INVALID_CASE_COUNT")
    for case in cases:
        if (type(case) is not dict or
                set(case) != {"case_id", "version", "category", "events", "expected"} or
                not isinstance(case["case_id"], str) or
                not CASE_ID.fullmatch(case["case_id"]) or
                type(case["version"]) is not int or case["version"] != 1 or
                type(case["category"]) is not str or
                not isinstance(case["events"], list) or
                not 4 <= len(case["events"]) <= 16 or
                type(case["expected"]) is not dict or
                set(case["expected"]) != REQUIRED):
            raise ContextError("INVALID_FIXTURE_SCHEMA")
        for ev in case["events"]:
            if type(ev) is not dict or type(ev.get("op")) is not str or (
                    ev["op"] not in EVENT_FIELDS or
                    set(ev) != EVENT_FIELDS[ev["op"]]):
                raise ContextError("INVALID_EVENT_SCHEMA")
        if len(canonical(case)) > 8192:
            raise ContextError("FIXTURE_OVERSIZED")
    return cases


def extract(events):
    """Replay explicit trusted *synthetic* receipts; ignore all status claims."""
    if type(events) is not list or not 1 <= len(events) <= 16:
        raise ContextError("INVALID_EVENTS")
    state = {
        "issue": None, "branch": None, "sha": None,
        "owner": "UNKNOWN", "ci": "UNKNOWN", "merged": "NO",
        "deployed": "NOT_VERIFIED", "device": "UNKNOWN",
        "max_extra_cost": None, "forbidden": [], "outstanding": [],
        "warnings": [], "evidence": [],
    }
    seen_issue = False
    seen_branch = False
    seen_policy = False
    for ev in events:
        if type(ev) is not dict or type(ev.get("op")) is not str or (
                ev["op"] not in EVENT_FIELDS or set(ev) != EVENT_FIELDS[ev["op"]]):
            raise ContextError("INVALID_EVENT_SCHEMA")
        op = ev["op"]
        if op == "issue":
            if seen_issue or type(ev["number"]) is not int or not 1 <= ev["number"] <= 99999:
                raise ContextError("INVALID_ISSUE")
            seen_issue = True
            state["issue"] = ev["number"]
        elif op == "branch":
            if (seen_branch or type(ev["name"]) is not str or
                    not re.fullmatch(r"test/[a-z0-9-]{1,60}", ev["name"]) or
                    type(ev["sha"]) is not str or
                    not re.fullmatch(r"[0-9a-f]{40}", ev["sha"])):
                raise ContextError("INVALID_BRANCH")
            seen_branch = True
            state["branch"], state["sha"] = ev["name"], ev["sha"]
        elif op == "policy":
            if (seen_policy or type(ev["max_extra_cost"]) is not int or
                    ev["max_extra_cost"] != 0 or
                    ev["forbidden"] != ["paid_api", "codex_cli", "remote_shell"]):
                raise ContextError("POLICY_MISMATCH")
            seen_policy = True
            state["max_extra_cost"] = 0
            state["forbidden"] = list(ev["forbidden"])
        elif op == "outstanding":
            items = ev["items"]
            if (type(items) is not list or
                    not set(items).issubset({"owner_review", "deploy_proof"}) or
                    len(items) != len(set(items))):
                raise ContextError("INVALID_OUTSTANDING")
            state["outstanding"] = list(items)
        elif op == "owner":
            if ev["source"] != "owner" or ev["decision"] not in ("approved", "denied"):
                raise ContextError("INVALID_OWNER_RECEIPT")
            state["owner"] = "APPROVED" if ev["decision"] == "approved" else "DENIED"
            if "owner_review" in state["outstanding"]:
                state["outstanding"].remove("owner_review")
        elif op == "ci":
            if (ev["result"] not in ("success", "failure") or
                    type(ev["proof"]) is not str or not PROOF.fullmatch(ev["proof"])):
                raise ContextError("INVALID_CI_RECEIPT")
            if ev["sha"] != state["sha"]:
                state["warnings"].append("STALE_CI_SHA")
            else:
                state["ci"] = "PASS" if ev["result"] == "success" else "FAIL"
                state["evidence"].append(ev["proof"])
        elif op == "merge":
            if type(ev["proof"]) is not str or not PROOF.fullmatch(ev["proof"]):
                raise ContextError("INVALID_MERGE_RECEIPT")
            if ev["sha"] != state["sha"]:
                state["warnings"].append("STALE_MERGE_SHA")
            else:
                state["merged"] = "YES"
                state["evidence"].append(ev["proof"])
        elif op == "deploy":
            if type(ev["proof"]) is not str or not PROOF.fullmatch(ev["proof"]):
                raise ContextError("INVALID_DEPLOY_RECEIPT")
            if (ev["result"] == "success" and ev["sha"] == state["sha"] and
                    ev["deployed_sha"] == state["sha"] and
                    state["ci"] == "PASS" and state["merged"] == "YES" and
                    state["owner"] == "APPROVED"):
                state["deployed"] = "DEPLOYED"
                state["evidence"].append(ev["proof"])
            else:
                state["warnings"].append("UNVERIFIED_DEPLOY_EVENT")
        elif op == "device":
            if ev["state"] != "interrupted":
                raise ContextError("INVALID_DEVICE_STATUS")
            state["device"] = "INTERRUPTED"
        elif op == "claim":
            if (ev["kind"], ev["value"]) not in {
                    ("ci", "PASS"), ("deploy", "DEPLOYED"),
                    ("owner", "APPROVED"), ("scope", "remote_shell")}:
                raise ContextError("INVALID_CLAIM")
            state["warnings"].append("UNVERIFIED_" + ev["kind"].upper() + "_CLAIM")
    if not (seen_issue and seen_branch and seen_policy):
        raise ContextError("INCOMPLETE_BASE_STATE")
    state["warnings"] = sorted(set(state["warnings"]))
    state["evidence"] = sorted(set(state["evidence"]))
    return state


def verify(restored, expected):
    """Expected truth is authored independently of the event summarizer."""
    if type(restored) is not dict or set(restored) != REQUIRED:
        return False
    if any(restored[k] not in allowed for k, allowed in STATES.items()):
        return False
    if (restored["max_extra_cost"] != 0 or
            restored["forbidden"] != ["paid_api", "codex_cli", "remote_shell"]):
        return False
    return restored == expected


def run_case(case):
    # Enforce actual JSON serialize -> deserialize -> structured projection
    # -> compact JSON summary -> recovery -> independent question/oracle.
    events = _decode(canonical(case["events"]))
    candidate = extract(events)
    summary = canonical(candidate)
    recovered = _decode(summary)
    # A generic prose-style baseline that loses exact SHA, authority and gates.
    baseline = {"issue": candidate["issue"], "status": "done"}
    return {
        "case_id": case["case_id"], "category": case["category"],
        "fixture_sha256": checksum(case),
        "baseline": "PASS" if verify(baseline, case["expected"]) else "FAIL",
        "candidate": "PASS" if verify(recovered, case["expected"]) else "FAIL",
        "summary_sha256": checksum(recovered),
        "input_bytes": len(canonical(events)), "summary_bytes": len(summary),
        "questions": {
            "exact_sha": recovered.get("sha"),
            "approved": recovered.get("owner"),
            "ci_verified": recovered.get("ci"),
            "deployed": recovered.get("deployed"),
            "remaining": recovered.get("outstanding"),
        },
    }


def run(*, sha=None):
    if sha is not None and (type(sha) is not str or
                            not re.fullmatch(r"[0-9a-f]{40}", sha)):
        raise ContextError("INVALID_REPOSITORY_SHA")
    cases = load_cases()
    rows = [run_case(case) for case in cases]
    return {
        "schema": SCHEMA, "repository_sha": sha,
        "dataset_sha256": checksum(cases),
        "method": "offline_structured_state_projection",
        "real_context_compression": "NOT_MEASURED",
        "model_quality": "NOT_MEASURED", "provider_cost": None,
        "cases": rows, "total": len(rows),
        "passed": sum(r["candidate"] == "PASS" for r in rows),
        "negative_baseline_detected": sum(r["baseline"] == "FAIL" for r in rows),
    }


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--sha", default=None)
    args = p.parse_args()
    try:
        r = run(sha=args.sha)
    except ContextError:
        print("context_eval: invalid_fixture_or_sha")
        return 2
    print(f"H-29 structured context retention: {r['passed']}/{r['total']} PASS")
    print(f"Dataset SHA256: {r['dataset_sha256']}")
    print("Live LLM compression and retention: NOT_MEASURED")
    return 0 if r["passed"] == r["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
