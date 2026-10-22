"""Deterministic offline A/B/AB choice for Hermes #476, no model/tool executor.

Selection uses independently provided synthetic facts, mandatory constraints,
and proof IDs. No trust is granted to self-scores, votes, or approval claims.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from .cases import CASES, SHA

SCHEMA = "hermes-alternatives-eval-v1"
KEYS = ("A", "B", "AB")
REASONS = {
    "IMPROVEMENT_VERIFIED", "NO_PROVEN_GAIN", "UNSUPPORTED_CLAIMS",
    "REQUIREMENT_REGRESSION", "UNVERIFIED_EVIDENCE", "SCOPE_VIOLATION",
    "STEP_BUDGET", "BUDGET_EXHAUSTED", "JUDGE_UNTRUSTED",
}
MAX_CASE_BYTES = 8192

class EvalError(ValueError):
    """Static diagnostic, never echo source material."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvalError("SERIALIZATION_ERROR") from exc


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def validate(case):
    if type(case) is not dict or set(case) != {
        "case_id", "version", "category", "base_sha", "truth",
        "required", "allowed_scope", "budget", "judge", "note",
        "candidates", "expected",
    }:
        raise EvalError("INVALID_SCHEMA")
    if (type(case["case_id"]) is not str or
            not re.fullmatch(r"ar-[0-9]{2}-[a-z0-9-]+", case["case_id"]) or
            type(case["version"]) is not int or case["version"] != 1 or
            case["base_sha"] != SHA or type(case["category"]) is not str or
            type(case["note"]) is not str or type(case["truth"]) is not dict or
            not case["truth"] or len(case["truth"]) > 8 or
            any(type(k) is not str or not re.fullmatch(r"[a-z_]{2,40}", k) or
                type(v) is not int or not 1 <= v <= 8
                for k, v in case["truth"].items())):
        raise EvalError("INVALID_FACTS")
    if (type(case["required"]) is not list or not case["required"] or
            not set(case["required"]).issubset(case["truth"]) or
            len(set(case["required"])) != len(case["required"])):
        raise EvalError("INVALID_REQUIRED")
    if (type(case["allowed_scope"]) is not list or
            case["allowed_scope"] != ["review"] or
            type(case["budget"]) is not int or not 1 <= case["budget"] <= 3 or
            case["judge"] not in ("independent", "untrusted")):
        raise EvalError("INVALID_POLICY")
    if (type(case["expected"]) is not dict or set(case["expected"]) !=
            {"winner", "stop_reason"} or case["expected"]["winner"] not in KEYS or
            case["expected"]["stop_reason"] not in REASONS):
        raise EvalError("INVALID_EXPECTED")
    if type(case["candidates"]) is not dict or set(case["candidates"]) != set(KEYS):
        raise EvalError("INVALID_CANDIDATES")
    for candidate in case["candidates"].values():
        if type(candidate) is not dict or set(candidate) != {
            "claims", "proofs", "scope", "steps", "self_score", "claimed_approval"}:
            raise EvalError("INVALID_CANDIDATE")
        if (type(candidate["claims"]) is not list or
                type(candidate["proofs"]) is not list or
                type(candidate["scope"]) is not list or
                len(candidate["claims"]) != len(set(candidate["claims"])) or
                len(candidate["proofs"]) != len(set(candidate["proofs"])) or
                len(candidate["scope"]) != len(set(candidate["scope"])) or
                not all(type(x) is str and len(x) <= 64
                        for k in ("claims", "proofs", "scope")
                        for x in candidate[k]) or
                type(candidate["steps"]) is not int or
                not 1 <= candidate["steps"] <= 100 or
                type(candidate["self_score"]) is not int or
                not 0 <= candidate["self_score"] <= 100 or
                type(candidate["claimed_approval"]) is not bool):
            raise EvalError("INVALID_CANDIDATE")
    if len(canonical(case)) > MAX_CASE_BYTES:
        raise EvalError("CASE_OVERSIZED")
    return case


def load_cases():
    cases = deepcopy(CASES)
    if len(cases) != 12 or len({c.get("case_id") for c in cases}) != 12:
        raise EvalError("INVALID_DATASET")
    for c in cases:
        validate(c)
    return cases


def score(case, candidate):
    """Candidate-blind independent synthetic fact and proof verification."""
    facts = case["truth"]
    claims = set(candidate["claims"])
    proofs = set(candidate["proofs"])
    scope = set(candidate["scope"])
    denies = []
    if not scope.issubset(case["allowed_scope"]):
        denies.append("SCOPE_VIOLATION")
    if not set(case["required"]).issubset(claims):
        denies.append("REQUIREMENT_REGRESSION")
    if claims.difference(facts):
        denies.append("UNSUPPORTED_CLAIMS")
    if any(f"proof:{claim}" not in proofs for claim in claims):
        denies.append("UNVERIFIED_EVIDENCE")
    if candidate["steps"] > 4:
        denies.append("STEP_BUDGET")
    return {
        "eligible": not denies,
        "score": sum(facts[k] for k in claims if k in facts) if not denies else None,
        "reasons": sorted(set(denies)), "steps": candidate["steps"],
        "claims_verified": len(claims.intersection(facts)) if not denies else 0,
        "model": None, "actual_latency": "NOT_MEASURED",
    }


def choose(case, *, permutation=KEYS):
    """Preserve incumbent unless an eligible alternative has proven gain."""
    validate(case)
    if tuple(sorted(permutation)) != tuple(sorted(KEYS):
        raise EvalError("INVALID_PERMUTATION")
    incumbent = score(case, case["candidates"]["A"])
    if not incumbent["eligible"]:
        raise EvalError("INCUMBENT_INVALID")
    if case["judge"] != "independent" or case["budget"] < len(KEYS):
        reason = ("JUDGE_UNTRUSTED" if case["judge"] != "independent"
                  else "BUDGET_EXHAUSTED")
        not_run = {"eligible": None, "score": None, "reasons": ["NOT_RUN"],
                   "steps": None, "claims_verified": None, "model": None,
                   "actual_latency": "NOT_MEASURED"}
        return {"winner": "A", "stop_reason": reason,
                "evaluations": {k: incumbent if k == "A" else dict(not_run)
                                for k in KEYS},
                "evaluated": 1, "iteration_count": 0, "model_calls": 0}
    evaluations = {k: score(case, case["candidates"][k]) for k in permutation}
    a = evaluations["A"]
    winners = [k for k in KEYS if evaluations[k]["eligible"]
               and evaluations[k]["score"] > a["score"]]
    if winners:
        winner = min(winners, key=lambda k: (
            -evaluations[k]["score"], evaluations[k]["steps"], KEYS.index(k)))
        reason = "IMPROVEMENT_VERIFIED"
    else:
        winner = "A"
        for reason in ("SCOPE_VIOLATION", "REQUIREMENT_REGRESSION",
                       "UNVERIFIED_EVIDENCE", "UNSUPPORTED_CLAIMS", "STEP_BUDGET"):
            if any(reason in evaluations[k]["reasons"] for k in ("B", "AB")):
                break
        else:
            reason = "NO_PROVEN_GAIN"
    return {"winner": winner, "stop_reason": reason, "evaluations": evaluations,
            "evaluated": 3, "iteration_count": 1, "model_calls": 0}


def run_case(case):
    result = choose(case)
    expected = case["expected"]
    base = result["evaluations"]["A"]["score"]
    chosen = result["evaluations"][result["winner"]]["score"]
    return {
        "case_id": case["case_id"], "category": case["category"],
        "fixture_sha256": sha256(case),
        "incumbent_score": base, "winner_score": chosen,
        "verified_delta": chosen - base,
        "winner": result["winner"], "stop_reason": result["stop_reason"],
        "oracle": ("PASS" if result["winner"] == expected["winner"]
                   and result["stop_reason"] == expected["stop_reason"] else "FAIL"),
        "evaluations": result["evaluations"],
        "iteration_count": result["iteration_count"],
        "review_budget_used": result["evaluated"], "model_calls": 0,
        "runtime_latency": "NOT_MEASURED", "provider_cost": "UNKNOWN",
        "approval_for_merge_or_deploy": False,
    }


def run(*, sha=None):
    if sha is not None and (type(sha) is not str or
                            not re.fullmatch(r"[0-9a-f]{40}", sha)):
        raise EvalError("INVALID_REPOSITORY_SHA")
    cases = load_cases()
    rows = [run_case(c) for c in cases]
    return {
        "schema": SCHEMA, "repository_sha": sha,
        "dataset_sha256": sha256(cases), "dataset_version": 1,
        "mode": "offline_fixed_candidates", "case_count": len(rows),
        "passed": sum(x["oracle"] == "PASS" for x in rows),
        "chosen_incumbent": sum(x["winner"] == "A" for x in rows),
        "chosen_revision": sum(x["winner"] == "B" for x in rows),
        "chosen_synthesis": sum(x["winner"] == "AB" for x in rows),
        "actual_model_quality": "NOT_MEASURED", "model_calls": 0,
        "actual_latency": "NOT_MEASURED", "provider_cost": "UNKNOWN",
        "cases": rows,
    }


def main():
    import argparse
    p = argparse.ArgumentParser(prog="python -m hermes_decision_eval.core")
    p.add_argument("--sha")
    p.add_argument("--format", choices=("short", "json"), default="short")
    args = p.parse_args()
    try:
        r = run(sha=args.sha)
    except EvalError:
        print("alternatives_eval: invalid-fixture-or-sha")
        return 2
    if args.format == "json":
        print(json.dumps(r, sort_keys=True, ensure_ascii=True))
    else:
        print(f"H-476 fixed A/B/AB: {r['passed']}/{r['case_count']} PASS")
        print(f"Choices: A={r['chosen_incumbent']}, B={r['chosen_revision']}, AB={r['chosen_synthesis']}")
        print(f"Dataset SHA256: {r['dataset_sha256']}")
        print("Runtime model quality, latency, provider cost: NOT_MEASURED / UNKNOWN")
    return 0 if r["passed"] == r["case_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
