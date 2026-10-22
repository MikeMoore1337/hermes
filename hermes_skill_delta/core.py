"""H-28: semantic regression tests for a fictional read-only QA summary.

Only Python dictionaries are read. This module never imports or activates a
Hermes, Codex, model, CLI, runtime skill or real credential.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from .cases import CASES, TARGET
from .variants import SOURCE_SHA, VARIANTS

SCHEMA = "hermes-skill-delta-offline-v1"
MAX_DESCRIPTION_BYTES = 300
REQUIRED_PERMISSIONS = ["qa.read"]
REQUIRED_FIELDS = {
    "case_id", "version", "locale", "request", "target_sha",
    "receipts", "claims", "owner_approved", "expected",
}
STATUS_KEYS = {"ci", "merge", "deployment", "effects"}
RECEIPT_KIND = {
    "ci": ("github-actions", {"success", "failure"}),
    "merge": ("github", {"merged"}),
    "deploy": ("hermes-deployer", {"success"}),
}


class EvaluationError(ValueError):
    """Static sanitized reason code only."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False, ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvaluationError("INVALID_SERIALIZATION") from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_cases():
    cases = deepcopy(CASES)
    if len(cases) != 12 or len({c.get("case_id") for c in cases}) != 12:
        raise EvaluationError("INVALID_CORPUS")
    for c in cases:
        validate_case(c)
    return cases


def validate_case(c):
    if type(c) is not dict or set(c) != REQUIRED_FIELDS:
        raise EvaluationError("CASE_SCHEMA")
    if (type(c["case_id"]) is not str or
            not re.fullmatch(r"se-[0-9]{2}-[a-z0-9-]+", c["case_id"]) or
            type(c["version"]) is not int or c["version"] != 1 or
            c["locale"] not in ("en", "ru") or
            type(c["request"]) is not str or
            not 4 <= len(c["request"]) <= 160 or
            c["target_sha"] != TARGET or
            type(c["owner_approved"]) is not bool):
        raise EvaluationError("CASE_IDENTITY")
    if (type(c["receipts"]) is not dict or
            set(c["receipts"]) != set(RECEIPT_KIND) or
            type(c["claims"]) is not dict or
            set(c["claims"]) != set(RECEIPT_KIND) or
            any(type(v) is not bool for v in c["claims"].values())):
        raise EvaluationError("CASE_INPUT")
    for key, receipt in c["receipts"].items():
        if receipt is None:
            continue
        if (type(receipt) is not dict or
                set(receipt) != {"kind", "sha", "issuer", "result"} or
                type(receipt["kind"]) is not str or receipt["kind"] != key or
                type(receipt["sha"]) is not str or
                not re.fullmatch(r"[0-9a-f]{40}", receipt["sha"]) or
                type(receipt["issuer"]) is not str or
                len(receipt["issuer"]) > 64 or
                type(receipt["result"]) is not str or
                len(receipt["result"]) > 32):
            raise EvaluationError("CASE_RECEIPT")
    if (type(c["expected"]) is not dict or
            set(c["expected"]) != STATUS_KEYS or
            c["expected"]["ci"] not in ("UNKNOWN", "PASS", "FAIL") or
            c["expected"]["merge"] not in ("NOT_VERIFIED", "MERGED") or
            c["expected"]["deployment"] not in ("NOT_VERIFIED", "DEPLOYED") or
            c["expected"]["effects"] != []):
        raise EvaluationError("CASE_EXPECTED")
    if len(canonical(c)) > 2048:
        raise EvaluationError("CASE_OVERSIZED")


def load_variants():
    variants = deepcopy(VARIANTS)
    if set(variants) != {"baseline", "revised", "regressed"}:
        raise EvaluationError("INVALID_VARIANTS")
    for key, v in variants.items():
        if (type(v) is not dict or
                set(v) != {"version", "name", "description", "contract",
                           "source_sha", "source_license"} or
                type(v["version"]) is not int or
                v["version"] not in (1, 2, 3) or
                v["name"] != "qa-evidence-summary" or
                type(v["description"]) is not str or
                type(v["contract"]) is not dict or
                set(v["contract"]) != {"receipt_only", "exact_sha",
                                      "require_owner", "permissions", "effects",
                                      "dependencies"} or
                any(type(v["contract"][p]) is not bool
                    for p in ("receipt_only", "exact_sha", "require_owner")) or
                v["source_sha"] != SOURCE_SHA or
                v["source_license"] != "ORIGINAL_SYNTHETIC"):
            raise EvaluationError("VARIANT_SCHEMA")
        for p in ("permissions", "effects", "dependencies"):
            if type(v["contract"][p]) is not list or any(
                    type(x) is not str for x in v["contract"][p]):
                raise EvaluationError("VARIANT_SCHEMA")
    return variants


def contract_gate(v):
    """No candidate may expand original read-only privileges."""
    c = v["contract"]
    denied = []
    if c["permissions"] != REQUIRED_PERMISSIONS or c["effects"]:
        denied.append("PERMISSION_EXPANSION")
    if c["dependencies"]:
        denied.append("UNREVIEWED_DEPENDENCY")
    if len(v["description"].encode("utf-8")) > MAX_DESCRIPTION_BYTES:
        denied.append("DESCRIPTION_BUDGET")
    if not c["receipt_only"] or not c["require_owner"]:
        denied.append("TRUST_BOUNDARY_CHANGE")
    return sorted(set(denied))


def _recognized(key, receipt, target, *, exact_sha):
    if receipt is None:
        return False
    issuer, statuses = RECEIPT_KIND[key]
    return (receipt["kind"] == key and receipt["issuer"] == issuer and
            receipt["result"] in statuses and
            (not exact_sha or receipt["sha"] == target))


def simulate(case, variant):
    """Pure synthetic behavior; untrusted request prose is never parsed."""
    validate_case(case)
    c = variant["contract"]
    receipts = case["receipts"]
    claims = case["claims"]
    exact = c["exact_sha"]
    ci_valid = _recognized("ci", receipts["ci"], case["target_sha"],
                           exact_sha=exact)
    if ci_valid:
        ci = "PASS" if receipts["ci"]["result"] == "success" else "FAIL"
    elif not c["receipt_only"] and claims["ci"]:
        ci = "PASS"
    else:
        ci = "UNKNOWN"
    merge_valid = _recognized("merge", receipts["merge"], case["target_sha"],
                              exact_sha=exact)
    merged = ci == "PASS" and (merge_valid or (
        not c["receipt_only"] and claims["merge"]))
    deploy_valid = _recognized("deploy", receipts["deploy"], case["target_sha"],
                               exact_sha=exact)
    deployed = (merged and ci == "PASS" and
                (not c["require_owner"] or case["owner_approved"]) and
                (deploy_valid or (not c["receipt_only"] and claims["deploy"])))
    return {
        "ci": ci,
        "merge": "MERGED" if merged else "NOT_VERIFIED",
        "deployment": "DEPLOYED" if deployed else "NOT_VERIFIED",
        "effects": [],
    }


def assess(variant, cases):
    violations = contract_gate(variant)
    if violations:
        return {
            "verdict": "BLOCKED", "correct": None, "incorrect": None,
            "not_run": len(cases), "violations": violations, "failures": [],
            "description_bytes": len(variant["description"].encode("utf-8")),
            "variant_sha256": digest(variant),
        }
    failures = []
    for case in cases:
        observed = simulate(case, variant)
        if observed != case["expected"]:
            failures.append(case["case_id"])
    return {
        "verdict": "PASS" if not failures else "FAIL",
        "correct": len(cases) - len(failures), "incorrect": len(failures),
        "not_run": 0, "violations": [],
        "failures": failures,
        "description_bytes": len(variant["description"].encode("utf-8")),
        "variant_sha256": digest(variant),
    }


def compare(baseline, candidate, cases):
    """No model/human authority; a candidate is a review proposal only."""
    a = assess(baseline, cases)
    b = assess(candidate, cases)
    if a["verdict"] == "BLOCKED":
        raise EvaluationError("BASELINE_INVALID")
    if b["verdict"] == "BLOCKED":
        decision = "REGRESSED"
    elif b["correct"] > a["correct"] and not any(
            f in b["failures"] for f in set(c["case_id"] for c in cases)
            - set(a["failures"])):
        decision = "IMPROVED"
    elif b["correct"] == a["correct"] and b["failures"] == a["failures"]:
        decision = "NO_GAIN"
    else:
        decision = "REGRESSED"
    return {
        "status": decision, "baseline": a, "candidate": b,
        "delta_correct": (b["correct"] - a["correct"]
                          if b["correct"] is not None else None),
        "merge_permission": False, "auto_apply": False,
        "model_behavior": "NOT_MEASURED",
    }


def run(*, sha=None):
    if sha is not None and (
            type(sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", sha)):
        raise EvaluationError("INVALID_REPOSITORY_SHA")
    cases = load_cases()
    variants = load_variants()
    improvement = compare(variants["baseline"], variants["revised"], cases)
    regression = compare(variants["baseline"], variants["regressed"], cases)
    nogain = compare(variants["baseline"], variants["baseline"], cases)
    return {
        "schema": SCHEMA, "dataset_version": 1, "repository_sha": sha,
        "dataset_sha256": digest(cases), "source_sha": SOURCE_SHA,
        "source_is_synthetic": True,
        "mode": "offline_fixed_bilingual_semantic_events",
        "case_count": len(cases),
        "variant_results": {
            "baseline": assess(variants["baseline"], cases),
            "revised": assess(variants["revised"], cases),
            "regressed": assess(variants["regressed"], cases),
        },
        "comparisons": {
            "revised_vs_baseline": improvement,
            "regressed_vs_baseline": regression,
            "baseline_vs_baseline": nogain,
        },
        "human_review": "REQUIRED_BEFORE_ANY_REAL_CHANGE",
        "no_live_skill_changed": True,
        "model_calls": 0, "provider_cost": "UNKNOWN",
        "model_effectiveness": "NOT_MEASURED",
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha")
    parser.add_argument("--format", choices=("short", "json"), default="short")
    args = parser.parse_args()
    try:
        report = run(sha=args.sha)
    except EvaluationError:
        print("skill_delta: invalid_fixture_or_sha")
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    else:
        x = report["variant_results"]
        print("H-28 offline skill variants: " +
              ", ".join(f"{key}={x[key]['correct']}/{report['case_count']}"
                        if x[key]["correct"] is not None else f"{key}=BLOCKED"
                        for key in ("baseline", "revised", "regressed")))
        print("Decisions: " + ", ".join(
            f"{k}={v['status']}" for k,v in report["comparisons"].items()))
        print(f"Corpus SHA256: {report['dataset_sha256']}")
        print("Real LLM effectiveness NOT_MEASURED; source-only, zero model calls.")
    return 0 if (
        report["comparisons"]["revised_vs_baseline"]["status"] == "IMPROVED" and
        report["comparisons"]["regressed_vs_baseline"]["status"] == "REGRESSED" and
        report["comparisons"]["baseline_vs_baseline"]["status"] == "NO_GAIN" and
        report["variant_results"]["revised"]["correct"] == report["case_count"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
