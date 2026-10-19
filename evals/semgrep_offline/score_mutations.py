"""Score actual Semgrep JSON against synthetic, explicitly labeled H-21 cases.

No network, subprocess, or source-path output. A positive label represents a
security concern in the synthetic story, NOT a claim of exploitability.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "mutation_corpus.py"
LABEL = re.compile(r"^\s*# h21-case: ([a-z_]+) ([a-z-]+) (vuln|safe)\s*$")
RULES = {
    "shell-true": "hermes-subprocess-shell-true",
    "shell-os-system": "hermes-direct-os-system",
    "tls-disable": "hermes-requests-verify-false",
    "jwt-no-verify": "hermes-jwt-verify-disabled",
    "token-log": "hermes-environment-secret-logged",
}


def cases(source: str) -> dict[int, tuple[str, str, str]]:
    ast.parse(source)  # Fixture must be valid Python.
    lines = source.splitlines()
    found: dict[int, tuple[str, str, str]] = {}
    names: set[str] = set()
    for i, line in enumerate(lines):
        match = LABEL.fullmatch(line)
        if not match:
            continue
        name, rule, label = match.groups()
        if name in names or rule not in RULES:
            raise ValueError("duplicate_or_unknown_case")
        names.add(name)
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j == len(lines) or lines[j].lstrip().startswith("#"):
            raise ValueError("missing_case_statement")
        if j + 1 in found:
            raise ValueError("multiple_labels_per_statement")
        found[j + 1] = (name, rule, label)
    if not found or len(found) != 29:
        raise ValueError("unexpected_mutation_case_inventory")
    if {rule for _, rule, _ in found.values()} != set(RULES):
        raise ValueError("missing_rule_in_corpus")
    return found


def score(report: dict, annotated: dict[int, tuple[str, str, str]]) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("scanner_results_missing")
    if report.get("errors") or report.get("skipped_rules"):
        raise ValueError("scanner_errors_or_skipped_rules")
    detected: set[int] = set()
    unexpected = 0
    duplicates = 0
    for finding in report["results"]:
        if not isinstance(finding, dict):
            raise ValueError("malformed_finding")
        rule = finding.get("check_id")
        line = finding.get("start", {}).get("line")
        path = finding.get("path", "")
        if (not isinstance(rule, str) or type(line) is not int
                or not isinstance(path, str)):
            raise ValueError("invalid_finding_coordinates")
        if not path.replace("\\", "/").endswith("/mutation_corpus.py"):
            unexpected += 1
            continue
        entry = annotated.get(line)
        if entry is None or not (
            rule == RULES[entry[1]] or rule.endswith("." + RULES[entry[1]])
        ):
            unexpected += 1
            continue
        if line in detected:
            duplicates += 1
        detected.add(line)
    totals = dict.fromkeys(("tp", "fp", "fn", "tn"), 0)
    per_rule: dict[str, dict[str, int]] = {
        key: dict.fromkeys(totals, 0) for key in RULES
    }
    misses: list[str] = []
    false_alarms: list[str] = []
    for line, (name, rule, label) in annotated.items():
        outcome = ("tp" if line in detected else "fn") if label == "vuln" else (
            "fp" if line in detected else "tn"
        )
        totals[outcome] += 1
        per_rule[rule][outcome] += 1
        if outcome == "fn":
            misses.append(name)
        if outcome == "fp":
            false_alarms.append(name)
    totals["fp"] += unexpected
    result = {
        "status": "SYNTHETIC_CORPUS_ONLY",
        "number_of_cases": len(annotated),
        "total": totals,
        "per_rule": per_rule,
        "missed_case_ids": sorted(misses),
        "false_alarm_case_ids": sorted(false_alarms),
        "unexpected_matches": unexpected,
        "duplicate_matches": duplicates,
        "precision": round(totals["tp"] / (totals["tp"] + totals["fp"]), 4)
        if totals["tp"] + totals["fp"] else None,
        "recall": round(totals["tp"] / (totals["tp"] + totals["fn"]), 4)
        if totals["tp"] + totals["fn"] else None,
        "real_project_precision_verified": False,
        "all_security_boundaries_verified": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    annotated = cases(CORPUS.read_text(encoding="utf-8"))
    raw = args.report.read_bytes()
    if not 0 < len(raw) < 2_000_000:
        raise ValueError("invalid_report_size")
    data = json.loads(raw)
    result = score(data, annotated)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
