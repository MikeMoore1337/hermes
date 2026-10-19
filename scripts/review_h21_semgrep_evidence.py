"""H-21 #188: local Semgrep JSON evidence reviewer, never a security GO.

This runs no Semgrep, scans no files, and emits no source paths or findings.
Only an observed, bounded, complete report may record scope. It cannot
substitute for scanner provenance, false-negative tests, or CodeQL comparison.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

VERSION = "1.181.0"
MAX_BYTES = 2_000_000
MAX_PATHS = 2000
ROOTS = ("scripts", "qa_advisor")
# A finding must belong to one of the five reviewed local rules. This is
# NOT evidence that every rule actually executed when the result list is empty.
RULE_IDS = frozenset({
    "hermes-subprocess-shell-true",
    "hermes-direct-os-system",
    "hermes-requests-verify-false",
    "hermes-jwt-verify-disabled",
    "hermes-environment-secret-logged",
})


class EvidenceDenied(ValueError):
    """Fixed denial code, never include untrusted report contents."""


def _unique(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceDenied("duplicate_key")
        obj[key] = value
    return obj


def _scoped_path(value: object) -> str:
    """Normalize ONLY /code/<root>/... or <root>/... offline Docker paths."""
    if type(value) is not str or not 1 <= len(value) <= 500:
        raise EvidenceDenied("invalid_scan_path")
    name = value.replace("\\", "/")
    if (any(ord(c) < 32 or ord(c) == 127 for c in name)
            or ":" in name or "//" in name):
        raise EvidenceDenied("unsafe_scan_path")
    if name.startswith("/code/"):
        name = name[len("/code/"):]
    elif name.startswith("/"):
        raise EvidenceDenied("unreviewed_scan_root")
    parts = name.split("/")
    if (len(parts) < 2 or any(p in ("", ".", "..") for p in parts)
            or parts[0] not in ROOTS or not name.endswith(".py")):
        raise EvidenceDenied("unreviewed_scan_scope")
    return name


def _location(value: object) -> tuple[int, int]:
    if type(value) is not dict:
        raise EvidenceDenied("missing_finding_location")
    line, column = value.get("line"), value.get("col")
    if (type(line) is not int or line < 1
            or type(column) is not int or column < 1):
        raise EvidenceDenied("invalid_finding_location")
    return line, column


def review(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise EvidenceDenied("size_invalid")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError):
        raise EvidenceDenied("json_invalid") from None
    if type(report) is not dict or report.get("version") != VERSION:
        raise EvidenceDenied("scanner_version_unverified")
    if any(type(report.get(key)) is not list for key in
           ("results", "errors", "skipped_rules")):
        raise EvidenceDenied("missing_result_or_error_inventory")
    paths = report.get("paths")
    if type(paths) is not dict or type(paths.get("scanned")) is not list:
        raise EvidenceDenied("scanned_inventory_missing")
    scanned = paths["scanned"]
    skipped = paths.get("skipped", [])
    if type(skipped) is not list or type(scanned) is not list:
        raise EvidenceDenied("invalid_scan_inventory")
    if not scanned or len(scanned) > MAX_PATHS:
        raise EvidenceDenied("missing_or_oversized_scan_scope")
    normalized = [_scoped_path(name) for name in scanned]
    if len(set(normalized)) != len(normalized):
        raise EvidenceDenied("duplicate_scanned_path")
    if {name.split("/", 1)[0] for name in normalized} != set(ROOTS):
        raise EvidenceDenied("incomplete_scan_roots")
    if report["errors"] or report["skipped_rules"] or skipped:
        raise EvidenceDenied("scanner_errors_or_skips")
    findings = report["results"]
    if len(findings) > 10_000:
        raise EvidenceDenied("oversized_finding_inventory")
    known_paths = set(normalized)
    seen_findings: set[tuple[str, str, tuple[int, int], tuple[int, int]]] = set()
    for item in findings:
        if type(item) is not dict:
            raise EvidenceDenied("invalid_finding_inventory")
        rule = item.get("check_id")
        if (type(rule) is not str or not 1 <= len(rule) <= 200
                or not any(rule == known or rule.endswith("." + known)
                           for known in RULE_IDS)):
            raise EvidenceDenied("unknown_finding_rule")
        location = _scoped_path(item.get("path"))
        if location not in known_paths:
            raise EvidenceDenied("finding_outside_scanned_scope")
        beginning = _location(item.get("start"))
        ending = _location(item.get("end"))
        if ending < beginning:
            raise EvidenceDenied("invalid_finding_range")
        key = (rule, location, beginning, ending)
        if key in seen_findings:
            raise EvidenceDenied("duplicate_finding")
        seen_findings.add(key)
    return {
        "status": "BOUNDED_SCAN_SCOPE_RECORDED_NO_GO",
        "semgrep_version": VERSION,
        "scanned_files": len(scanned),
        "finding_count": len(findings),
        "rule_execution_inventory_verified": False,
        "scan_exit_code_verified": False,
        "errors_and_skips": 0,
        "coverage_and_false_negatives_verified": False,
        "incremental_value_over_codeql_verified": False,
        "scanner_binary_provenance_verified": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="No-network Semgrep evidence reviewer")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        path = args.report
        if path is None or path.is_symlink() or not path.is_file():
            raise EvidenceDenied("missing_or_unsafe_report")
        if not 0 < path.stat().st_size <= MAX_BYTES:
            raise EvidenceDenied("report_size_denied")
        with path.open("rb") as file:
            outcome = review(file.read(MAX_BYTES + 1))
    except (OSError, EvidenceDenied):
        outcome = {"status": "INCONCLUSIVE", "resident_agent_allowed": False}
    print(json.dumps(outcome, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
