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


class EvidenceDenied(ValueError):
    """Fixed denial code, never include untrusted report contents."""


def _unique(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceDenied("duplicate_key")
        obj[key] = value
    return obj


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
    if (type(skipped) is not list or not scanned or len(scanned) > MAX_PATHS
            or len(set(str(p) for p in scanned)) != len(scanned)):
        raise EvidenceDenied("incomplete_or_duplicate_file_inventory")
    roots = set()
    for name in scanned:
        if type(name) is not str or not 1 <= len(name) <= 500:
            raise EvidenceDenied("invalid_scanned_path")
        normalized = name.replace("\\", "/")
        if normalized.startswith(("http:", "https:")) or ".." in normalized.split("/"):
            raise EvidenceDenied("unsafe_scanned_path")
        matched = [root for root in ROOTS
                   if normalized.startswith(root + "/") or "/" + root + "/" in normalized]
        if len(matched) != 1 or not normalized.endswith(".py"):
            raise EvidenceDenied("unreviewed_scan_scope")
        roots.add(matched[0])
    if roots != set(ROOTS):
        raise EvidenceDenied("incomplete_scan_roots")
    if report["errors"] or report["skipped_rules"] or skipped:
        raise EvidenceDenied("scanner_errors_or_skips")
    findings = report["results"]
    if len(findings) > 10_000 or any(
        type(item) is not dict
        or type(item.get("check_id")) is not str
        or not 1 <= len(item["check_id"]) <= 200
        for item in findings
    ):
        raise EvidenceDenied("invalid_finding_inventory")
    return {
        "status": "BOUNDED_SCAN_SCOPE_RECORDED_NO_GO",
        "semgrep_version": VERSION,
        "scanned_files": len(scanned),
        "finding_count": len(findings),
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
