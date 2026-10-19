#!/usr/bin/env python3
"""H-15: offline, source-linked reconciliation of all OCI HIGH/CRITICAL CVEs.

Documentation/evidence ONLY. Never makes an image deployable or waives a CVE.
Does not fetch untrusted references, call Docker, or access owner devices.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from scripts.h15_brc_trivy_review import MAX_REPORT, _strict_dict, assess

CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
DISPOSITIONS = {"UNRESOLVED", "DEBIAN_SOURCE_EXCEPTION_REQUIRES_OWNER_REVIEW"}
EXPECTED_SCOPE = "DISPOSABLE_BRC_RELAY_OCI_ONLY"
EXPECTED_PACKAGE_CLASS = {"braces": "lang-pkgs"}
MAX_LEDGER = 100_000


class TriageError(ValueError):
    pass


def reconcile(raw: bytes, image_id: str, ledger: dict) -> dict:
    # Existing image validator verifies Docker ID, Debian OS, Trivy schema,
    # observed OS package extraction and package/vulnerability record types.
    examined = assess(raw, image_id)
    if not isinstance(ledger, dict) or ledger.get("schema") != 1:
        raise TriageError("unsupported_ledger_schema")
    if ledger.get("owner_approval") != "NOT_GRANTED" or ledger.get("scope") != EXPECTED_SCOPE:
        raise TriageError("implicit_release_approval_refused")
    baseline = ledger.get("evidence")
    entries = ledger.get("cves")
    if (not isinstance(baseline, dict) or not isinstance(entries, list)
            or not 1 <= len(entries) <= 200):
        raise TriageError("incomplete_review_ledger")
    if (not isinstance(baseline.get("image_id"), str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", baseline["image_id"])
            or not isinstance(baseline.get("report_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", baseline["report_sha256"])):
        raise TriageError("invalid_baseline_identity")
    if baseline.get("observed_distinct_cves") != len(entries):
        raise TriageError("baseline_cardinality_mismatch")
    if (sum(e.get("baseline_records", 0) for e in entries
            if isinstance(e, dict)) != baseline.get("observed_high_critical_records")):
        raise TriageError("baseline_record_mismatch")
    reviewed = {}
    for row in entries:
        if not isinstance(row, dict) or set(row) != {
            "id", "source_package", "baseline_records", "disposition",
            "reason", "reference", "baseline_packages",
        }:
            raise TriageError("invalid_review_entry")
        ident = row["id"]
        if not isinstance(ident, str) or not CVE.fullmatch(ident) or ident in reviewed:
            raise TriageError("invalid_or_duplicate_cve")
        if row["disposition"] not in DISPOSITIONS:
            raise TriageError("unapproved_disposition")
        if (row["disposition"] == "DEBIAN_SOURCE_EXCEPTION_REQUIRES_OWNER_REVIEW"
                and ident != "CVE-2023-45853"):
            raise TriageError("unsupported_source_exception")
        if row["reference"] != "https://security-tracker.debian.org/tracker/" + ident:
            raise TriageError("untrusted_reference")
        if (not isinstance(row["reason"], str) or not 15 <= len(row["reason"]) <= 800
                or not isinstance(row["source_package"], str)
                or not row["source_package"].strip()
                or not isinstance(row["baseline_records"], int)
                or row["baseline_records"] < 1):
            raise TriageError("incomplete_review_reason")
        packages = row["baseline_packages"]
        if (not isinstance(packages, list) or not packages
                or len(packages) > 50
                or any(not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", p)
                       for p in packages)
                or len(packages) != len(set(packages))):
            raise TriageError("invalid_baseline_packages")
        reviewed[ident] = row
    if not isinstance(raw, bytes) or len(raw) > MAX_REPORT:
        raise TriageError("oversized_report")
    report = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_dict)
    observed: dict[str, dict] = {}
    for result in report["Results"]:
        if result["Class"] not in ("os-pkgs", "lang-pkgs"):
            raise TriageError("unsupported_package_class")
        for finding in result.get("Vulnerabilities") or []:
            if finding.get("Severity") not in ("HIGH", "CRITICAL"):
                continue
            ident = finding["VulnerabilityID"]
            if not isinstance(ident, str) or not CVE.fullmatch(ident):
                raise TriageError("unrecognized_vulnerability_id")
            package = finding.get("PkgName")
            if not isinstance(package, str) or not package:
                raise TriageError("unattributed_package")
            group = observed.setdefault(ident, {"records": 0, "packages": set(), "class": result["Class"]})
            if group["class"] != result["Class"]:
                raise TriageError("mixed_package_class")
            group["records"] += 1
            group["packages"].add(package)
    rows = []
    for ident, group in sorted(observed.items()):
        existing = reviewed.get(ident)
        if existing is None:
            disposition = "NEW_IDENTFIER_NOT_REVIEWED"
            matched = False
            source = "UNKNOWN"
        else:
            disposition = existing["disposition"]
            source = existing["source_package"]
            expected_class = EXPECTED_PACKAGE_CLASS.get(source, "os-pkgs")
            matched = (set(group["packages"]).issubset(existing["baseline_packages"])
                       and group["class"] == expected_class)
            if not matched:
                disposition = "PACKAGE_SCOPE_CHANGED_REVIEW_REQUIRED"
        rows.append({
            "id": ident, "records": group["records"],
            "source_package": source,
            "disposition": disposition,
            "package_scope_matches_reviewed_baseline": matched,
            "owner_signoff": False,
        })
    unknown = sum(1 for row in rows if row["disposition"] == "NEW_IDENTFIER_NOT_REVIEWED")
    changed = sum(1 for row in rows if row["disposition"] == "PACKAGE_SCOPE_CHANGED_REVIEW_REQUIRED")
    source_exceptions = sum(
        1 for row in rows if row["disposition"] == "DEBIAN_SOURCE_EXCEPTION_REQUIRES_OWNER_REVIEW"
    )
    observed_total = sum(row["records"] for row in rows)
    if observed_total != examined["high_critical_records"]:
        raise TriageError("scanner_reconciliation_mismatch")
    if (image_id == baseline["image_id"]
            and hashlib.sha256(raw).hexdigest() != baseline["report_sha256"]):
        raise TriageError("baseline_image_report_mismatch")
    return {
        "schema": "hermes-h15-cve-triage-v1",
        "image_id": image_id,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "total_high_critical_records": observed_total,
        "distinct_cve_count": len(rows),
        "unknown_cve_count": unknown,
        "changed_package_scope_count": changed,
        "source_exception_pending_signoff": source_exceptions,
        "absent_baseline_cve_count": len(set(reviewed) - set(observed)),
        "review_status": "INCOMPLETE" if unknown or changed else "KNOWN_IDS_RECONCILED",
        "cves": rows,
        "production_release_approved": False,
        "public_mcp_enable_allowed": False,
        "owner_device_commands_allowed": False,
        "owner_signoff_received": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        for path, max_bytes in ((args.report, MAX_REPORT), (args.ledger, MAX_LEDGER)):
            if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= max_bytes:
                raise TriageError("unsafe_input")
        ledger = json.loads(args.ledger.read_text("utf-8"), object_pairs_hook=_strict_dict)
        triage = reconcile(args.report.read_bytes(), args.image_id, ledger)
        with args.output.open("xb") as target:
            target.write((json.dumps(triage, indent=2, sort_keys=True) + "\n").encode())
    except (OSError, ValueError, UnicodeError, RecursionError, KeyError, TypeError):
        print("H15_CVE_TRIAGE=INVALID_EVIDENCE")
        print("H15_CVE_PRODUCTION_GO=NO")
        return 2
    print("H15_CVE_TRIAGE=" + triage["review_status"])
    print("H15_CVE_HIGH_CRITICAL=" + str(triage["total_high_critical_records"]))
    print("H15_CVE_DISTINCT=" + str(triage["distinct_cve_count"]))
    print("H15_CVE_UNREVIEWED=" + str(triage["unknown_cve_count"]))
    print("H15_CVE_CHANGED_SCOPE=" + str(triage["changed_package_scope_count"]))
    print("H15_CVE_PRODUCTION_GO=NO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
