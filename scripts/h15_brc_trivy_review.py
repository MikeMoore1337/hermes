#!/usr/bin/env python3
"""H-15: review pinned Trivy JSON from the ACTUAL CI-built relay image.

Conservative, offline-only parser. Vulnerabilities are recorded, not waived.
Successful report parsing never grants production deployment. No network, Docker,
scanner installation or sensitive package/target/vulnerability text in output.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

MAX_REPORT = 15_000_000
IMAGE_RE = re.compile(r"sha256:[a-f0-9]{64}\Z")
LEVELS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class ScanDenied(ValueError):
    pass


def _strict_dict(pairs: list[tuple[str, object]]) -> dict:
    data = {}
    for key, value in pairs:
        if key in data:
            raise ScanDenied("duplicate_json_key")
        data[key] = value
    return data


def assess(raw: bytes, expected_image_id: str) -> dict:
    if not IMAGE_RE.fullmatch(expected_image_id):
        raise ScanDenied("invalid_expected_image")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REPORT:
        raise ScanDenied("empty_or_oversized_report")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_dict)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ScanDenied):
            raise
        raise ScanDenied("malformed_scan_json") from exc
    if not isinstance(data, dict) or data.get("SchemaVersion") != 2:
        raise ScanDenied("unsupported_trivy_schema")
    if data.get("ArtifactType") != "container_image":
        raise ScanDenied("wrong_target_type")
    metadata = data.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("ImageID") != expected_image_id:
        raise ScanDenied("image_digest_mismatch")
    os_meta = metadata.get("OS")
    if not isinstance(os_meta, dict) or os_meta.get("Family") != "debian":
        raise ScanDenied("wrong_os_family")
    targets = data.get("Results")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 150:
        raise ScanDenied("missing_scan_targets")
    counts = Counter({level: 0 for level in LEVELS})
    covered = set()
    vuln_records = 0
    os_packages = 0
    lang_packages = 0
    for target in targets:
        if not isinstance(target, dict):
            raise ScanDenied("invalid_scan_target")
        cls = target.get("Class")
        if cls not in ("os-pkgs", "lang-pkgs"):
            raise ScanDenied("unexpected_scan_class")
        if cls == "os-pkgs":
            if target.get("Type") != "debian":
                raise ScanDenied("wrong_os_scan_type")
            covered.add(cls)
        else:
            covered.add(cls)
        items = target.get("Packages") or []
        if not isinstance(items, list) or len(items) > 30000:
            raise ScanDenied("invalid_package_records")
        if any(not isinstance(item, dict) for item in items):
            raise ScanDenied("invalid_package_record")
        if cls == "os-pkgs":
            os_packages += len(items)
        else:
            lang_packages += len(items)
        vulnerabilities = target.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 20000:
            raise ScanDenied("invalid_vulnerability_records")
        for v in vulnerabilities:
            if not isinstance(v, dict):
                raise ScanDenied("invalid_vulnerability_record")
            if not isinstance(v.get("VulnerabilityID"), str) or not v["VulnerabilityID"]:
                raise ScanDenied("missing_vulnerability_identifier")
            severity = v.get("Severity", "UNKNOWN")
            if severity not in LEVELS:
                raise ScanDenied("unknown_severity")
            counts[severity] += 1
            vuln_records += 1
    # --list-all-pkgs must be used to demonstrate OS package extraction.
    if "os-pkgs" not in covered or not 30 <= os_packages <= 1500:
        raise ScanDenied("os_package_extraction_unproven")
    return {
        "schema": "hermes-h15-trivy-review-v1",
        "status": "REVIEW_REQUIRED" if vuln_records else "NO_FINDINGS_OBSERVED",
        "image_id": expected_image_id,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "scan_completed": True,
        "os_packages_detected": os_packages,
        "language_packages_detected": lang_packages,
        "os_scan_target_present": True,
        "language_scan_target_present": "lang-pkgs" in covered,
        "vulnerability_records": vuln_records,
        "severity_counts": dict(counts),
        "high_critical_records": counts["HIGH"] + counts["CRITICAL"],
        "db_freshness_cryptographically_verified": False,
        "fixed_version_review_completed": False,
        "production_release_approved": False,
        "public_mcp_enable_allowed": False,
        "owner_device_commands_allowed": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--image-id", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.report.is_symlink() or not args.report.is_file():
            raise ScanDenied("unsafe_report_path")
        if args.report.stat().st_size > MAX_REPORT:
            raise ScanDenied("oversized_report")
        summary = assess(args.report.read_bytes(), args.image_id)
        # xb is atomic no-clobber, including a preexisting symlink.
        with args.output.open("xb") as file:
            file.write((json.dumps(summary, sort_keys=True, indent=2) + "\n").encode())
    except (ScanDenied, OSError, ValueError, RecursionError):
        print("H15_TRIVY_REVIEW=INCONCLUSIVE")
        print("H15_TRIVY_PRODUCTION_GO=NO")
        return 2
    print("H15_TRIVY_REVIEW=" + summary["status"])
    print("H15_TRIVY_OS_PACKAGES=" + str(summary["os_packages_detected"]))
    print("H15_TRIVY_HIGH_CRITICAL=" + str(summary["high_critical_records"]))
    print("H15_TRIVY_PRODUCTION_GO=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
