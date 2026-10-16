"""Read-only, offline review of externally generated Syft/Trivy evidence.

No scanner execution, Docker commands, network, secrets, image pulls or writes.
A matching self-reported digest is NOT signed source-to-image provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

IMAGE = (
    "nousresearch/hermes-agent@sha256:"
    "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05"
)
SCHEMA = "hermes-h18-scan-evidence-v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
MAX_BYTES = 12_000_000
MANIFEST_KEYS = {
    "schema", "image", "platform", "syft_sha256", "trivy_sha256",
    "syft_version", "trivy_version", "trivy_db_sha256",
    "trivy_db_updated_at", "scanner_run_at",
}


class ScanEvidenceDenied(ValueError):
    """Fixed diagnostics only. Raw scanner contents must never enter logs."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScanEvidenceDenied("duplicate_json_key")
        result[key] = value
    return result


def _read(path: Path, max_bytes: int = MAX_BYTES) -> bytes:
    # Reject symlinks to prevent accidentally ingesting secrets through a link.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ScanEvidenceDenied("missing_or_oversized_evidence")
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    if not 1 <= len(data) <= max_bytes:
        raise ScanEvidenceDenied("missing_or_oversized_evidence")
    return data


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, TypeError):
        raise ScanEvidenceDenied("invalid_json") from None
    if type(value) is not dict:
        raise ScanEvidenceDenied("invalid_object")
    return value


def _utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ScanEvidenceDenied("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ScanEvidenceDenied("invalid_timestamp") from None
    return parsed


def assess(manifest: bytes, syft: bytes, trivy: bytes) -> dict:
    info = _json(manifest)
    if set(info) != MANIFEST_KEYS or info["schema"] != SCHEMA:
        raise ScanEvidenceDenied("invalid_manifest_schema")
    if info["image"] != IMAGE or info["platform"] != "linux/amd64":
        raise ScanEvidenceDenied("unexpected_image_identity")
    for field in ("syft_sha256", "trivy_sha256", "trivy_db_sha256"):
        if type(info[field]) is not str or not HEX.fullmatch(info[field]):
            raise ScanEvidenceDenied("invalid_hash")
    for field in ("syft_version", "trivy_version"):
        if type(info[field]) is not str or not VERSION.fullmatch(info[field]):
            raise ScanEvidenceDenied("invalid_scanner_version")
    if hashlib.sha256(syft).hexdigest() != info["syft_sha256"]:
        raise ScanEvidenceDenied("syft_sha256_mismatch")
    if hashlib.sha256(trivy).hexdigest() != info["trivy_sha256"]:
        raise ScanEvidenceDenied("trivy_sha256_mismatch")
    db_time = _utc(info["trivy_db_updated_at"])
    run_time = _utc(info["scanner_run_at"])
    if not db_time <= run_time <= db_time + timedelta(days=7):
        raise ScanEvidenceDenied("db_time_outside_declared_scan_window")

    sbom, scan = _json(syft), _json(trivy)
    desc, source = sbom.get("descriptor"), sbom.get("source")
    if type(desc) is not dict or type(source) is not dict:
        raise ScanEvidenceDenied("invalid_syft_source")
    if desc.get("name") != "syft" or desc.get("version") != info["syft_version"]:
        raise ScanEvidenceDenied("syft_version_mismatch")
    target = source.get("target")
    if source.get("type") != "image" or type(target) is not dict:
        raise ScanEvidenceDenied("invalid_syft_target")
    if target.get("userInput") != IMAGE:
        raise ScanEvidenceDenied("syft_subject_mismatch")
    # Self-reported platform manifest is corroborating metadata, NOT attestation.
    declared = target.get("manifestDigest")
    if declared != IMAGE.split("@", 1)[1]:
        raise ScanEvidenceDenied("syft_manifest_digest_missing_or_mismatch")
    artifacts = sbom.get("artifacts")
    if type(artifacts) is not list or not 1 <= len(artifacts) <= 100_000:
        raise ScanEvidenceDenied("syft_packages_unavailable")
    if any(type(row) is not dict or
           type(row.get("name")) is not str or not row["name"] or
           type(row.get("version")) is not str or not row["version"]
           for row in artifacts):
        raise ScanEvidenceDenied("invalid_syft_package")

    if (scan.get("SchemaVersion") != 2 or
            scan.get("ArtifactName") != IMAGE or
            scan.get("ArtifactType") != "container_image"):
        raise ScanEvidenceDenied("invalid_trivy_subject")
    results = scan.get("Results")
    if type(results) is not list or not 1 <= len(results) <= 1000:
        raise ScanEvidenceDenied("trivy_results_missing")
    vulnerable = 0
    blocking = 0
    for result in results:
        if type(result) is not dict:
            raise ScanEvidenceDenied("invalid_trivy_result")
        findings = result.get("Vulnerabilities") or []
        if type(findings) is not list or len(findings) > 10_000:
            raise ScanEvidenceDenied("invalid_trivy_findings")
        for finding in findings:
            if type(finding) is not dict or not finding.get("VulnerabilityID"):
                raise ScanEvidenceDenied("invalid_trivy_finding")
            severity = finding.get("Severity")
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ScanEvidenceDenied("invalid_trivy_severity")
            vulnerable += 1
            blocking += severity in {"HIGH", "CRITICAL"}
    return {
        "status": "HIGH_CVE_REVIEW" if blocking else "UNATTESTED_REVIEW_REQUIRED",
        "image": IMAGE, "platform": "linux/amd64",
        "syft_artifact_count": len(artifacts),
        "trivy_vulnerability_count": vulnerable,
        "trivy_high_critical_count": blocking,
        "scanner_reports_hash_checked": True,
        "vulnerability_database_identity_self_reported": True,
        "source_to_image_provenance_verified": False,
        "scanner_binary_provenance_verified": False,
        "complete_sbom_verified": False,
        "vulnerability_coverage_verified": False,
        "production_deployed": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Syft/Trivy evidence review (never GO)")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--syft-json", type=Path)
    parser.add_argument("--trivy-json", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if not all((args.manifest, args.syft_json, args.trivy_json)):
        print(json.dumps({"status": "INCONCLUSIVE", "reason": "inputs_required",
                          "resident_agent_allowed": False}))
        return 2
    try:
        report = assess(_read(args.manifest, 16_384),
                        _read(args.syft_json), _read(args.trivy_json))
    except (ScanEvidenceDenied, OSError, RecursionError):
        print(json.dumps({"status": "INCONCLUSIVE", "reason": "invalid_scan_evidence",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    # A self-reported scan cannot prove provenance or grant runtime permissions.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
