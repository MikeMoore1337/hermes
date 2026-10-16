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


def _syft_image_identity(source: dict) -> bool:
    """Accept two strictly validated native Syft layouts, never just a mutable tag."""
    if source.get("type") != "image":
        raise ScanEvidenceDenied("invalid_syft_target")
    pinned_digest = IMAGE.partition("@")[2]
    target = source.get("target")
    if target is not None:
        if type(target) is not dict or target.get("userInput") != IMAGE:
            raise ScanEvidenceDenied("syft_subject_mismatch")
        if target.get("manifestDigest") != pinned_digest:
            raise ScanEvidenceDenied("syft_manifest_digest_missing_or_mismatch")
        return True

    # Syft 1.54.1 native JSON: source.metadata (not source.target).
    # The local Docker daemon may return a reconstructed manifestDigest
    # different from the published platform RepoDigest: keep this mismatch
    # visible, NEVER silently claim source-to-build parity.
    metadata = source.get("metadata")
    if type(metadata) is not dict:
        raise ScanEvidenceDenied("invalid_syft_target")
    if (source.get("name") != IMAGE.partition("@")[0]
            or source.get("version") != pinned_digest
            or metadata.get("userInput") != IMAGE
            or metadata.get("repoDigests") != [IMAGE]
            or metadata.get("architecture") != "amd64"
            or metadata.get("os") != "linux"):
        raise ScanEvidenceDenied("syft_subject_mismatch")
    local_digest = metadata.get("manifestDigest")
    if (type(local_digest) is not str or not local_digest.startswith("sha256:")
            or HEX.fullmatch(local_digest[7:]) is None
            or source.get("id") != local_digest[7:]):
        raise ScanEvidenceDenied("invalid_syft_local_manifest_identity")
    return local_digest == pinned_digest


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
    syft_local_manifest_matches_repo_digest = _syft_image_identity(source)
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
    trivy_identity = scan.get("Metadata")
    if trivy_identity is not None:
        if (type(trivy_identity) is not dict
                or trivy_identity.get("Reference") != IMAGE
                or trivy_identity.get("RepoDigests") != [IMAGE]):
            raise ScanEvidenceDenied("trivy_image_identity_mismatch")
    trivy_version = scan.get("Trivy")
    if trivy_version is not None:
        if (type(trivy_version) is not dict
                or trivy_version.get("Version") != info["trivy_version"]):
            raise ScanEvidenceDenied("trivy_version_mismatch")
    results = scan.get("Results")
    if type(results) is not list or not 1 <= len(results) <= 1000:
        raise ScanEvidenceDenied("trivy_results_missing")
    vulnerable = 0
    blocking = 0
    vulnerability_ids: set[str] = set()
    severities: dict[str, int] = {}
    for result in results:
        if type(result) is not dict:
            raise ScanEvidenceDenied("invalid_trivy_result")
        # A missing key can be native Trivy output for a clean target.
        # Explicit null, false, empty object or string is corrupted evidence.
        findings = result["Vulnerabilities"] if "Vulnerabilities" in result else []
        if type(findings) is not list or len(findings) > 10_000:
            raise ScanEvidenceDenied("invalid_trivy_findings")
        for finding in findings:
            if type(finding) is not dict:
                raise ScanEvidenceDenied("invalid_trivy_finding")
            vuln_id = finding.get("VulnerabilityID")
            if type(vuln_id) is not str or not 1 <= len(vuln_id) <= 128:
                raise ScanEvidenceDenied("invalid_trivy_finding")
            severity = finding.get("Severity")
            if type(severity) is not str or severity not in {
                    "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ScanEvidenceDenied("invalid_trivy_severity")
            vulnerable += 1
            vulnerability_ids.add(vuln_id)
            severities[severity] = severities.get(severity, 0) + 1
            blocking += severity in {"HIGH", "CRITICAL"}
    return {
        "status": "HIGH_CVE_REVIEW" if blocking else "UNATTESTED_REVIEW_REQUIRED",
        "image": IMAGE, "platform": "linux/amd64",
        "syft_artifact_count": len(artifacts),
        "trivy_vulnerability_count": vulnerable,
        "trivy_high_critical_count": blocking,
        "trivy_unique_vulnerability_ids": len(vulnerability_ids),
        "trivy_severity_counts": dict(sorted(severities.items())),
        "syft_local_manifest_matches_pinned_repo_digest":
            syft_local_manifest_matches_repo_digest,
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
