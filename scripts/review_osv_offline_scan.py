"""H-22: conservative, offline review of OSV-Scanner V2 JSON evidence.

Never invokes scanner, accesses a project, updates dependencies, or contacts APIs.
Manifest is operator-supplied and unsigned: hash parity alone cannot prove DB freshness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "hermes-h22-osv-evidence-v1"
VERSION = "2.7.0"
MAX_REPORT = 6_000_000
MAX_MANIFEST = 8_192
MAX_LOCKFILE = 8_000_000
HEX = re.compile(r"[a-f0-9]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\Z")
MANIFEST_KEYS = {
    "schema", "scanner_version", "scanner_binary_sha256", "db_zip_sha256",
    "db_ecosystem", "db_snapshot_utc", "report_sha256", "lockfile_sha256",
    "lockfile_kind", "scan_offline", "scanner_exit_code",
}
DB = {"uv.lock": "PyPI", "package-lock.json": "npm"}


class EvidenceDenied(ValueError):
    """Fixed codes only; never echo potentially private paths or source content."""


def _unique(pairs):
    record = {}
    for k, v in pairs:
        if k in record:
            raise EvidenceDenied("duplicate_json_key")
        record[k] = v
    return record


def _json(raw: bytes, limit: int):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise EvidenceDenied("missing_or_oversized_evidence")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except EvidenceDenied:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise EvidenceDenied("invalid_json") from None


def _shape(value, required):
    if type(value) is not dict or set(value) != required:
        raise EvidenceDenied("invalid_evidence_schema")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value):
    if type(value) is not str or not value.endswith("Z"):
        raise EvidenceDenied("invalid_db_snapshot")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceDenied("invalid_db_snapshot") from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise EvidenceDenied("invalid_db_snapshot")


def assess(manifest_raw: bytes, report_raw: bytes, lockfile_raw: bytes) -> dict:
    m = _json(manifest_raw, MAX_MANIFEST)
    _shape(m, MANIFEST_KEYS)
    if m["schema"] != SCHEMA or m["scanner_version"] != VERSION:
        raise EvidenceDenied("unrecognized_scanner_manifest")
    kind = m["lockfile_kind"]
    if type(kind) is not str or kind not in DB or m["db_ecosystem"] != DB[kind]:
        raise EvidenceDenied("unsupported_lockfile_or_db")
    _utc(m["db_snapshot_utc"])
    for key in ("scanner_binary_sha256", "db_zip_sha256",
                "report_sha256", "lockfile_sha256"):
        if type(m[key]) is not str or HEX.fullmatch(m[key]) is None:
            raise EvidenceDenied("invalid_hash")
    if type(m["scan_offline"]) is not bool or m["scan_offline"] is not True:
        raise EvidenceDenied("offline_only_required")
    if type(m["scanner_exit_code"]) is not int or m["scanner_exit_code"] not in (0, 1):
        raise EvidenceDenied("scanner_execution_not_verified")
    if type(lockfile_raw) is not bytes or not 0 < len(lockfile_raw) <= MAX_LOCKFILE:
        raise EvidenceDenied("lockfile_size_invalid")
    if _sha(report_raw) != m["report_sha256"] or _sha(lockfile_raw) != m["lockfile_sha256"]:
        raise EvidenceDenied("evidence_hash_mismatch")
    report = _json(report_raw, MAX_REPORT)
    if type(report) is not dict or set(report) != {"results"} or type(report["results"]) is not list:
        raise EvidenceDenied("invalid_osv_output")
    if not 1 <= len(report["results"]) <= 10:
        # An empty report cannot prove source extraction succeeded.
        raise EvidenceDenied("missing_or_unbounded_results")
    unique = set()
    packages = 0
    entries = 0
    alias_count = 0
    for result in report["results"]:
        if type(result) is not dict or "source" not in result or "packages" not in result:
            raise EvidenceDenied("invalid_result")
        source = result["source"]
        if (type(source) is not dict or source.get("type") != "lockfile"
                or type(source.get("path")) is not str or
                not source["path"].replace("\\", "/").endswith("/" + kind)
                and source["path"] != kind):
            raise EvidenceDenied("unexpected_source_type")
        items = result["packages"]
        if type(items) is not list or len(items) > 10000:
            raise EvidenceDenied("invalid_packages")
        for item in items:
            if type(item) is not dict or type(item.get("package")) is not dict:
                raise EvidenceDenied("invalid_package")
            pkg = item["package"]
            if (pkg.get("ecosystem") != DB[kind]
                    or type(pkg.get("name")) is not str or not pkg["name"]
                    or type(pkg.get("version")) is not str or not pkg["version"]):
                raise EvidenceDenied("invalid_package_identity")
            packages += 1
            vulns = item.get("vulnerabilities", [])
            if type(vulns) is not list or len(vulns) > 1000:
                raise EvidenceDenied("invalid_vulnerabilities")
            for vulnerability in vulns:
                if type(vulnerability) is not dict:
                    raise EvidenceDenied("invalid_vulnerability")
                v_id = vulnerability.get("id")
                if type(v_id) is not str or len(v_id) > 100:
                    raise EvidenceDenied("invalid_vulnerability_id")
                aliases = vulnerability.get("aliases", [])
                if (type(aliases) is not list or len(aliases) > 40
                        or any(type(x) is not str or len(x) > 100 for x in aliases)):
                    raise EvidenceDenied("invalid_aliases")
                entries += 1
                group = [s for s in [v_id, *aliases] if CVE.fullmatch(s) or GHSA.fullmatch(s)]
                alias_count += len(group)
                unique.update(group)
    if packages > 15000 or entries > 30000:
        raise EvidenceDenied("too_many_records")
    # Binary/DB SHA values originate only from the unsigned manifest; no auto-PASS.
    return {
        "schema": "hermes-h22-review-v1",
        "status": "INCONCLUSIVE",
        "reason": "unsigned_scanner_db_and_extraction_evidence",
        "source_kind": kind,
        "osv_scanner_version_claimed": VERSION,
        "evidence_hashes_match_manifest": True,
        "db_signature_verified": False,
        "db_completeness_verified": False,
        "scanner_binary_provenance_verified": False,
        "dependency_extraction_verified": False,
        "packages_with_result_entries": packages,
        "vulnerability_records": entries,
        "cve_ghsa_alias_occurrences": alias_count,
        "distinct_cve_ghsa_ids": len(unique),
        "report_contains_findings": bool(entries),
        "fix_versions_verified": False,
        "resident_agent_allowed": False,
        "auto_upgrade_allowed": False,
    }


def _read(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise EvidenceDenied("unsafe_or_missing_path")
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if not raw or len(raw) > limit:
        raise EvidenceDenied("unsafe_or_missing_path")
    return raw


def main(argv=None) -> int:
    cli = argparse.ArgumentParser(description="H-22 sanitized offline OSV evidence review")
    cli.add_argument("--manifest", type=Path)
    cli.add_argument("--report", type=Path)
    cli.add_argument("--lockfile", type=Path)
    cli.add_argument("--execute", action="store_true")
    args = cli.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        if args.manifest is None or args.report is None or args.lockfile is None:
            raise EvidenceDenied("missing_inputs")
        output = assess(_read(args.manifest, MAX_MANIFEST),
                        _read(args.report, MAX_REPORT),
                        _read(args.lockfile, MAX_LOCKFILE))
    except (EvidenceDenied, OSError, RecursionError):
        output = {"status": "INCONCLUSIVE", "reason": "evidence_invalid",
                  "resident_agent_allowed": False, "auto_upgrade_allowed": False}
    print(json.dumps(output, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
