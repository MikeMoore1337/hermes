"""H-22: no optimistic PASS without signed offline DB and binary provenance."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts import review_osv_offline_scan as scanner


def sample(kind="uv.lock", vulnerabilities=None):
    vulnerable = vulnerabilities if vulnerabilities is not None else []
    lockfile = (b'[[package]]\nname = "fictional-public"\nversion = "1.0.0"'
                if kind == "uv.lock" else b'{"lockfileVersion":3,"packages":{}}')
    raw = {
        "results": [{
            "source": {"type": "lockfile", "path": "/synthetic/" + kind},
            "packages": [{
                "package": {
                    "name": "fictional-public",
                    "version": "1.0.0",
                    "ecosystem": scanner.DB[kind],
                },
                "vulnerabilities": vulnerable,
            }],
        }]
    }
    report = json.dumps(raw).encode()
    manifest = {
        "schema": scanner.SCHEMA,
        "scanner_version": scanner.VERSION,
        "scanner_binary_sha256": "a" * 64,
        "db_zip_sha256": "b" * 64,
        "db_ecosystem": scanner.DB[kind],
        "db_snapshot_utc": "2026-10-16T12:30:00Z",
        "report_sha256": hashlib.sha256(report).hexdigest(),
        "lockfile_sha256": hashlib.sha256(lockfile).hexdigest(),
        "lockfile_kind": kind,
        "scan_offline": True,
        "scanner_exit_code": 0,
    }
    return manifest, raw, lockfile


def review(m, report, lockfile):
    report_raw = json.dumps(report).encode()
    m["report_sha256"] = hashlib.sha256(report_raw).hexdigest()
    return scanner.assess(json.dumps(m).encode(), report_raw, lockfile)


class OfflineOSVEvidenceTest(unittest.TestCase):
    def test_clean_report_cannot_be_declared_pass(self):
        m, r, lockfile = sample()
        report = review(m, r, lockfile)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        self.assertEqual(report["packages_with_result_entries"], 1)
        self.assertEqual(report["vulnerability_records"], 0)
        self.assertFalse(report["db_signature_verified"])
        self.assertFalse(report["dependency_extraction_verified"])
        self.assertFalse(report["resident_agent_allowed"])
        self.assertFalse(report["auto_upgrade_allowed"])

    def test_cvss_not_invented_aliases_deduplicated(self):
        vulns = [
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-102268"]},
            {"id": "CVE-2026-102268", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
        ]
        m, r, lockfile = sample(vulnerabilities=vulns)
        report = review(m, r, lockfile)
        self.assertEqual(report["vulnerability_records"], 2)
        self.assertEqual(report["distinct_cve_ghsa_ids"], 2)
        self.assertEqual(report["cve_ghsa_alias_occurrences"], 4)
        self.assertTrue(report["report_contains_findings"])
        self.assertFalse(report["fix_versions_verified"])

    def test_package_lock_npm_accepted(self):
        m, r, lockfile = sample(kind="package-lock.json")
        self.assertEqual(review(m, r, lockfile)["source_kind"], "package-lock.json")

    def test_missing_database_provenance_stays_inconclusive(self):
        m, r, lockfile = sample()
        m["db_zip_sha256"] = "c" * 64  # Self-declared digest cannot prove supplied DB.
        self.assertEqual(review(m, r, lockfile)["status"], "INCONCLUSIVE")

    def test_disallow_online_execution(self):
        m, r, lockfile = sample()
        m["scan_offline"] = False
        with self.assertRaisesRegex(scanner.EvidenceDenied, "offline_only_required"):
            review(m, r, lockfile)

    def test_wrong_scanner_version_rejected(self):
        m, r, lockfile = sample()
        m["scanner_version"] = "0.0.0"
        with self.assertRaisesRegex(scanner.EvidenceDenied, "unrecognized_scanner_manifest"):
            review(m, r, lockfile)

    def test_missing_or_wrong_lockfile_ecosystem_rejected(self):
        m, r, lockfile = sample()
        m["db_ecosystem"] = "Go"
        with self.assertRaisesRegex(scanner.EvidenceDenied, "unsupported_lockfile_or_db"):
            review(m, r, lockfile)

    def test_report_hash_mismatch_rejected(self):
        m, r, lockfile = sample()
        m["report_sha256"] = "0" * 64
        with self.assertRaisesRegex(scanner.EvidenceDenied, "evidence_hash_mismatch"):
            scanner.assess(json.dumps(m).encode(), json.dumps(r).encode(), lockfile)

    def test_lockfile_hash_mismatch_rejected(self):
        m, r, lockfile = sample()
        with self.assertRaisesRegex(scanner.EvidenceDenied, "evidence_hash_mismatch"):
            review(m, r, lockfile + b"corrupted")

    def test_unknown_source_or_ecosystem_rejected(self):
        for mode in ("source", "package"):
            m, r, lockfile = sample()
            if mode == "source":
                r["results"][0]["source"]["type"] = "docker"
            else:
                r["results"][0]["packages"][0]["package"]["ecosystem"] = "npm"
            with self.subTest(mode=mode):
                with self.assertRaises(scanner.EvidenceDenied):
                    review(m, r, lockfile)

    def test_raw_private_strings_not_reported(self):
        m, r, lockfile = sample(vulnerabilities=[{
            "id": "GHSA-aaaa-bbbb-cccc", "summary": "PRIVATE_MARKER_STRING",
            "aliases": ["CVE-2026-222222"],
        }])
        r["results"][0]["source"]["path"] = "C:\\secret-dir\\uv.lock"
        r["results"][0]["packages"][0]["package"]["name"] = "private-pkg-PRIVATE_MARKER_STRING"
        output = json.dumps(review(m, r, lockfile))
        self.assertNotIn("PRIVATE_MARKER_STRING", output)
        self.assertNotIn("secret-dir", output)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", output)

    def test_empty_or_duplicate_evidence_rejected(self):
        for raw in (b"", b'{}', b'{"results":[]}',
                    b'{"results": [], "results": []}', b"x" * (scanner.MAX_REPORT + 1)):
            with self.subTest(raw=raw[:15]):
                with self.assertRaises(scanner.EvidenceDenied):
                    scanner.assess(json.dumps(sample()[0]).encode(), raw, sample()[2])

    def test_unsigned_binary_and_db_never_grant_go(self):
        m, r, lockfile = sample()
        m["scanner_exit_code"] = 0
        output = review(m, r, lockfile)
        self.assertEqual(output["status"], "INCONCLUSIVE")
        self.assertFalse(output["scanner_binary_provenance_verified"])
        self.assertFalse(output["db_completeness_verified"])

    def test_cli_without_optin_does_not_load_files(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = scanner.main([])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")

    def test_cli_invalid_path_only_fixed_error_code(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = scanner.main(["--execute", "--manifest", "MISSING_SENSITIVE_PATH"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "INCONCLUSIVE")
        self.assertNotIn("MISSING_SENSITIVE_PATH", out.getvalue())


if __name__ == "__main__":
    unittest.main()
