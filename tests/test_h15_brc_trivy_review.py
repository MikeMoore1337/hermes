"""H-15 Trivy report: sanitized, exact-image, fail-closed offline tests."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_brc_trivy_review import ScanDenied, assess

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/h15_brc_trivy_review.py"
IMAGE = "sha256:" + "a" * 64


def fixture(findings=True):
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE, "OS": {"Family": "debian", "Name": "12"}},
        "Results": [
            {
                "Class": "os-pkgs", "Type": "debian", "Target": "private-path-marker",
                "Packages": [{"Name": f"pkg{i}", "Version": "1"} for i in range(88)],
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2099-99999",
                    "PkgName": "secrets-marker",
                    "Severity": "HIGH", "FixedVersion": "2",
                }] if findings else [],
            },
            {
                "Class": "lang-pkgs", "Type": "npm",
                "Packages": [{"Name": "sample", "Version": "1"}],
                "Vulnerabilities": [],
            },
        ],
    }


def review(report=None):
    return assess(json.dumps(report or fixture()).encode(), IMAGE)


class TrivyReviewTests(unittest.TestCase):
    def test_report_binds_real_image_and_sanitizes_findings(self):
        output = review()
        self.assertEqual(output["status"], "REVIEW_REQUIRED")
        self.assertEqual(output["image_id"], IMAGE)
        self.assertEqual(output["os_packages_detected"], 88)
        self.assertEqual(output["language_packages_detected"], 1)
        self.assertEqual(output["high_critical_records"], 1)
        self.assertEqual(output["high_critical_by_source"], {"os-pkgs": 1, "lang-pkgs": 0})
        self.assertEqual(output["high_critical_with_fixed_version_claim"], {"os-pkgs": 1, "lang-pkgs": 0})
        self.assertFalse(output["production_release_approved"])
        self.assertFalse(output["public_mcp_enable_allowed"])
        self.assertFalse(output["owner_device_commands_allowed"])
        self.assertNotIn("secrets-marker", str(output))
        self.assertNotIn("private-path-marker", str(output))
        self.assertNotIn("CVE-2099", str(output))

    def test_empty_findings_not_promoted_to_release_go(self):
        out = review(fixture(findings=False))
        self.assertEqual(out["status"], "NO_FINDINGS_OBSERVED")
        self.assertFalse(out["db_freshness_cryptographically_verified"])
        self.assertFalse(out["production_release_approved"])

    def test_missing_os_coverage_or_package_list_rejected(self):
        data = fixture()
        data["Results"][0]["Packages"] = []
        with self.assertRaisesRegex(ScanDenied, "os_package_extraction_unproven"):
            review(data)
        data = fixture()
        data["Results"] = [data["Results"][1]]
        with self.assertRaisesRegex(ScanDenied, "os_package_extraction_unproven"):
            review(data)

    def test_wrong_image_or_target_rejected(self):
        for name, value in (("ImageID", "sha256:" + "b" * 64),):
            with self.subTest(name=name):
                data = fixture()
                data["Metadata"][name] = value
                with self.assertRaisesRegex(ScanDenied, "image_digest_mismatch"):
                    review(data)
        data = fixture()
        data["ArtifactType"] = "filesystem"
        with self.assertRaisesRegex(ScanDenied, "wrong_target_type"):
            review(data)
        data = fixture()
        data["Metadata"]["OS"]["Family"] = "alpine"
        with self.assertRaisesRegex(ScanDenied, "wrong_os_family"):
            review(data)

    def test_invalid_json_and_severity_rejected(self):
        with self.assertRaises(ScanDenied):
            assess(b'{"SchemaVersion":2,"SchemaVersion":2}', IMAGE)
        with self.assertRaises(ScanDenied):
            assess(b'{}', IMAGE)
        with self.assertRaises(ScanDenied):
            assess(b'', IMAGE)
        data = fixture()
        data["Results"][0]["Vulnerabilities"][0]["Severity"] = "EXPLOITABLE"
        with self.assertRaisesRegex(ScanDenied, "unknown_severity"):
            review(data)

    def test_cli_writes_once_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            src = directory / "scan.json"
            out = directory / "review.json"
            src.write_text(json.dumps(fixture()))
            command = ["python3", str(CLI), "--report", str(src),
                       "--image-id", IMAGE, "--output", str(out)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("H15_TRIVY_REVIEW=REVIEW_REQUIRED", first.stdout)
            self.assertIn("H15_TRIVY_PRODUCTION_GO=NO", first.stdout)
            original = out.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(second.returncode, 2)
            self.assertEqual(out.read_bytes(), original)

    def test_scanner_alias_removed_before_strict_offline_image_export(self):
        workflow = (ROOT / ".github/workflows/h15-remote-commander-candidate.yml").read_text()
        tagged = workflow.index("      - name: Pin real local BRC image for read-only vulnerability scan")
        removed = workflow.index('docker image rm "hermes-brc-relay-scan:${GITHUB_SHA}"')
        export = workflow.index("      - name: Export real vetted relay OCI image as independently pinned offline archive")
        self.assertLess(tagged, removed)
        self.assertLess(removed, export)
        self.assertIn("H15_TRIVY_PRODUCTION_GO=NO", workflow)

    def test_failure_message_never_leaks_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            src = directory / "PRIVATE-MARKER-REPORT"
            src.write_text('{"bad":"private-secret-marker"}')
            out = directory / "out"
            command = ["python3", str(CLI), "--report", str(src),
                       "--image-id", IMAGE, "--output", str(out)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn("PRIVATE-MARKER", run.stdout + run.stderr)
            self.assertNotIn("private-secret", run.stdout + run.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
