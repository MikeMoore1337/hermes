"""H-15: reconcile real-style image findings, no automatic CVE waiver or release."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_brc_cve_triage import TriageError, reconcile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/h15_brc_cve_triage.py"
LEDGER = ROOT / "docs/security/h15-brc-cve-dispositions.json"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
IMAGE = "sha256:" + "a" * 64


def fixture():
    ledger = json.loads(LEDGER.read_text())
    os_rows = [{"Name": f"installed-os-{i}", "Version": "1"} for i in range(88)]
    lang_rows = [{"Name": "braces", "Version": "3.0.3"}]
    os_vulns, lang_vulns = [], []
    for item in ledger["cves"]:
        for package in item["baseline_packages"]:
            record = {
                "VulnerabilityID": item["id"],
                "PkgName": package,
                "InstalledVersion": "1",
                "Severity": "CRITICAL" if item["id"] == "CVE-2023-45853" else "HIGH",
            }
            (lang_vulns if item["source_package"] == "braces" else os_vulns).append(record)
    report = {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE, "OS": {"Family": "debian", "Name": "12.15"}},
        "Results": [
            {"Class": "os-pkgs", "Type": "debian", "Packages": os_rows,
             "Vulnerabilities": os_vulns},
            {"Class": "lang-pkgs", "Type": "node-pkg", "Packages": lang_rows,
             "Vulnerabilities": lang_vulns},
        ],
    }
    return report, ledger


def run(report, ledger, image=IMAGE):
    return reconcile(json.dumps(report).encode("utf-8"), image, ledger)


class H15CveTriageTests(unittest.TestCase):
    def test_all_thirteen_ids_reconciled_without_any_auto_approval(self):
        report, ledger = fixture()
        result = run(report, ledger)
        self.assertEqual(result["total_high_critical_records"], 58)
        self.assertEqual(result["distinct_cve_count"], 13)
        self.assertEqual(result["review_status"], "KNOWN_IDS_RECONCILED")
        self.assertEqual(result["unknown_cve_count"], 0)
        self.assertEqual(result["changed_package_scope_count"], 0)
        self.assertEqual(result["source_exception_pending_signoff"], 1)
        self.assertFalse(result["production_release_approved"])
        self.assertFalse(result["public_mcp_enable_allowed"])
        self.assertFalse(result["owner_device_commands_allowed"])
        self.assertFalse(result["owner_signoff_received"])
        self.assertTrue(all(row["owner_signoff"] is False for row in result["cves"]))
        self.assertEqual(result, run(report, ledger))

    def test_unexpected_new_cve_must_be_visible_and_release_remains_blocked(self):
        report, ledger = fixture()
        report["Results"][0]["Vulnerabilities"].append({
            "VulnerabilityID": "CVE-2099-90000",
            "PkgName": "libmount1", "Severity": "HIGH",
        })
        reviewed = run(report, ledger)
        self.assertEqual(reviewed["review_status"], "INCOMPLETE")
        self.assertEqual(reviewed["unknown_cve_count"], 1)
        self.assertEqual(reviewed["total_high_critical_records"], 59)
        self.assertIn("CVE-2099-90000", [row["id"] for row in reviewed["cves"]])
        self.assertFalse(reviewed["production_release_approved"])

    def test_known_cve_new_package_cannot_inherit_prior_disposition(self):
        report, ledger = fixture()
        report["Results"][0]["Vulnerabilities"].append({
            "VulnerabilityID": "CVE-2026-53613",
            "PkgName": "different-scope", "Severity": "HIGH",
        })
        checked = run(report, ledger)
        self.assertEqual(checked["changed_package_scope_count"], 1)
        self.assertEqual(checked["review_status"], "INCOMPLETE")
        self.assertIn("PACKAGE_SCOPE_CHANGED_REVIEW_REQUIRED",
                      [r["disposition"] for r in checked["cves"]])

    def test_approval_tampering_and_unjustified_exception_rejected(self):
        report, ledger = fixture()
        for bogus in ("APPROVED", "YES", True):
            with self.subTest(owner_approval=bogus):
                candidate = copy.deepcopy(ledger)
                candidate["owner_approval"] = bogus
                with self.assertRaisesRegex(TriageError, "implicit_release_approval_refused"):
                    run(report, candidate)
        candidate = copy.deepcopy(ledger)
        entry = next(e for e in candidate["cves"] if e["id"] == "CVE-2026-93687")
        entry["disposition"] = "DEBIAN_SOURCE_EXCEPTION_REQUIRES_OWNER_REVIEW"
        with self.assertRaisesRegex(TriageError, "unsupported_source_exception"):
            run(report, candidate)
        candidate = copy.deepcopy(ledger)
        candidate["cves"][0]["reference"] = "https://attacker.invalid/security"
        with self.assertRaisesRegex(TriageError, "untrusted_reference"):
            run(report, candidate)

    def test_changed_base_image_report_fails_closed(self):
        report, ledger = fixture()
        with self.assertRaises(ValueError):
            run(report, ledger, image="sha256:" + "b" * 64)
        with self.assertRaisesRegex(TriageError, "baseline_image_report_mismatch"):
            run(report, ledger, image=ledger["evidence"]["image_id"])

    def test_missing_cve_and_fully_remediated_image_still_not_approved(self):
        report, ledger = fixture()
        report["Results"][0]["Vulnerabilities"] = []
        report["Results"][1]["Vulnerabilities"] = []
        reviewed = run(report, ledger)
        self.assertEqual(reviewed["distinct_cve_count"], 0)
        self.assertEqual(reviewed["absent_baseline_cve_count"], 13)
        self.assertFalse(reviewed["production_release_approved"])

    def test_cli_no_overwrite_and_no_secret_package_names_in_stdout(self):
        report, ledger = fixture()
        with tempfile.TemporaryDirectory() as workdir:
            root = Path(workdir)
            report_path = root / "sensitive-image-report.json"
            ledger_path = root / "ledger.json"
            output_path = root / "triage.json"
            report_path.write_text(json.dumps(report))
            ledger_path.write_text(json.dumps(ledger))
            cmd = [
                "python3", str(SCRIPT), "--report", str(report_path),
                "--ledger", str(ledger_path), "--image-id", IMAGE,
                "--output", str(output_path),
            ]
            first = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("H15_CVE_HIGH_CRITICAL=58", first.stdout)
            self.assertIn("H15_CVE_PRODUCTION_GO=NO", first.stdout)
            self.assertNotIn("sensitive-image-report", first.stdout + first.stderr)
            existing = output_path.read_bytes()
            second = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(second.returncode, 2)
            self.assertEqual(output_path.read_bytes(), existing)

    def test_ci_retains_triage_in_cve_evidence_and_keeps_no_go(self):
        workflow = WORKFLOW.read_text()
        start = workflow.index("      - name: Validate image-bound vulnerability evidence")
        end = workflow.index("      - name: Retain isolated image provenance", start)
        scope = workflow[start:end]
        self.assertIn("scripts/h15_brc_cve_triage.py", scope)
        self.assertIn("docs/security/h15-brc-cve-dispositions.json", scope)
        self.assertIn("trivy-triage.json", scope)
        self.assertIn("H15_CVE_PRODUCTION_GO=NO", scope)
        self.assertIn("trivy-triage.json", WORKFLOW.read_text())
        self.assertNotIn("release_approved=true", scope)


if __name__ == "__main__":
    unittest.main()
