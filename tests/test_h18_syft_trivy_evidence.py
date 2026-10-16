"""H-18: offline scanner evidence is untrusted and cannot grant deployment GO."""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import review_syft_trivy_evidence as review


def payload(severity=None):
    syft = {
        "descriptor": {"name": "syft", "version": "1.42.0"},
        "source": {"type": "image", "target": {
            "userInput": review.IMAGE,
            "manifestDigest": review.IMAGE.partition("@")[2]}},
        "artifacts": [
            {"name": "hermes-agent", "version": "0.22.2"},
            {"name": "python", "version": "3.14.7"},
        ],
    }
    trivy = {
        "SchemaVersion": 2,
        "ArtifactName": review.IMAGE,
        "ArtifactType": "container_image",
        "Results": [{"Target": "base", "Vulnerabilities": (
            [{"VulnerabilityID": "CVE-EXAMPLE-123", "Severity": severity}]
            if severity else []
        )}],
    }
    s = json.dumps(syft, sort_keys=True).encode()
    t = json.dumps(trivy, sort_keys=True).encode()
    manifest = {
        "schema": review.SCHEMA, "image": review.IMAGE,
        "platform": "linux/amd64", "syft_version": "1.42.0",
        "trivy_version": "0.69.0",
        "syft_sha256": hashlib.sha256(s).hexdigest(),
        "trivy_sha256": hashlib.sha256(t).hexdigest(),
        "trivy_db_sha256": "a" * 64,
        "trivy_db_updated_at": "2026-10-15T12:00:00Z",
        "scanner_run_at": "2026-10-16T12:00:00Z",
    }
    return manifest, syft, trivy


def encode(info, syft, trivy):
    return (json.dumps(info).encode(), json.dumps(syft, sort_keys=True).encode(),
            json.dumps(trivy, sort_keys=True).encode())


class ScannerEvidenceTest(unittest.TestCase):
    def test_clean_report_cannot_grant_go(self):
        result = review.assess(*encode(*payload()))
        self.assertEqual(result["status"], "UNATTESTED_REVIEW_REQUIRED")
        self.assertEqual(result["syft_artifact_count"], 2)
        self.assertEqual(result["trivy_vulnerability_count"], 0)
        self.assertTrue(result["scanner_reports_hash_checked"])
        self.assertFalse(result["source_to_image_provenance_verified"])
        self.assertFalse(result["complete_sbom_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_severity_counts_are_not_hidden(self):
        for severity, expected in (("CRITICAL", 1), ("HIGH", 1),
                                   ("MEDIUM", 0), ("LOW", 0)):
            with self.subTest(severity=severity):
                info, syft, trivy = payload(severity)
                outcome = review.assess(*encode(info, syft, trivy))
                self.assertEqual(outcome["trivy_high_critical_count"], expected)
                self.assertEqual(outcome["trivy_vulnerability_count"], 1)
                self.assertEqual(outcome["status"], (
                    "HIGH_CVE_REVIEW" if expected else "UNATTESTED_REVIEW_REQUIRED"))

    def test_digest_platform_and_manifest_tampering_denied(self):
        cases = [
            ("unexpected_image_identity",
             lambda m, s, t: m.update(image="tag:latest")),
            ("unexpected_image_identity",
             lambda m, s, t: m.update(platform="linux/arm64")),
            ("syft_subject_mismatch",
             lambda m, s, t: s["source"]["target"].update(userInput="wrong")),
            ("syft_manifest_digest_missing_or_mismatch",
             lambda m, s, t: s["source"]["target"].update(manifestDigest="sha256:"+"0"*64)),
            ("invalid_trivy_subject",
             lambda m, s, t: t.update(ArtifactName="different")),
            ("syft_version_mismatch",
             lambda m, s, t: s["descriptor"].update(version="0.0.1")),
            ("db_time_outside_declared_scan_window",
             lambda m, s, t: m.update(scanner_run_at="2026-10-30T12:00:00Z")),
        ]
        for error, edit in cases:
            with self.subTest(error=error):
                m, s, t = payload()
                edit(m, s, t)
                s_bytes = json.dumps(s, sort_keys=True).encode()
                t_bytes = json.dumps(t, sort_keys=True).encode()
                m["syft_sha256"] = hashlib.sha256(s_bytes).hexdigest()
                m["trivy_sha256"] = hashlib.sha256(t_bytes).hexdigest()
                with self.assertRaisesRegex(review.ScanEvidenceDenied, error):
                    review.assess(*encode(m, s, t))

    def test_hash_mismatch_and_duplicate_json_key_fail(self):
        m, s, t = payload()
        with self.assertRaisesRegex(review.ScanEvidenceDenied, "trivy_sha256_mismatch"):
            review.assess(json.dumps(m).encode(), json.dumps(s, sort_keys=True).encode(),
                          b'{"tampered":true}')
        with self.assertRaises(review.ScanEvidenceDenied):
            review.assess(b'{"schema":"one","schema":"two"}',
                          json.dumps(s).encode(), json.dumps(t).encode())

    def test_missing_results_or_bad_severity_denied(self):
        for change in ("no_results", "unknown_severity", "bad_artifact"):
            with self.subTest(change=change):
                m, s, t = payload("CRITICAL")
                if change == "no_results":
                    t["Results"] = []
                elif change == "unknown_severity":
                    t["Results"][0]["Vulnerabilities"][0]["Severity"] = "BOGUS"
                else:
                    s["artifacts"] = [{"name": "", "version": "0"}]
                sb = json.dumps(s, sort_keys=True).encode()
                tb = json.dumps(t, sort_keys=True).encode()
                m["syft_sha256"] = hashlib.sha256(sb).hexdigest()
                m["trivy_sha256"] = hashlib.sha256(tb).hexdigest()
                with self.assertRaises(review.ScanEvidenceDenied):
                    review.assess(json.dumps(m).encode(), sb, tb)

    def test_default_noop_and_explicit_inputs(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(review.main([]), 0)
            self.assertIn("NOT_EXECUTED", output.getvalue())
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(review.main(["--execute"]), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "INCONCLUSIVE")

    def test_file_review_never_echoes_secrets_or_returns_zero(self):
        info, syft, trivy = payload()
        with tempfile.TemporaryDirectory() as td:
            paths = [Path(td) / name for name in ("manifest.json", "syft.json", "trivy.json")]
            for path, data in zip(paths, encode(info, syft, trivy)):
                path.write_bytes(data)
            args = ["--execute", "--manifest", str(paths[0]),
                    "--syft-json", str(paths[1]), "--trivy-json", str(paths[2])]
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(review.main(args), 2)
                report = json.loads(output.getvalue())
                self.assertEqual(report["status"], "UNATTESTED_REVIEW_REQUIRED")
                self.assertFalse(report["resident_agent_allowed"])
            paths[2].write_text("ACCESS_TOKEN=VERY_PRIVATE", encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(review.main(args), 2)
                self.assertNotIn("VERY_PRIVATE", output.getvalue())
                self.assertIn("INCONCLUSIVE", output.getvalue())

    def test_symlink_and_large_input_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "actual.json"
            original.write_text('{"ok":true}', encoding="utf-8")
            link = root / "alias.json"
            try:
                link.symlink_to(original)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaises(review.ScanEvidenceDenied):
                    review._read(link)
            with self.assertRaises(review.ScanEvidenceDenied):
                review._read(original, max_bytes=4)


if __name__ == "__main__":
    unittest.main()
