"""No-risk vendor Python fingerprinting: no provenance or GO claims."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import verify_v0221_vendor_fingerprints as vendor
from scripts.verify_v0221_local_image import IMAGE

META = json.dumps([IMAGE]).encode() + b"|amd64"


def record():
    files = []
    for name, count in vendor.VENDOR_COUNTS.items():
        for i in range(count):
            files.append({
                "path": f"{name}/module_{i}.py",
                "size": i,
                "sha256": "a" * 64,
            })
    return {
        "schema": "hermes-v0221-vendor-python-fingerprints-v1",
        "embedded_commit": vendor.SOURCE_SHA,
        "embedded_version": "0.22.1",
        "files": files,
    }


def payload(doc=None):
    return json.dumps(doc or record()).encode()


class VendorFileContracts(unittest.TestCase):
    def test_dry_run_never_touches_docker(self):
        with patch.object(vendor, "collect") as collect:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(vendor.main([]), 0)
        collect.assert_not_called()
        self.assertIn("NOT_EXECUTED", out.getvalue())

    def test_execute_without_output_refuses_before_docker(self):
        with patch.object(vendor, "collect") as collect:
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(vendor.main(["--execute"]), 2)
        collect.assert_not_called()

    def test_whole_vendor_set_has_unique_reproducible_sha256(self):
        item, result = vendor.validate(payload())
        repeat, again = vendor.validate(payload())
        self.assertEqual(item, repeat)
        self.assertEqual(result["artifact_sha256"], again["artifact_sha256"])
        self.assertEqual(result["python_file_count"], 1176)
        self.assertEqual(len(item["files"]), 1176)
        self.assertFalse(result["supplier_source_verified"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["complete_sbom_verified"])

    def test_wrong_stamp_count_duplicate_path_and_traversal_denied(self):
        cases = []
        for key, value in (("embedded_commit", "0" * 40),
                           ("embedded_version", "9.99")):
            doc = record()
            doc[key] = value
            cases.append(doc)
        doc = record()
        doc["files"].pop()
        cases.append(doc)
        doc = record()
        doc["files"][1] = dict(doc["files"][0])
        cases.append(doc)
        doc = record()
        doc["files"][0]["path"] = "../escape.py"
        cases.append(doc)
        doc = record()
        doc["files"][0]["sha256"] = "wrong"
        cases.append(doc)
        doc = record()
        doc["files"][0]["size"] = True
        cases.append(doc)
        doc = record()
        doc["files"][0]["size"] = 5_000_001
        cases.append(doc)
        for case in cases:
            with self.subTest(case=str(case["files"][0])[:40]):
                with self.assertRaises(vendor.FingerprintDenied):
                    vendor.validate(payload(case))

    def test_exact_two_restricted_commands(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return Mock(returncode=0, stdout=META if len(calls) == 1 else payload(),
                        stderr=b"never echo private credentials")
        artifact, result = vendor.collect(runner)
        self.assertEqual(calls, list(vendor.commands()))
        run = calls[1]
        for opt in ("--pull=never", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--user", "65534:65534",
                    "--memory", "256m", "--pids-limit", "25"):
            self.assertIn(opt, run)
        self.assertNotIn("--mount", run)
        self.assertNotIn("--volume", run)
        self.assertNotIn("private", str(result))
        self.assertEqual(len(artifact["files"]), vendor.EXPECTED)

    def test_overwrite_is_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "existing.json"
            output.write_text("original", encoding="utf-8")
            with patch.object(vendor, "collect", return_value=vendor.validate(payload())):
                with patch("sys.stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(vendor.main(["--execute", "--output", str(output)]), 2)
            self.assertIn("NO_DATA", out.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()
