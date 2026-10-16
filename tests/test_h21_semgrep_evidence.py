"""H-21: synthetic malicious scanner reports cannot claim complete coverage."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts import review_h21_semgrep_evidence as review


def packet(**changes):
    data = {
        "version": review.VERSION,
        "results": [],
        "errors": [],
        "skipped_rules": [],
        "paths": {"scanned": ["/code/scripts/one.py", "/code/qa_advisor/two.py"],
                  "skipped": []},
    }
    data.update(changes)
    return json.dumps(data).encode()


class SemgrepEvidenceTests(unittest.TestCase):
    def test_zero_findings_are_only_a_scope_record(self):
        result = review.review(packet())
        self.assertEqual(result["status"], "BOUNDED_SCAN_SCOPE_RECORDED_NO_GO")
        self.assertEqual(result["scanned_files"], 2)
        self.assertEqual(result["finding_count"], 0)
        self.assertFalse(result["coverage_and_false_negatives_verified"])
        self.assertFalse(result["incremental_value_over_codeql_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_skips_errors_wrong_scope_or_version_are_denied(self):
        invalid = [
            {"version": "1.0.0"},
            {"errors": [{"message": "TOKEN_PRIVATE_VALUE"}]},
            {"skipped_rules": ["danger"]},
            {"paths": {"scanned": ["/code/scripts/one.py",
                                   "/code/qa_advisor/two.py"], "skipped": ["one.py"]}},
            {"paths": {"scanned": ["/code/scripts/one.py"], "skipped": []}},
            {"paths": {"scanned": ["/code/scripts/one.py",
                                   "/code/qa_advisor/../vault.py"], "skipped": []}},
            {"results": ["untrusted"]},
        ]
        for mutation in invalid:
            with self.subTest(mutation=list(mutation)):
                with self.assertRaises(review.EvidenceDenied):
                    review.review(packet(**mutation))

    def test_duplicates_and_untrusted_raw_bytes_are_denied(self):
        for data in (b'{"version":"1","version":"2"}',
                     b"SECRET" * (review.MAX_BYTES // 6 + 1), b"not-json"):
            with self.assertRaises(review.EvidenceDenied):
                review.review(data)

    def test_cli_no_scanner_execution_and_no_secret_echo(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(review.main([]), 0)
        self.assertIn("NOT_EXECUTED", output.getvalue())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PRIVATE_REPORT.json"
            path.write_bytes(packet(errors=[{"message": "TOKEN_PRIVATE_VALUE"}]))
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(review.main(["--execute", "--report", str(path)]), 2)
            self.assertEqual(json.loads(out.getvalue())["status"], "INCONCLUSIVE")
            self.assertNotIn("PRIVATE_VALUE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
