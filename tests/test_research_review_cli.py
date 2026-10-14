"""No-network CLI tests; input is always a strict already-fetched citation array."""
from __future__ import annotations

import io
import json
import unittest
from datetime import UTC, datetime

from research_scout.review_cli import MAX_INPUT_BYTES, main, review_payload
from research_scout.citation_review import CitationInputError

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def record():
    return {
        "status": "UNVERIFIED_METADATA",
        "pmid": "36334240",
        "source_url": "https://pubmed.ncbi.nlm.nih.gov/36334240/",
        "citation_title": "Resistance exercise review",
        "citation_doi": "10.1007/s40279-022-01784-y",
        "publication_date_candidate": "2026 Oct 14",
        "source_api": "NCBI_ESUMMARY",
    }


class SafeReviewCLITests(unittest.TestCase):
    def test_explicit_flag_required_before_reading(self):
        source = io.BytesIO(b"Do not read this token")
        output = io.StringIO()
        status = main([], input_stream=source, output_stream=output, now=NOW)
        self.assertEqual(status, 2)
        self.assertEqual(source.tell(), 0)
        self.assertNotIn("token", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "REJECTED")

    def test_bounded_unpublished_digest_on_stdin(self):
        raw = json.dumps([record()]).encode()
        output = io.StringIO()
        status = main(["--review-stdin"], input_stream=io.BytesIO(raw),
                      output_stream=output, now=NOW)
        parsed = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(parsed["status"], "MANUAL_REVIEW")
        self.assertFalse(parsed["scientific_claims_verified"])
        self.assertEqual(parsed["items"][0]["pmid"], "36334240")

    def test_no_data_reports_no_data_not_health(self):
        result = review_payload(b"[]", now=NOW)
        self.assertEqual(result["status"], "NO_DATA")

    def test_invalid_plain_text_no_secret_echo(self):
        output = io.StringIO()
        status = main(["--review-stdin"],
                      input_stream=io.BytesIO(b"Bearer TOPSECRET"),
                      output_stream=output, now=NOW)
        self.assertEqual(status, 2)
        self.assertNotIn("TOPSECRET", output.getvalue())

    def test_duplicate_json_keys_denied_at_nested_depth(self):
        raw = json.dumps([record()]).replace(
            '"pmid": "36334240"',
            '"pmid": "99999999", "pmid": "36334240"', 1
        ).encode()
        with self.assertRaisesRegex(CitationInputError, "duplicate_input_json_key"):
            review_payload(raw, now=NOW)

    def test_nonfinite_json_denied(self):
        with self.assertRaisesRegex(CitationInputError, "invalid_nonfinite_json"):
            review_payload(b'[NaN]', now=NOW)

    def test_too_large_stdin_not_read_beyond_bound(self):
        big = b"A" * (MAX_INPUT_BYTES + 400)
        stream = io.BytesIO(big)
        output = io.StringIO()
        self.assertEqual(main(["--review-stdin"], input_stream=stream,
                              output_stream=output, now=NOW), 2)
        self.assertEqual(stream.tell(), MAX_INPUT_BYTES + 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "input_size_invalid")

    def test_private_or_non_ncbi_record_never_echoed(self):
        untrusted = record()
        untrusted["password"] = "SUPERSECRET"
        result = review_payload(json.dumps([untrusted]).encode(), now=NOW)
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("SUPERSECRET", str(result))

    def test_missing_date_never_filled_with_current_date(self):
        r = record()
        r["publication_date_candidate"] = "2026 Oct"
        result = review_payload(json.dumps([r]).encode(), now=NOW)
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("published_date", result["items"][0])

    def test_network_is_not_required(self):
        # The report consumes bytes, not a PMID that would trigger a fetch.
        output = io.StringIO()
        self.assertEqual(main(["--review-stdin"],
                              input_stream=io.BytesIO(b"[]"),
                              output_stream=output, now=NOW), 0)

    def test_stdin_error_returns_sanitized_rejection(self):
        class BrokenStream:
            def read(self, _: int) -> bytes:
                raise OSError("Bearer PRIVATE")
        output = io.StringIO()
        self.assertEqual(main(["--review-stdin"],
                              input_stream=BrokenStream(),
                              output_stream=output, now=NOW), 2)
        self.assertNotIn("PRIVATE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
