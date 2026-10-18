"""H-03 reverse-update retrieval: deterministic offline positive/negative cases."""
from __future__ import annotations

import io
import json
import socket
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote

from research_scout import crossref_updates as updates

ORIGINAL = "10.1007/s00520-026-11251-3"
CORRECTION = "10.1007/s00520-026-11294-6"


def data(items=(), total=None):
    return json.dumps({
        "status": "ok",
        "message": {"total-results": len(items) if total is None else total,
                    "items": list(items)},
    }).encode("utf-8")


def notice(doi=CORRECTION, target=ORIGINAL, kind="correction",
           when=None):
    return {
        "DOI": doi,
        "update-to": [{
            "DOI": target, "type": kind,
            "updated": when if when is not None else
                       {"date-parts": [[2026, 10, 2]]},
        }],
    }


class CrossrefReverseUpdateTests(unittest.TestCase):
    def test_ironman_correction_has_traceable_original_and_new_doi(self):
        result = updates.inspect(ORIGINAL, transport=lambda _: data([notice()]))
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["source"], "CROSSREF")
        self.assertEqual(result["notice_codes"], ["CORRECTION_NOTICE"])
        self.assertEqual(result["notices"], [{
            "doi": CORRECTION, "notice_type": "CORRECTION_NOTICE",
            "published": "2026-10-02", "source": "CROSSREF_REVERSE_UPDATE_METADATA",
        }])
        self.assertFalse(result["authoritative_notice_clearance"])
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["automatic_publication"])

    def test_absent_updates_means_only_checked_registry_coverage(self):
        r = updates.inspect(ORIGINAL, transport=lambda _: data())
        self.assertEqual(r["status"], "NOT_FOUND_WITH_COVERAGE")
        self.assertEqual(r["coverage"], "CROSSREF_REVERSE_UPDATES_ONLY")
        self.assertEqual(r["notices"], [])
        self.assertFalse(r["authoritative_notice_clearance"])
        self.assertTrue(r["manual_review_required"])

    def test_update_types_are_distinguished_without_claiming_effect(self):
        cases = {
            "retraction": "RETRACTION_OR_WITHDRAWAL_NOTICE",
            "withdrawal": "RETRACTION_OR_WITHDRAWAL_NOTICE",
            "partial-retraction": "RETRACTION_OR_WITHDRAWAL_NOTICE",
            "expression-of-concern": "EXPRESSION_OF_CONCERN",
            "erratum": "CORRECTION_NOTICE",
            "other-unknown": "OTHER_OR_UNKNOWN_NOTICE",
        }
        for kind, expected in cases.items():
            with self.subTest(kind=kind):
                r = updates.inspect(ORIGINAL, transport=lambda _: data([notice(kind=kind)]))
                self.assertEqual(r["notice_codes"], [expected])
                self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_multiple_related_notices_and_truncation_no_clean_status(self):
        a = notice()
        b = notice(doi="10.1000/second", kind="retraction")
        r = updates.inspect(ORIGINAL, transport=lambda _: data([a, b], total=6))
        self.assertEqual(len(r["notices"]), 2)
        self.assertEqual(r["coverage"], "CROSSREF_FILTER_TRUNCATED")
        self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_original_doi_case_is_normalized_only_for_matching(self):
        mixed = notice(target=ORIGINAL.upper())
        self.assertEqual(updates.inspect(ORIGINAL, transport=lambda _: data([mixed]))["status"],
                         "REVIEW_REQUIRED")

    def test_missing_invalid_contradictory_results_are_rejected(self):
        cases = [
            (data([notice(target="10.1000/unrelated")]), "update_relation_mismatch"),
            (data([notice(doi=ORIGINAL)]), "update_relation_mismatch"),
            (data([{"DOI": CORRECTION}]), "update_links_invalid"),
            (data([notice(when={"date-parts": [[2026, 2, 30]]})]), "update_date_invalid"),
            (data([notice(when={"date-parts": [[2026, 10, True]]})]), "update_date_invalid"),
            (data([notice(kind=None)]), "update_type_invalid"),
            (data([notice(target="file:///etc/shadow")]), "update_doi_invalid"),
            (data([notice(), notice()]), "update_duplicate_notice"),
            (data([notice()], total=0), "update_schema_invalid"),
            (data([], total=9), "update_incomplete_result"),
            (data([notice()] * 6), "update_schema_invalid"),
            (b'{"status":"ok","message":{"items":[],"items":[],"total-results":0}}',
             "update_duplicate_json_key"),
            (b'{"status":"ok","message":{"items":[],"total-results":NaN}}',
             "update_json_invalid"),
            (b'{"status":"ok","message":null}', "update_schema_invalid"),
            (b'{', "update_json_invalid"),
            (b'x' * (updates.MAX_BYTES + 1), "update_response_invalid"),
        ]
        for raw, code in cases:
            with self.subTest(code=code, raw=raw[:35]):
                with self.assertRaisesRegex(updates.UpdateLookupError, code):
                    updates.parse(raw, doi=ORIGINAL)

    def test_input_rejected_without_any_network(self):
        for value in ("", "file:///etc/passwd", "10.1000/a?rows=999",
                      "10.1000/a%2fb", "10.1000/a#frag",
                      "10.1000/foo\nbar", 1, None, True):
            with self.subTest(value=repr(value)):
                get = Mock()
                with self.assertRaisesRegex(updates.UpdateLookupError, "update_doi_invalid"):
                    updates.inspect(value, transport=get)
                get.assert_not_called()

    def test_fixed_endpoint_and_no_arbitrary_location(self):
        path = updates.query_path(ORIGINAL)
        self.assertEqual(path,
                         "/works?filter=updates:10.1007%2Fs00520-026-11251-3"
                         "&rows=5&select=DOI,update-to")
        self.assertIn(ORIGINAL, unquote(path))
        self.assertEqual(path.count("&"), 2)

    def test_explicit_execute_gate_keeps_default_offline(self):
        out = io.StringIO()
        with patch.object(updates, "fetch") as network, patch("sys.stdout", out):
            self.assertEqual(updates.main(["--doi", ORIGINAL]), 0)
            network.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["requests_attempted"], 0)

    def test_unavailable_request_is_unknown_not_clearance(self):
        with patch.object(updates, "inspect",
                          side_effect=updates.UpdateLookupError("update_http_unavailable")):
            out = io.StringIO()
            with patch("sys.stdout", out):
                self.assertEqual(updates.main(["--execute", "--doi", ORIGINAL]), 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["publisher_clearance"])

    def test_response_429_timeout_malformed_and_oversize_fail_closed(self):
        class Response:
            def __init__(self, status=200, content_type="application/json",
                         raw=b"{}", size=None):
                self.status, self.content_type = status, content_type
                self.raw, self.size = raw, size
            def getheader(self, key, default=None):
                return {"Content-Type": self.content_type,
                        "Content-Length": self.size}.get(key, default)
            def read(self, count):
                return self.raw[:count]
        for response, code in [
            (Response(status=429), "update_http_429"),
            (Response(status=302), "update_http_unavailable"),
            (Response(content_type="text/html"), "update_content_type_invalid"),
            (Response(size="999999"), "update_body_oversize"),
            (Response(raw=b"x" * (updates.MAX_BYTES+1)), "update_body_oversize"),
        ]:
            conn = Mock()
            conn.getresponse.return_value = response
            with self.subTest(code=code), patch.object(updates, "resolve_public",
                            return_value="203.0.113.1"), patch.object(
                            updates, "PinnedTLS", return_value=conn):
                with self.assertRaisesRegex(updates.UpdateLookupError, code):
                    updates.fetch(ORIGINAL)
            self.assertEqual(conn.request.call_count, 1)
            self.assertEqual(conn.request.call_args.args[0], "GET")
            self.assertEqual(conn.request.call_args.args[1], updates.query_path(ORIGINAL))
            self.assertEqual(conn.close.call_count, 1)

        conn = Mock()
        conn.request.side_effect = TimeoutError()
        with patch.object(updates, "resolve_public", return_value="203.0.113.1"), \
             patch.object(updates, "PinnedTLS", return_value=conn):
            with self.assertRaisesRegex(updates.UpdateLookupError,
                                        "update_network_or_tls_unavailable"):
                updates.fetch(ORIGINAL)
        conn.close.assert_called_once()

    def test_dns_denied_without_connecting(self):
        with patch.object(updates, "resolve_public",
                          side_effect=updates.CrossrefError("crossref_dns_private_denied")):
            with patch.object(updates, "PinnedTLS") as connect:
                with self.assertRaisesRegex(updates.UpdateLookupError, "update_dns_unavailable"):
                    updates.fetch(ORIGINAL)
                connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
