"""Crossref DOI metadata matching: no-network negative and injection tests."""
from __future__ import annotations

import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

from research_scout import crossref


def payload(doi="10.1038/s41586-020-2649-2"):
    return json.dumps({
        "status": "ok", "message": {"DOI": doi,
                                   "title": ["Untrusted scientific title"],
                                   "references": [{"secret": "NeverOutput"}]},
    }).encode("utf-8")


class CrossrefTests(unittest.TestCase):
    def test_verified_doi_only_does_not_verify_science(self):
        result = crossref.verify("10.1038/s41586-020-2649-2", transport=lambda _: payload())
        self.assertEqual(result["status"], "DOI_METADATA_MATCH")
        self.assertIs(result["scientific_claims_verified"], False)
        self.assertIs(result["peer_review_verified"], False)
        self.assertIs(result["source_independence_verified"], False)
        self.assertNotIn("NeverOutput", str(result))
        self.assertNotIn("Untrusted scientific title", str(result))

    def test_absent_doi_in_europe_pmc_is_hold_not_network(self):
        with patch.object(crossref,"fetch") as get:
            r=crossref.review_candidate({
                "source":"EUROPE_PMC","status":"MANUAL_REVIEW","doi":None
            },transport=get)
            self.assertEqual(r["status"], "HOLD")
            self.assertEqual(r["reason"], "missing_doi")
            get.assert_not_called()

    def test_single_cross_check_with_fixed_source(self):
        calls=[]
        def transport(doi):
            calls.append(doi)
            return payload()
        r=crossref.review_candidate({
            "source":"EUROPE_PMC","status":"MANUAL_REVIEW",
            "doi":"10.1038/s41586-020-2649-2",
        },transport=transport)
        self.assertEqual(r["status"], "MANUAL_REVIEW")
        self.assertEqual(len(calls),1)
        self.assertFalse(r["automatic_publication"])

    def test_doi_mismatch_and_invalid_json_hold_without_untrusted_text(self):
        for data,reason in (
            (payload("10.1000/wrong"),"crossref_doi_mismatch"),
            (b'{"message":{"DOI":"10.1038/s41586-020-2649-2"},"message":{}}',
             "crossref_duplicate_json_key"),
            (b'{"message":null}',"crossref_schema_invalid"),
            (b'{"message":{"DOI":1}}',"crossref_doi_missing"),
            (b'not-json',"crossref_json_invalid"),
            (b'x'*(crossref.MAX_BYTES+1),"crossref_response_invalid"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(crossref.CrossrefError,reason):
                    crossref.verify("10.1038/s41586-020-2649-2",transport=lambda _:data)

    def test_unknown_doi_prevent_path_injection(self):
        for doi in (
            "", "https://api.crossref.org/works/abc",
            "10.1000/path?redirect=/etc/passwd",
            "10.1000/a#fragment","10.1000/a\nHeader: token",
            "10.1000/a%2fpath","10.1000/secret@private",
            "10.1000/"+"a"*400,None,12,True,
        ):
            with self.subTest(doi=repr(doi)):
                with self.assertRaisesRegex(crossref.CrossrefError,"doi_invalid"):
                    crossref.valid_doi(doi)

    def test_wrong_origin_or_hold_candidate_denied_before_get(self):
        client=Mock()
        for candidate in (
            {"source":"fake","status":"MANUAL_REVIEW","doi":"10.1000/a"},
            {"source":"EUROPE_PMC","status":"HOLD","doi":"10.1000/a"},
            {"source":"EUROPE_PMC","status":"READY_FOR_PUBLICATION","doi":"10.1000/a"},
            {"source":"EUROPE_PMC","status":"MANUAL_REVIEW","doi":"file://private"},
        ):
            with self.subTest(c=repr(candidate)):
                with self.assertRaises(crossref.CrossrefError):
                    crossref.review_candidate(candidate,transport=client)
        client.assert_not_called()

    def test_dns_private_addresses_denied(self):
        records=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",443))]
        with patch.object(crossref.socket,"getaddrinfo",return_value=records):
            with self.assertRaisesRegex(crossref.CrossrefError,"crossref_dns_private_denied"):
                crossref.resolve_public()

    def test_cli_default_offline_and_error_never_echoes_doi(self):
        with patch.object(crossref,"verify") as get:
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(crossref.main(["--doi","10.1000/example"]),0)
            get.assert_not_called()
        self.assertIn("NOT_EXECUTED",out.getvalue())
        with patch.object(crossref,"verify",
                          side_effect=crossref.CrossrefError("crossref_http_unavailable")):
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(crossref.main(["--execute","--doi","10.1000/secret"]),2)
            self.assertNotIn("secret",out.getvalue())

    def test_one_exact_tls_get_only_without_redirect_or_proxy(self):
        conn=Mock()
        response=Mock()
        response.status=200
        response.getheader.side_effect=lambda key, default="": (
            "application/json" if key=="Content-Type" else
            "identity" if key=="Content-Encoding" else
            "128" if key=="Content-Length" else default
        )
        response.read.return_value=payload()
        conn.getresponse.return_value=response
        with patch.object(crossref,"resolve_public",return_value="1.1.1.1"):
            with patch.object(crossref,"PinnedTLS",return_value=conn):
                raw=crossref.fetch("10.1038/s41586-020-2649-2")
        self.assertEqual(raw,payload())
        request=conn.request.call_args
        self.assertEqual(request.args[:2],(
            "GET", "/works/10.1038%2Fs41586-020-2649-2"))
        self.assertEqual(conn.request.call_count,1)
        self.assertEqual(request.kwargs["headers"]["Host"],"api.crossref.org")
        conn.close.assert_called_once()


if __name__=="__main__":
    unittest.main()
