"""Mock-only tests; never contact NCBI, GitHub or an AI provider."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from research_scout.ncbi_esearch import (
    NCBIError, TOPICS, _fetch, find_candidates, parse_candidates,
)

EMAIL = "maintainer@example.org"


def body(ids=None, *, count=None, retmax="5", retstart="0"):
    ids = ["36334240", "37120382"] if ids is None else ids
    return json.dumps({"esearchresult": {
        "count": str(len(ids)) if count is None else count,
        "retmax": retmax, "retstart": retstart, "idlist": ids,
    }}).encode()


class SearchContractTests(unittest.TestCase):
    def test_only_candidate_ids_no_claims(self):
        value = parse_candidates(body(), "resistance-training")
        self.assertEqual(value["status"], "UNVERIFIED_PMID_CANDIDATES")
        self.assertEqual(value["pmids"], ["36334240", "37120382"])
        self.assertNotIn("title", value)
        self.assertEqual(value["window"], "30_days_entrez_entry")

    def test_no_data_not_forged_as_success(self):
        self.assertEqual(parse_candidates(body([]), "exercise-recovery")["status"], "NO_DATA")

    def test_topic_and_contact_required_before_fetch(self):
        for topic in ("", "*", "db=gene", "resistance-training&email=bad", None):
            with self.subTest(topic=topic), self.assertRaises(NCBIError):
                find_candidates(topic, contact=EMAIL,
                                fetch=lambda *_: self.fail("must not fetch"))
        with self.assertRaisesRegex(NCBIError, "ncbi_contact_missing"):
            find_candidates("resistance-training", contact="",
                            fetch=lambda *_: self.fail("must not fetch"))

    def test_maximum_and_duplicate_pmid(self):
        for p in (body(["1234567"] * 2),
                  body([str(1234567+i) for i in range(6)])):
            with self.assertRaises(NCBIError):
                parse_candidates(p, "muscle-hypertrophy")

    def test_unsafe_ids_rejected(self):
        for item in ("127.0.0.1", "1234567/../../", "https://localhost", 36334240, None):
            with self.subTest(item=item), self.assertRaises(NCBIError):
                parse_candidates(body([item]), "exercise-recovery")

    def test_malformed_counts_and_result_shape(self):
        for kwargs in ({"count": "NaN"}, {"count": 0}, {"count": "999999999999"},
                       {"count": "0"}, {"retmax": "500"}, {"retstart": "1"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(NCBIError):
                parse_candidates(body(["36334240"], **kwargs), "resistance-training")

    def test_duplicate_json_keys_rejected(self):
        bad = body().decode().replace('"count": "2"', '"count":"1","count":"2"')
        with self.assertRaisesRegex(NCBIError, "ncbi_duplicate_json_key"):
            parse_candidates(bad.encode(), "resistance-training")

    def test_http200_errors_and_warnings_not_success(self):
        for field in ("error", "errors", "warninglist", "errorlist"):
            payload = json.loads(body())
            payload["esearchresult"][field] = "Bearer FAKE_PRIVATE_VALUE"
            with self.subTest(field=field), self.assertRaisesRegex(
                NCBIError, "ncbi_esearch_api_error"
            ) as failure:
                parse_candidates(json.dumps(payload).encode(), "exercise-recovery")
            self.assertNotIn("FAKE_PRIVATE_VALUE", str(failure.exception))

    def test_invalid_or_oversized_json_rejected(self):
        for p in (b"[]", b"{}", b"\xff", b"no", b"A" * 131073):
            with self.subTest(length=len(p)), self.assertRaises(NCBIError):
                parse_candidates(p, "exercise-recovery")


class SearchTransportTests(unittest.TestCase):
    def connection(self, status=200, media="application/json"):
        client = Mock()
        response = Mock(status=status)
        response.getheader.side_effect = lambda key, default=None: {
            "Content-Type": media
        }.get(key, default)
        response.read.return_value = body()
        client.getresponse.return_value = response
        return client

    @patch("research_scout.ncbi_esearch._resolve", return_value="8.8.8.8")
    @patch("research_scout.ncbi_esearch._PinnedNCBI")
    def test_exact_single_public_get_without_key(self, constructor, dns):
        client = self.connection()
        constructor.return_value = client
        self.assertEqual(_fetch("exercise-recovery", EMAIL), body())
        args, kwargs = client.request.call_args
        self.assertEqual(args[0], "GET")
        path = urlsplit(args[1])
        self.assertEqual(path.path, "/entrez/eutils/esearch.fcgi")
        query = parse_qs(path.query)
        self.assertEqual(query["db"], ["pubmed"])
        self.assertEqual(query["term"], [TOPICS["exercise-recovery"]])
        self.assertEqual(query["email"], [EMAIL])
        self.assertEqual(query["tool"], ["HermesResearchScout"])
        self.assertEqual(query["retmax"], ["5"])
        self.assertEqual(query["reldate"], ["30"])
        self.assertEqual(query["datetype"], ["edat"])
        self.assertNotIn("api_key", query)
        self.assertEqual(client.request.call_count, 1)
        client.close.assert_called_once_with()

    @patch("research_scout.ncbi_esearch._resolve", return_value="8.8.8.8")
    @patch("research_scout.ncbi_esearch._PinnedNCBI")
    def test_redirect_and_html_blocked(self, constructor, dns):
        for status, media in ((302, "application/json"), (200, "text/html")):
            client = self.connection(status=status, media=media)
            constructor.return_value = client
            with self.assertRaises(NCBIError):
                _fetch("muscle-hypertrophy", EMAIL)
            self.assertEqual(client.request.call_count, 1)
            client.close.assert_called_once_with()

    @patch("research_scout.ncbi_esearch._resolve", side_effect=NCBIError("ncbi_private_dns_denied"))
    @patch("research_scout.ncbi_esearch._PinnedNCBI")
    def test_private_dns_blocks_before_connection(self, constructor, dns):
        with self.assertRaises(NCBIError):
            _fetch("resistance-training", EMAIL)
        constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
