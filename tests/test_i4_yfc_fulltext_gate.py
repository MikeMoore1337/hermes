"""Offline, no-network, no-model regression coverage for I4 fulltext preflight."""
from __future__ import annotations

import json
from unittest import TestCase
from unittest.mock import MagicMock, patch

from research_scout import yfc_fulltext_gate as fulltext


def sample(*, pmcid="12345678", doi="10.1234/sample", license_present=True, body=True):
    rights = "<license><license-p>PRIVATE_SENTINEL</license-p></license>" if license_present else ""
    section = "<body><sec><p>PRIVATE_SENTINEL</p></sec></body>" if body else ""
    return (f"<article><front><article-meta>"
            f'<article-id pub-id-type="pmc">{pmcid}</article-id>'
            f'<article-id pub-id-type="doi">{doi}</article-id>'
            f"<permissions>{rights}</permissions>"
            f"</article-meta></front>{section}</article>").encode()


class FulltextGateTests(TestCase):
    def test_identity_bound_xml_never_returns_article_text(self):
        report = fulltext.inspect("PMC12345678", sample(), expected_doi="10.1234/sample")
        self.assertEqual(report["status"], "NEEDS_CONTENT")
        self.assertEqual(report["source_identity"], "PMC12345678")
        self.assertTrue(report["full_text_available"])
        self.assertTrue(report["license_marker_present"])
        self.assertFalse(report["license_reuse_verified"])
        self.assertFalse(report["primary_claims_verified"])
        self.assertEqual(report["claim_source_matrix"], [])
        self.assertIsNone(report["reviewer_attestation"])
        self.assertIsNone(report["yfc_intake_payload"])
        self.assertFalse(report["hmac_submission_allowed"])
        self.assertFalse(report["automatic_publication"])
        self.assertEqual(report["model_calls"], 0)
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))

    def test_pmc_and_doi_spoofing_fail_closed(self):
        for xml in (sample(pmcid="9999999"), sample(doi="10.1234/other")):
            with self.assertRaises(fulltext.FulltextHold):
                fulltext.inspect("PMC12345678", xml, expected_doi="10.1234/sample")
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_ID_DUPLICATE"):
            fulltext.inspect("PMC12345678", sample().replace(
                b"</article-meta>", b'<article-id pub-id-type="pmc">12345678</article-id></article-meta>'))

    def test_dtd_and_entity_injection_rejected(self):
        attack = b'<!DOCTYPE article [<!ENTITY secret SYSTEM "file:///etc/passwd">]>' + sample()
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DTD_OR_ENTITY_DENIED"):
            fulltext.inspect("PMC12345678", attack)
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DTD_OR_ENTITY_DENIED"):
            fulltext.inspect("PMC12345678", b"<?xml-stylesheet href='https://evil.invalid'?>" + sample())

    def test_missing_body_and_non_jats_are_denied(self):
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_BODY_MISSING"):
            fulltext.inspect("PMC12345678", sample(body=False))
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_JATS_REQUIRED"):
            fulltext.inspect("PMC12345678", b"<metadata/>")

    def test_no_license_marker_still_requires_manual_review(self):
        report = fulltext.inspect("PMC12345678", sample(license_present=False))
        self.assertFalse(report["license_marker_present"])
        self.assertFalse(report["license_reuse_verified"])
        self.assertEqual(report["status"], "NEEDS_CONTENT")

    def test_input_licensing_and_bounds(self):
        for ident in ("PMC0", "12345", "PMC1234/../../etc", "https://evil.invalid"):
            with self.assertRaisesRegex(fulltext.FulltextHold, "PMCID_NOT_ALLOWLISTED"):
                fulltext.inspect(ident, sample())
        with self.assertRaisesRegex(fulltext.FulltextHold, "DOI_INVALID"):
            fulltext.inspect("PMC12345678", sample(), expected_doi="BAD_DOI")
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_SIZE_LIMIT"):
            fulltext.inspect("PMC12345678", b"x" * (fulltext.MAX_XML + 1))
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_XML_INVALID"):
            fulltext.inspect("PMC12345678", b"<article>")

    @patch.object(fulltext, "resolve_public", return_value="203.0.113.1")
    @patch.object(fulltext, "PinnedHTTPS")
    def test_one_fixed_tls_fetch_no_redirect_and_no_credentials(self, constructor, dns):
        connection = MagicMock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.getheader.side_effect = lambda name, default="": {
            "Content-Type": "application/xml", "Content-Encoding": "identity",
            "Content-Length": str(len(sample())),
        }.get(name, default)
        connection.getresponse.return_value.read.return_value = sample()
        constructor.return_value = connection
        self.assertEqual(fulltext.fetch("PMC12345678"), sample())
        constructor.assert_called_once_with("203.0.113.1")
        args, kwargs = connection.request.call_args
        self.assertEqual(args[:2], ("GET",
            "/europepmc/webservices/rest/PMC12345678/fullTextXML"))
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")
        self.assertEqual(kwargs["headers"]["Host"], "www.ebi.ac.uk")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual(connection.request.call_count, 1)
        connection.close.assert_called_once()

    @patch.object(fulltext, "resolve_public", return_value="203.0.113.1")
    @patch.object(fulltext, "PinnedHTTPS")
    def test_redirect_and_oversize_response_never_fallback(self, constructor, dns):
        connection = MagicMock()
        constructor.return_value = connection
        connection.getresponse.return_value.status = 302
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_NOT_AVAILABLE"):
            fulltext.fetch("PMC12345678")
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.getheader.side_effect = lambda name, default="": {
            "Content-Type": "application/xml", "Content-Length": str(fulltext.MAX_XML+1)
        }.get(name, default)
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_SIZE_LIMIT"):
            fulltext.fetch("PMC12345678")
        self.assertEqual(connection.request.call_count, 2)
