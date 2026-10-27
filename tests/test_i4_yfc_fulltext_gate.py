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

    def test_standard_pmcid_alias_is_strictly_verified(self):
        # PMC's JATS guidelines specify pub-id-type="pmcid", while
        # historical documents also use "pmc".
        xml = sample().replace(b'pub-id-type="pmc"', b'pub-id-type="pmcid"')
        for ident in (b"12345678", b"PMC12345678"):
            with self.subTest(ident=ident):
                aliased = xml.replace(b">12345678</article-id>", b">" + ident + b"</article-id>")
                report = fulltext.inspect("PMC12345678", aliased,
                                          expected_doi="10.1234/sample")
                self.assertEqual(report["source_identity"], "PMC12345678")
                self.assertFalse(report["hmac_submission_allowed"])
                self.assertFalse(report["automatic_publication"])

        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_PMCI_MISMATCH"):
            fulltext.inspect("PMC12345678", sample().replace(
                b'pub-id-type="pmc"', b'pub-id-type="pmid"'),
                expected_doi="10.1234/sample")

        for wrong in (b"99999999", b"PMC99999999", b"PMC12345678X"):
            with self.subTest(wrong=wrong):
                modified = xml.replace(b">12345678</article-id>",
                                       b">" + wrong + b"</article-id>")
                with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_PMCI_MISMATCH"):
                    fulltext.inspect("PMC12345678", modified,
                                     expected_doi="10.1234/sample")

    def test_pmc_alias_conflicts_and_duplicates_fail_closed(self):
        both = sample().replace(
            b'<article-id pub-id-type="doi">',
            b'<article-id pub-id-type="pmcid">PMC12345678</article-id>'
            b'<article-id pub-id-type="doi">'
        )
        self.assertEqual(fulltext.inspect(
            "PMC12345678", both, expected_doi="10.1234/sample"
        )["status"], "NEEDS_CONTENT")

        conflicting = both.replace(
            b'<article-id pub-id-type="pmcid">PMC12345678</article-id>',
            b'<article-id pub-id-type="pmcid">PMC99999999</article-id>'
        )
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_PMCI_MISMATCH"):
            fulltext.inspect("PMC12345678", conflicting)

        duplicate = both.replace(
            b'<article-id pub-id-type="doi">',
            b'<article-id pub-id-type="pmcid">PMC12345678</article-id>'
            b'<article-id pub-id-type="doi">'
        )
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_ID_DUPLICATE"):
            fulltext.inspect("PMC12345678", duplicate)

        bad_doi = both.replace(b"10.1234/sample", b"10.1234/other")
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DOI_MISMATCH"):
            fulltext.inspect("PMC12345678", bad_doi,
                             expected_doi="10.1234/sample")

    def test_dtd_and_entity_injection_rejected(self):
        attack = b'<!DOCTYPE article [<!ENTITY secret SYSTEM "file:///etc/passwd">]>' + sample()
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DTD_OR_ENTITY_DENIED"):
            fulltext.inspect("PMC12345678", attack)
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DTD_OR_ENTITY_DENIED"):
            fulltext.inspect("PMC12345678", b"<?xml-stylesheet href='https://evil.invalid'?>" + sample())


    def test_standard_external_jats_public_dtd_is_stripped_without_resolution(self):
        preamble = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<!DOCTYPE article PUBLIC '
            b'"-//NLM//DTD JATS (Z39.96) Journal Archiving and Interchange DTD v1.1 20151215//EN" '
            b'"https://jats.nlm.nih.gov/archiving/1.1/JATS-archivearticle1.dtd">\n'
        )
        content = preamble + sample()
        with patch.object(fulltext.ET, "fromstring", wraps=fulltext.ET.fromstring) as parse:
            report = fulltext.inspect("PMC12345678", content, expected_doi="10.1234/sample")
        self.assertTrue(report["full_text_available"])
        parsed_input = parse.call_args.args[0]
        self.assertNotIn(b"<!DOCTYPE", parsed_input)
        self.assertNotIn(b"jats.nlm.nih.gov", parsed_input)
        self.assertEqual(report["sha256"], fulltext.hashlib.sha256(content).hexdigest())
        self.assertFalse(report["license_reuse_verified"])
        self.assertFalse(report["automatic_publication"])

    def test_malicious_external_dtd_custom_system_and_internal_subset_rejected(self):
        pub = (
            b'<!DOCTYPE article PUBLIC '
            b'"-//NLM//DTD JATS (Z39.96) Journal Publishing DTD v1.0 20120330//EN" '
            b'"JATS-journalpublishing1.dtd">'
        )
        for prefix in (
            b'<!DOCTYPE article SYSTEM "file:///etc/passwd">',
            b'<!DOCTYPE article SYSTEM "https://evil.example/external.dtd">',
            b'<!DOCTYPE article PUBLIC "-//EVIL//DTD bogus//EN" "x.dtd">',
            pub[:-1] + b' [ ]>',
            pub[:-1] + b' [<!ENTITY x SYSTEM "file:///etc/passwd">]>',
            pub + pub,
            b'<!-- note -->' + pub,
            b'<?xml-model href="https://evil.example/x"?>' + pub,
            b'<?xml-stylesheet href="https://evil.example/x"?>' + pub,
        ):
            with self.subTest(prefix=prefix[:50]):
                with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DTD_OR_ENTITY_DENIED"):
                    fulltext.inspect("PMC12345678", prefix + sample())

    def test_jats_public_dtd_does_not_bypass_real_article_identity(self):
        public = (
            b'<!DOCTYPE article PUBLIC '
            b'"-//NLM//DTD JATS (Z39.96) Journal Publishing DTD v1.0 20120330//EN" '
            b'"JATS-journalpublishing1.dtd">'
        )
        with self.assertRaisesRegex(fulltext.FulltextHold, "FULLTEXT_DOI_MISMATCH"):
            fulltext.inspect("PMC12345678", public + sample(doi="10.1234/other"),
                             expected_doi="10.1234/sample")

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
