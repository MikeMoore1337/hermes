"""H-12 public HTML review: all scenarios use synthetic HTML and mocked transport."""
from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

from statejnik_integration import html_review as h

ALLOWED = frozenset({"news.example.org"})
URL = "https://news.example.org/blog/running"
HTML = (
    '<!doctype html><html lang="ru"><head>'
    '<title>Беговая обувь: выбор и уход</title>'
    '</head><body><script>SECRET_KEY=123</script>'
    '<h1>Как выбрать беговые кроссовки</h1>'
    '<p>Текст статьи не должен попадать в метаданные</p></body></html>'
).encode("utf-8")


class GuardedHtmlTests(unittest.TestCase):
    def test_synthetic_html_yields_bounded_review_metadata_no_body(self):
        result = h.parse_public_html(URL, HTML, allowed_hosts=ALLOWED)
        self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(result["page"]["h1"], "Как выбрать беговые кроссовки")
        self.assertEqual(result["page"]["title"], "Беговая обувь: выбор и уход")
        self.assertEqual(result["source_sha256"], hashlib.sha256(HTML).hexdigest())
        self.assertFalse(result["final_redirect_url_verified"])
        self.assertFalse(result["source_authenticity_verified"])
        self.assertFalse(result["search_demand_verified"])
        self.assertIsNone(result["wordstat_volume"])
        self.assertFalse(result["publication_allowed"])
        self.assertNotIn("SECRET_KEY", str(result))
        self.assertNotIn("Текст статьи", str(result))

    def test_default_live_gate_denies_before_transport_or_dns(self):
        with patch("statejnik_integration.html_review.fetch_public_html") as send:
            with self.assertRaisesRegex(h.HtmlReviewDenied, "network_not_enabled"):
                h.candidate_fetch_one(URL, allowed_hosts=ALLOWED)
            send.assert_not_called()

    def test_explicit_synthetic_transport_wires_exact_host_and_authorization(self):
        with patch("statejnik_integration.html_review.fetch_public_html",
                   return_value=(200, HTML)) as send:
            packet = h.candidate_fetch_one(
                URL, allowed_hosts=ALLOWED, network_authorized=True
            )
            send.assert_called_once_with(URL, allowed_hosts=ALLOWED, authorized=True)
        self.assertEqual(packet["requested_url"], URL)
        self.assertEqual(packet["status"], "MANUAL_REVIEW_REQUIRED")

    def test_disallowed_host_never_calls_transport_even_when_authorized(self):
        for url in ("http://news.example.org/blog",
                    "https://127.0.0.1/latest",
                    "https://169.254.169.254/metadata",
                    "https://news.example.org.evil.org/path",
                    "https://news.example.org@evil.org/path",
                    "https://news.example.org:444/path",
                    "https://news.example.org/#fragment"):
            with self.subTest(url=url):
                with patch("statejnik_integration.html_review.fetch_public_html") as send:
                    with self.assertRaises(h.HtmlReviewDenied):
                        h.candidate_fetch_one(
                            url, allowed_hosts=ALLOWED, network_authorized=True
                        )
                    send.assert_not_called()

    def test_network_failures_never_reveal_source_or_url(self):
        from statejnik_integration.network_boundary import NetworkDenied
        with patch("statejnik_integration.html_review.fetch_public_html",
                   side_effect=NetworkDenied("dns_not_public")):
            with self.assertRaisesRegex(h.HtmlReviewDenied, "network_transport_denied") as err:
                h.candidate_fetch_one(URL, allowed_hosts=ALLOWED,
                                      network_authorized=True)
        self.assertNotIn("news.example.org", str(err.exception))
        self.assertNotIn("SECRET", str(err.exception))

    def test_bad_status_denied_even_from_injected_transport(self):
        with patch("statejnik_integration.html_review.fetch_public_html",
                   return_value=(302, HTML)):
            with self.assertRaisesRegex(h.HtmlReviewDenied, "network_transport_denied"):
                h.candidate_fetch_one(URL, allowed_hosts=ALLOWED,
                                      network_authorized=True)

    def test_reject_giant_non_utf8_or_binary_payload(self):
        for payload in (b"", b"<html>", b"\xff" * 100, b"<html>\x00</html>",
                        b"A" * (h.MAX_HTML_BYTES + 1), "not bytes", False):
            with self.subTest(payload_type=type(payload).__name__,
                              payload_size=len(payload) if hasattr(payload, "__len__") else 0):
                with self.assertRaises(h.HtmlReviewDenied):
                    h.parse_public_html(URL, payload, allowed_hosts=ALLOWED)

    def test_script_style_template_content_never_interpreted_as_page_heading(self):
        html = (
            b"<html><head><title>Public</title></head><body>"
            b"<script><h1>SECRET</h1></script>"
            b"<style><h1>STYLE_SECRET</h1></style>"
            b"<template><h1>TEMPLATE_SECRET</h1></template>"
            b"<h1>Allowed <em>heading</em></h1></body></html>"
        )
        result = h.parse_public_html(URL, html, allowed_hosts=ALLOWED)
        self.assertEqual(result["page"]["h1"], "Allowed heading")
        self.assertNotIn("SECRET", str(result))
        self.assertNotIn("STYLE_SECRET", str(result))

    def test_multiple_or_missing_headings_denied(self):
        htmls = (
            b"<html><title>Okay</title><body>None</body></html>",
            b"<html><h1>Okay</h1></html>",
            b"<html><title>First</title><title>Second</title><h1>Okay</h1></html>",
            b"<html><title>Okay</title><h1>First</h1><h1>Second</h1></html>",
            b"<html><title>  </title><h1>Okay</h1></html>",
        )
        for data in htmls:
            with self.subTest(data=data[:30]), self.assertRaises(h.HtmlReviewDenied):
                h.parse_public_html(URL, data, allowed_hosts=ALLOWED)

    def test_user_supplied_markdown_and_html_in_heading_is_neutralized(self):
        payload = (
            '<html><title>[Link](https://evil.org) | <em>safe</em></title>'
            '<h1>&lt;script&gt;*manual* #review!</h1></html>'
        ).encode()
        result = h.parse_public_html(URL, payload, allowed_hosts=ALLOWED)
        for text in (result["page"]["title"], result["page"]["h1"]):
            for character in "<>|[]\\`*#!":
                self.assertNotIn(character, text)

    def test_excessive_heading_or_tag_count_fail_closed(self):
        too_long = ('<html><title>' + "A" * 300 + '</title><h1>short</h1></html>').encode()
        with self.assertRaises(h.HtmlReviewDenied):
            h.parse_public_html(URL, too_long, allowed_hosts=ALLOWED)
        tags = ('<html><title>x</title><h1>okay</h1>' +
                '<b></b>' * 7000 + '</html>').encode()
        with self.assertRaisesRegex(h.HtmlReviewDenied, "html_too_complex"):
            h.parse_public_html(URL, tags, allowed_hosts=ALLOWED)

    def test_parsed_html_feeds_existing_site_gap_without_claiming_article(self):
        from statejnik_integration.offline_gap import _site
        record = h.parse_public_html(URL, HTML, allowed_hosts=ALLOWED)
        payload = h.to_offline_gap_site(record, allowed_hosts=ALLOWED)
        _site(payload)
        self.assertEqual(payload["pages"][0]["url"], URL)
        self.assertEqual(payload["article_urls"], [])
        self.assertEqual(payload["pages"][0]["h1"], "Как выбрать беговые кроссовки")

    def test_explicit_operator_article_classification_only(self):
        record = h.parse_public_html(URL, HTML, allowed_hosts=ALLOWED)
        payload = h.to_offline_gap_site(
            record, allowed_hosts=ALLOWED, operator_classified_article=True
        )
        self.assertEqual(payload["article_urls"], [URL])
        self.assertFalse(record["source_authenticity_verified"])
        self.assertFalse(record["publication_allowed"])

    def test_forged_or_wrongly_classified_review_cannot_enter_gap(self):
        record = h.parse_public_html(URL, HTML, allowed_hosts=ALLOWED)
        for field, value in (
            ("status", "VERIFIED"),
            ("source_authenticity_verified", True),
            ("publication_allowed", True),
            ("search_demand_verified", True),
            ("page", {"url": "https://evil.org", "title": "x", "h1": "y"}),
        ):
            with self.subTest(field=field):
                modified = dict(record)
                modified[field] = value
                with self.assertRaises(h.HtmlReviewDenied):
                    h.to_offline_gap_site(modified, allowed_hosts=ALLOWED)
        with self.assertRaises(h.HtmlReviewDenied):
            h.to_offline_gap_site(record, allowed_hosts=ALLOWED,
                                  operator_classified_article="yes")

    def test_runner_and_systemd_do_not_import_live_html_candidate(self):
        from statejnik_integration import runner
        self.assertFalse(runner.catalog()["network_enabled"])
        self.assertNotIn("html_review", runner.run.__code__.co_names)
        self.assertNotIn("candidate_fetch_one", runner.run.__code__.co_names)
        self.assertFalse(runner.catalog()["automatic_publication_enabled"])


if __name__ == "__main__":
    unittest.main()
