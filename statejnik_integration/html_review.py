"""H-12 guarded read-only HTML-to-SEO-page metadata, not a site crawler.

Default refuses network before DNS. The explicit candidate call may use only
the Hermes pinned-TLS transport; it is NOT exposed by Statejnik runner,
Control Center, systemd, site scan, YFC or public API. HTML is untrusted.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from html.parser import HTMLParser

from .network_boundary import NetworkDenied, fetch_public_html, target

MAX_HTML_BYTES = 256 * 1024
MAX_TAGS = 6000
MAX_TEXT_CHARS = 4096
MAX_FIELD_CHARS = 180
SKIP_TAGS = frozenset({"script", "style", "template", "noscript", "svg"})


class HtmlReviewDenied(ValueError):
    """Sanitized error only: no URL, page text, credentials or response body."""


def _safe_field(raw: str) -> str:
    """Normalize heading text without allowing HTML or Markdown injection."""
    text = " ".join(raw.split())
    if len(text) > MAX_FIELD_CHARS:
        raise HtmlReviewDenied("html_heading_too_long")
    if not text:
        return ""
    if any(unicodedata.category(c).startswith("C") for c in text):
        raise HtmlReviewDenied("html_heading_unsafe")
    # Upstream site.py renders headings into Markdown, so strip syntax
    # instead of handing raw HTML or Markdown to the later article plan.
    text = re.sub(r"[<>|\[\]\\\x60*#!]", " ", text)
    text = " ".join(text.split())
    return text


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags = 0
        self.skipped = 0
        self.current: str | None = None
        self.depth = 0
        self.title_parts: list[str] = []
        self.h1_parts: list[str] = []
        self.title_count = 0
        self.h1_count = 0
        self.html_seen = False
        self.title_chars = 0
        self.h1_chars = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags += 1
        if self.tags > MAX_TAGS:
            raise HtmlReviewDenied("html_too_complex")
        if tag == "html":
            self.html_seen = True
        if tag in SKIP_TAGS:
            self.skipped += 1
        if self.skipped:
            return
        if tag == "title":
            self.title_count += 1
        if tag == "h1":
            self.h1_count += 1
        if tag in ("title", "h1"):
            if self.current is not None:
                raise HtmlReviewDenied("html_heading_nested")
            self.current = tag
            self.depth = 1
        elif self.current is not None:
            self.depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIP_TAGS and self.skipped:
            self.skipped -= 1
            return
        if self.skipped or self.current is None:
            return
        self.depth -= 1
        if self.depth <= 0 or tag == self.current:
            self.current = None
            self.depth = 0

    def handle_data(self, data: str) -> None:
        if self.skipped or self.current is None:
            return
        if self.current == "title":
            self.title_chars += len(data)
            if self.title_chars > MAX_TEXT_CHARS:
                raise HtmlReviewDenied("html_heading_too_long")
            self.title_parts.append(data)
        elif self.current == "h1":
            self.h1_chars += len(data)
            if self.h1_chars > MAX_TEXT_CHARS:
                raise HtmlReviewDenied("html_heading_too_long")
            self.h1_parts.append(data)


def parse_public_html(
    requested_url: str, payload: bytes, *,
    allowed_hosts: frozenset[str],
) -> dict[str, object]:
    """Parse bounded UTF-8 HTML only, for manual editorial/site-gap review.

    `requested_url` is never represented as the final redirect URL.
    A SHA256 proves only byte consistency; NOT that a source was authentic.
    """
    try:
        target(requested_url, allowed_hosts)
    except NetworkDenied:
        raise HtmlReviewDenied("html_url_not_admitted") from None
    if (type(payload) is not bytes or not 10 <= len(payload) <= MAX_HTML_BYTES
            or b"\x00" in payload):
        raise HtmlReviewDenied("html_payload_invalid")
    try:
        document = payload.decode("utf-8", "strict")
        parser = _Extractor()
        parser.feed(document)
        parser.close()
    except HtmlReviewDenied:
        raise
    except (UnicodeError, ValueError, RecursionError, AssertionError):
        raise HtmlReviewDenied("html_parse_failed") from None
    if not parser.html_seen or parser.title_count != 1 or parser.h1_count != 1:
        raise HtmlReviewDenied("html_headings_missing_or_ambiguous")
    title = _safe_field(" ".join(parser.title_parts))
    heading = _safe_field(" ".join(parser.h1_parts))
    if not title or not heading:
        raise HtmlReviewDenied("html_headings_missing_or_ambiguous")
    return {
        "schema": "hermes-h12-public-html-review-v1",
        "status": "MANUAL_REVIEW_REQUIRED",
        "requested_url": requested_url,
        "final_redirect_url_verified": False,
        "source_authenticity_verified": False,
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "source_bytes": len(payload),
        "page": {"url": requested_url, "title": title, "h1": heading},
        "wordstat_volume": None,
        "search_demand_verified": False,
        "scientific_claims_verified": False,
        "publication_allowed": False,
        "yfc_write_allowed": False,
    }


def to_offline_gap_site(
    review: dict[str, object], *,
    allowed_hosts: frozenset[str],
    operator_classified_article: bool = False,
) -> dict[str, object]:
    """Shape manually reviewed metadata for existing networkless site-gap.

    No classification of a URL as an editorial article by default.
    The result has no Wordstat, search volume or provenance claim.
    """
    if (type(review) is not dict
            or review.get("schema") != "hermes-h12-public-html-review-v1"
            or review.get("status") != "MANUAL_REVIEW_REQUIRED"
            or review.get("source_authenticity_verified") is not False
            or review.get("publication_allowed") is not False
            or review.get("search_demand_verified") is not False
            or type(operator_classified_article) is not bool):
        raise HtmlReviewDenied("site_handoff_invalid")
    url = review.get("requested_url")
    page = review.get("page")
    if (type(page) is not dict or type(url) is not str
            or page.get("url") != url
            or not all(type(page.get(k)) is str
                       and 0 < len(page[k]) <= MAX_FIELD_CHARS
                       and _safe_field(page[k]) == page[k]
                       for k in ("title", "h1"))):
        raise HtmlReviewDenied("site_handoff_invalid")
    try:
        target(url, allowed_hosts)
    except NetworkDenied:
        raise HtmlReviewDenied("site_handoff_invalid") from None
    return {
        "url": url,
        "pages": [{"url": url, "title": page["title"], "h1": page["h1"]}],
        "article_urls": [url] if operator_classified_article else [],
        "article_sections": [],
        "urls": [],
    }


def candidate_fetch_one(
    url: str, *,
    allowed_hosts: frozenset[str],
    network_authorized: bool = False,
) -> dict[str, object]:
    """Not registered in any CLI/service. No credentials, writes or posting."""
    if network_authorized is not True:
        raise HtmlReviewDenied("network_not_enabled")
    try:
        target(url, allowed_hosts)
        status, payload = fetch_public_html(
            url, allowed_hosts=allowed_hosts, authorized=True
        )
    except NetworkDenied:
        raise HtmlReviewDenied("network_transport_denied") from None
    if status != 200:
        raise HtmlReviewDenied("network_transport_denied")
    return parse_public_html(url, payload, allowed_hosts=allowed_hosts)
