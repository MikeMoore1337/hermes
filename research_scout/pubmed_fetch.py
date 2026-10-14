"""Explicit one-article public PubMed metadata fetch, with no private network reach.

No unattended schedule, model calls, tokens, redirects, arbitrary input URLs,
HTML body output, publication or YFC news ingestion. Public metadata is
UNVERIFIED until a human checks the actual article and provenance.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Callable

from .core import PROMPT_INJECTION

HOST = "pubmed.ncbi.nlm.nih.gov"
MAX_HTML_BYTES = 262144
PMID = re.compile(r"[1-9][0-9]{5,9}")
DOI = re.compile(r"10\.[0-9]{4,9}/[A-Za-z0-9._;()/:-]{1,110}")
META_NAMES = frozenset({
    "citation_title", "citation_doi", "citation_pmid",
    "citation_date", "citation_publication_date",
})


class PubmedFetchError(ValueError):
    """Fixed category, never containing remote response or publication text."""


def validate_pmid(value: Any) -> str:
    if type(value) is not str or PMID.fullmatch(value) is None:
        raise PubmedFetchError("invalid_pmid")
    return value


def public_dns_address(host: str = HOST) -> str:
    if host != HOST:
        raise PubmedFetchError("host_not_allowlisted")
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PubmedFetchError("dns_unavailable") from exc
    ips = sorted({item[4][0] for item in answers if item[0] in
                  (socket.AF_INET, socket.AF_INET6)})
    if not ips:
        raise PubmedFetchError("dns_unavailable")
    try:
        addresses = [ipaddress.ip_address(ip) for ip in ips]
    except ValueError as exc:
        raise PubmedFetchError("dns_invalid_address") from exc
    if not all(address.is_global for address in addresses):
        raise PubmedFetchError("private_dns_address")
    # Prefer IPv4 after validating ALL answers. Some small VPS hosts resolve
    # AAAA records but have no IPv6 default route, so choosing an IPv6 address
    # first prevents a valid public HTTPS request despite working IPv4 egress.
    ipv4 = [address for address in addresses if address.version == 4]
    return str(sorted(ipv4 or addresses, key=lambda item: int(item))[0])


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Pin the verified DNS answer while retaining HTTPS hostname verification."""

    def __init__(self, address: str):
        super().__init__(HOST, port=443, timeout=8, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def get_pubmed_html(pmid: str) -> bytes:
    validate_pmid(pmid)
    address = public_dns_address()
    connection = _PinnedHTTPS(address)
    try:
        connection.request(
            "GET", f"/{pmid}/",
            headers={
                "Host": HOST, "Accept": "text/html",
                "Accept-Encoding": "identity",
                "User-Agent": "Hermes-Research-Scout-Readonly/0.1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise PubmedFetchError("article_unavailable")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise PubmedFetchError("compressed_response_denied")
        content_type = response.getheader("Content-Type", "").lower()
        if not (content_type.startswith("text/html")
                or content_type.startswith("application/xhtml+xml")):
            raise PubmedFetchError("non_html_response")
        claimed = response.getheader("Content-Length")
        if claimed is not None and (not claimed.isascii() or
                not claimed.isdigit() or int(claimed) > MAX_HTML_BYTES):
            raise PubmedFetchError("oversized_article")
        body = response.read(MAX_HTML_BYTES + 1)
        if len(body) > MAX_HTML_BYTES:
            raise PubmedFetchError("oversized_article")
        return body
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
        raise PubmedFetchError("network_or_tls_error") from exc
    finally:
        connection.close()


class _CitationMeta(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self.conflicting = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta":
            return
        attributes = dict(attrs)
        name = (attributes.get("name") or "").lower()
        if name not in META_NAMES:
            return
        content = attributes.get("content")
        if type(content) is not str or not content.strip() or len(content) > 250:
            self.conflicting = True
            return
        if name in self.fields and self.fields[name] != content.strip():
            self.conflicting = True
        self.fields[name] = content.strip()


def pubmed_metadata(pmid: str, *, fetch: Callable[[str], bytes] = get_pubmed_html) -> dict[str, Any]:
    """Return only whitelisted public citation metadata, not an evidence claim."""
    validate_pmid(pmid)
    raw = fetch(pmid)
    if not isinstance(raw, bytes) or len(raw) > MAX_HTML_BYTES:
        raise PubmedFetchError("invalid_article_body")
    try:
        html = raw.decode("utf-8")
    except UnicodeError as exc:
        raise PubmedFetchError("article_encoding_invalid") from exc
    parser = _CitationMeta()
    parser.feed(html)
    parser.close()
    fields = parser.fields
    if parser.conflicting:
        raise PubmedFetchError("conflicting_citation_metadata")
    if fields.get("citation_pmid") != pmid:
        raise PubmedFetchError("pmid_mismatch_or_missing")
    title = fields.get("citation_title", "")
    if not title or len(title) > 180 or any(ord(ch) < 32 for ch in title):
        raise PubmedFetchError("title_missing_or_invalid")
    doi = fields.get("citation_doi")
    if doi is not None and DOI.fullmatch(doi) is None:
        raise PubmedFetchError("doi_invalid")
    date = fields.get("citation_publication_date", fields.get("citation_date"))
    if date is not None and (
        len(date) > 32 or not re.fullmatch(r"[0-9][0-9 /-]{3,31}", date)
    ):
        raise PubmedFetchError("publication_date_unverified")
    if PROMPT_INJECTION.search(title):
        return {
            "status": "QUARANTINE", "reason": "suspicious_citation_title",
            "pmid": pmid, "source_url": f"https://{HOST}/{pmid}/",
        }
    return {
        "status": "UNVERIFIED_METADATA",
        "pmid": pmid,
        "source_url": f"https://{HOST}/{pmid}/",
        "citation_title": title,
        "citation_doi": doi,
        "publication_date_candidate": date,
    }


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("--pmid", required=True)
    args = parser.parse_args()
    try:
        answer = pubmed_metadata(args.pmid)
    except PubmedFetchError as exc:
        answer = {"status": "UNKNOWN", "reason": str(exc)}
    print(json.dumps(answer, ensure_ascii=False, sort_keys=True))
    return 0 if answer["status"] == "UNVERIFIED_METADATA" else 1


if __name__ == "__main__":
    raise SystemExit(main())
