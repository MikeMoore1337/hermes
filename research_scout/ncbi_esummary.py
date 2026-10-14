"""Official NCBI ESummary JSON (not interactive PubMed HTML).

One explicit PMID, one HTTPS GET, verified public DNS/IP/TLS, no redirects,
no API key, model, publication, cron, arbitrary URLs or stored user data.
NCBI requires identifying contact details; a configured email is mandatory
and is never printed in diagnostics.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from typing import Any, Callable
from urllib.parse import urlencode

from .ncbi_rate_limit import NCBIRateGateError, reserve_request
from .core import PROMPT_INJECTION
from .pubmed_fetch import DOI, PubmedFetchError, validate_pmid

HOST = "eutils.ncbi.nlm.nih.gov"
TOOL = "HermesResearchScout"
MAX_BODY = 131072
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,90}\.[A-Za-z]{2,24}$"
)


class NCBIError(ValueError):
    """Fixed refusal code, never source text, request URL or contact email."""


def _contact(value: Any) -> str:
    if type(value) is not str or len(value) > 150 or not EMAIL_PATTERN.fullmatch(value):
        raise NCBIError("ncbi_contact_missing_or_invalid")
    return value


def _resolve() -> str:
    try:
        records = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise NCBIError("ncbi_dns_unavailable") from exc
    ips = sorted({item[4][0] for item in records
                  if item[0] in (socket.AF_INET, socket.AF_INET6)})
    if not ips:
        raise NCBIError("ncbi_dns_unavailable")
    try:
        parsed = [ipaddress.ip_address(ip) for ip in ips]
    except ValueError as exc:
        raise NCBIError("ncbi_dns_invalid") from exc
    if not all(item.is_global for item in parsed):
        raise NCBIError("ncbi_private_dns_denied")
    ipv4 = [item for item in parsed if item.version == 4]
    return str(sorted(ipv4 or parsed, key=lambda x: int(x))[0])


class _PinnedNCBI(http.client.HTTPSConnection):
    def __init__(self, address: str):
        super().__init__(HOST, port=443, timeout=8, context=ssl.create_default_context())
        self._pinned = address

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def _fetch(pmid: str, contact: str) -> bytes:
    validate_pmid(pmid)
    _contact(contact)
    address = _resolve()
    conn = _PinnedNCBI(address)
    query = urlencode({
        "db": "pubmed", "id": pmid, "retmode": "json",
        "tool": TOOL, "email": contact,
    })
    try:
        try:
            reserve_request()
        except NCBIRateGateError as exc:
            raise NCBIError(str(exc)) from None
        conn.request(
            "GET", "/entrez/eutils/esummary.fcgi?" + query,
            headers={
                "Host": HOST,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "HermesResearchScout/0.1",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise NCBIError("ncbi_http_unavailable")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise NCBIError("ncbi_compression_denied")
        media = response.getheader("Content-Type", "").lower()
        if not media.startswith("application/json"):
            raise NCBIError("ncbi_unexpected_content")
        header = response.getheader("Content-Length")
        if header is not None and (
            not header.isascii() or not header.isdigit() or int(header) > MAX_BODY
        ):
            raise NCBIError("ncbi_response_too_large")
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise NCBIError("ncbi_response_too_large")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise NCBIError("ncbi_network_or_tls_failure") from exc
    finally:
        conn.close()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON where later duplicate keys shadow earlier data."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NCBIError("ncbi_duplicate_json_key")
        result[key] = value
    return result


def _deny_reported_api_errors(section: dict[str, Any]) -> None:
    """A JSON 200 with a provider error cannot become valid citation evidence."""
    if any(key in section for key in ("error", "errors")):
        raise NCBIError("ncbi_api_reported_error")


def parse_esummary(payload: bytes, pmid: str) -> dict[str, Any]:
    """Strictly reduce public bibliographic metadata; not evidence validation."""
    validate_pmid(pmid)
    if type(payload) is not bytes or len(payload) > MAX_BODY:
        raise NCBIError("ncbi_response_invalid")
    try:
        root = json.loads(payload, object_pairs_hook=_unique_json_object)
    except NCBIError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise NCBIError("ncbi_response_invalid") from exc
    if not isinstance(root, dict) or not isinstance(root.get("result"), dict):
        raise NCBIError("ncbi_schema_invalid")
    _deny_reported_api_errors(root)
    result = root["result"]
    _deny_reported_api_errors(result)
    if result.get("uids") != [pmid] or not isinstance(result.get(pmid), dict):
        raise NCBIError("ncbi_pmid_mismatch")
    record = result[pmid]
    _deny_reported_api_errors(record)
    if record.get("uid") != pmid:
        raise NCBIError("ncbi_pmid_mismatch")
    title = record.get("title")
    if (type(title) is not str or not 1 <= len(title.strip()) <= 180
            or any(ord(ch) < 32 for ch in title)):
        raise NCBIError("ncbi_title_invalid")
    title = title.strip()
    published = record.get("pubdate")
    if published is not None and (
        type(published) is not str or not 1 <= len(published) <= 40
        or any(ord(ch) < 32 for ch in published)
    ):
        raise NCBIError("ncbi_date_invalid")
    ids = record.get("articleids", [])
    if not isinstance(ids, list) or len(ids) > 32:
        raise NCBIError("ncbi_ids_invalid")
    doi_values = []
    for article_id in ids:
        if not isinstance(article_id, dict):
            raise NCBIError("ncbi_ids_invalid")
        if article_id.get("idtype") == "doi":
            value = article_id.get("value")
            if type(value) is not str or DOI.fullmatch(value) is None:
                raise NCBIError("ncbi_doi_invalid")
            doi_values.append(value)
    if len(set(doi_values)) > 1:
        raise NCBIError("ncbi_conflicting_doi")
    if PROMPT_INJECTION.search(title):
        return {
            "status": "QUARANTINE", "reason": "suspicious_citation_title",
            "pmid": pmid, "source_url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
        }
    return {
        "status": "UNVERIFIED_METADATA",
        "pmid": pmid, "source_url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
        "citation_title": title, "citation_doi": doi_values[0] if doi_values else None,
        "publication_date_candidate": published,
        "source_api": "NCBI_ESUMMARY",
    }


def get_citation(
    pmid: str, *, contact: str,
    fetch: Callable[[str, str], bytes] = _fetch,
) -> dict[str, Any]:
    validate_pmid(pmid)
    _contact(contact)
    return parse_esummary(fetch(pmid, contact), pmid)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--pmid", required=True)
    args = parser.parse_args()
    try:
        result = get_citation(
            args.pmid, contact=os.environ.get("HERMES_NCBI_CONTACT_EMAIL", "")
        )
    except (NCBIError, PubmedFetchError) as exc:
        result = {"status": "UNKNOWN", "reason": str(exc)}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "UNVERIFIED_METADATA" else 1


if __name__ == "__main__":
    raise SystemExit(main())
