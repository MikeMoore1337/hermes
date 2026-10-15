"""H-03: one-shot DOI existence cross-check via official public Crossref REST.

No API key, credits, models, article downloads, redirects, retries, or
publishing. Crossref DOI equality verifies only bibliographic registration,
not a paper's scientific truth, peer-review status or study independence.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any, Callable
from urllib.parse import quote

from .europe_pmc import EuropePMCError, resolve_public as _resolve_pmc_public
from .pubmed_fetch import DOI

HOST = "api.crossref.org"
MAX_BYTES = 49_152
MAX_DOI = 256
USER_AGENT = "HermesResearchScout/0.3 (metadata-only; no bulk crawling)"


class CrossrefError(ValueError):
    """Fixed sanitized error codes, no remote data in error messages."""


def resolve_public() -> str:
    try:
        rows = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise CrossrefError("crossref_dns_unavailable") from None
    found = sorted({row[4][0] for row in rows
                    if row[0] in (socket.AF_INET, socket.AF_INET6)})
    try:
        candidates = [ipaddress.ip_address(ip) for ip in found]
    except ValueError:
        raise CrossrefError("crossref_dns_invalid") from None
    if not candidates or any(not ip.is_global for ip in candidates):
        raise CrossrefError("crossref_dns_private_denied")
    v4 = [ip for ip in candidates if ip.version == 4]
    return str(sorted(v4 or candidates, key=int)[0])


class PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, ip: str):
        super().__init__(HOST, timeout=9, context=ssl.create_default_context())
        self.pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self.pinned_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=HOST)
        except BaseException:
            sock.close()
            raise


def valid_doi(doi: object) -> str:
    if (type(doi) is not str or not 1 <= len(doi) <= MAX_DOI
            or DOI.fullmatch(doi) is None
            or any(ord(c) < 33 or ord(c) == 127 for c in doi)):
        raise CrossrefError("doi_invalid")
    return doi


def fetch(doi: str) -> bytes:
    known = valid_doi(doi)
    conn = PinnedTLS(resolve_public())
    try:
        conn.request(
            "GET", "/works/" + quote(known, safe=""),
            headers={
                "Accept": "application/json",
                "Host": HOST,
                "User-Agent": USER_AGENT,
                "Connection": "close",
                "Accept-Encoding": "identity",
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise CrossrefError("crossref_http_unavailable")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise CrossrefError("crossref_content_type_invalid")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise CrossrefError("crossref_encoding_invalid")
        length = response.getheader("Content-Length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or int(length) > MAX_BYTES
        ):
            raise CrossrefError("crossref_body_oversize")
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise CrossrefError("crossref_body_oversize")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException):
        raise CrossrefError("crossref_network_or_tls_failure") from None
    finally:
        conn.close()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name, value in pairs:
        if name in output:
            raise CrossrefError("crossref_duplicate_json_key")
        output[name] = value
    return output


def verify(doi: str, *, transport: Callable[[str], bytes] = fetch) -> dict[str, object]:
    """Only DOI registry presence; never a claim about study quality."""
    known = valid_doi(doi)
    raw = transport(known)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise CrossrefError("crossref_response_invalid")
    try:
        root = json.loads(raw, object_pairs_hook=_unique_pairs)
    except CrossrefError:
        raise
    except (ValueError, UnicodeError):
        raise CrossrefError("crossref_json_invalid") from None
    message = root.get("message") if type(root) is dict else None
    if type(message) is not dict:
        raise CrossrefError("crossref_schema_invalid")
    remote = message.get("DOI")
    if type(remote) is not str or len(remote) > MAX_DOI:
        raise CrossrefError("crossref_doi_missing")
    if remote.casefold() != known.casefold():
        raise CrossrefError("crossref_doi_mismatch")
    return {
        "status": "DOI_METADATA_MATCH",
        "doi": known,
        "registrar": "Crossref",
        "identifier_record_found": True,
        "scientific_claims_verified": False,
        "peer_review_verified": False,
        "source_independence_verified": False,
        "automatic_publication": False,
    }


def review_candidate(
    candidate: object, *, transport: Callable[[str], bytes] = fetch,
) -> dict[str, object]:
    """Cross-check only independently selected Europe PMC review candidates."""
    if (type(candidate) is not dict
            or candidate.get("source") != "EUROPE_PMC"
            or candidate.get("status") != "MANUAL_REVIEW"):
        raise CrossrefError("candidate_not_approved")
    raw_doi = candidate.get("doi")
    if raw_doi is None:
        return {
            "status": "HOLD", "reason": "missing_doi",
            "scientific_claims_verified": False,
        }
    checked = verify(valid_doi(raw_doi), transport=transport)
    return {
        "status": "MANUAL_REVIEW",
        "reason": "doi_registry_metadata_only",
        "doi": checked["doi"],
        "crossref_identifier_found": True,
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit one DOI metadata lookup")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--doi", required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = verify(args.doi)
    except CrossrefError as exc:
        print(json.dumps({"status": "UNKNOWN", "reason": str(exc)}))
        return 2
    # Never return remote titles, abstracts, external URLs or user content.
    print(json.dumps({
        "status": result["status"],
        "identifier_record_found": True,
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
