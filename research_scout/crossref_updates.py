"""Explicit bounded Crossref reverse-update lookup for an original article DOI.

Crossref's normal /works/{doi} DOI-existence result cannot clear updates:
the *notice's* update-to metadata points to the original DOI. This separate
single-GET search is operator-triggered only; never scheduled in daily_digest.
No crawling, redirects, retries, model, publisher-side clearance or publication.
"""
from __future__ import annotations

import argparse
from datetime import date
import http.client
import json
from typing import Any, Callable
from urllib.parse import quote

from .crossref import CrossrefError, HOST, PinnedTLS, resolve_public, valid_doi

MAX_UPDATES = 5
MAX_BYTES = 49_152
NOTICE_TYPES = {
    "correction": "CORRECTION_NOTICE",
    "erratum": "CORRECTION_NOTICE",
    "retraction": "RETRACTION_OR_WITHDRAWAL_NOTICE",
    "partial-retraction": "RETRACTION_OR_WITHDRAWAL_NOTICE",
    "withdrawal": "RETRACTION_OR_WITHDRAWAL_NOTICE",
    "expression-of-concern": "EXPRESSION_OF_CONCERN",
}


class UpdateLookupError(ValueError):
    """Sanitized codes, never external error bodies or remote titles."""


def checked_doi(value: object) -> str:
    try:
        return valid_doi(value)
    except CrossrefError:
        raise UpdateLookupError("update_doi_invalid") from None


def query_path(doi: str) -> str:
    """Fixed endpoint and minimal selected fields; never accept arbitrary URL."""
    doi = checked_doi(doi)
    return ("/works?filter=updates:" + quote(doi, safe="")
            + "&rows=5&select=DOI,update-to")


def fetch(doi: str) -> bytes:
    path = query_path(doi)
    try:
        ip = resolve_public()
    except CrossrefError:
        raise UpdateLookupError("update_dns_unavailable") from None
    conn = PinnedTLS(ip)
    try:
        conn.request("GET", path, headers={
            "Host": HOST, "Accept": "application/json",
            "User-Agent": "HermesResearchScout/0.4 (explicit updates-only)",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        response = conn.getresponse()
        if response.status == 429:
            # Explicit upstream throttling signal; a later manually approved
            # invocation may be appropriate, but NEVER retry automatically.
            raise UpdateLookupError("update_http_429")
        if response.status != 200:
            raise UpdateLookupError("update_http_unavailable")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise UpdateLookupError("update_content_type_invalid")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise UpdateLookupError("update_encoding_invalid")
        length = response.getheader("Content-Length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or int(length) > MAX_BYTES
        ):
            raise UpdateLookupError("update_body_oversize")
        raw = response.read(MAX_BYTES + 1)
        if not raw or len(raw) > MAX_BYTES:
            raise UpdateLookupError("update_body_oversize")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException):
        raise UpdateLookupError("update_network_or_tls_unavailable") from None
    finally:
        conn.close()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name, value in pairs:
        if name in output:
            raise UpdateLookupError("update_duplicate_json_key")
        output[name] = value
    return output


def _date(value: object) -> str:
    """Validate real Crossref partial date, without inventing day precision."""
    if type(value) is not dict or type(value.get("date-parts")) is not list:
        raise UpdateLookupError("update_date_invalid")
    parts = value["date-parts"]
    if len(parts) != 1 or type(parts[0]) is not list or not 1 <= len(parts[0]) <= 3:
        raise UpdateLookupError("update_date_invalid")
    inner = parts[0]
    if any(type(v) is not int for v in inner):
        raise UpdateLookupError("update_date_invalid")
    try:
        date(inner[0], inner[1] if len(inner) > 1 else 1,
             inner[2] if len(inner) > 2 else 1)
    except ValueError:
        raise UpdateLookupError("update_date_invalid") from None
    return "-".join(f"{v:04d}" if i == 0 else f"{v:02d}" for i, v in enumerate(inner))


def parse(raw: bytes, *, doi: str) -> dict[str, object]:
    known = checked_doi(doi)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise UpdateLookupError("update_response_invalid")
    try:
        root = json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: _invalid_constant())
    except UpdateLookupError:
        raise
    except (ValueError, UnicodeError):
        raise UpdateLookupError("update_json_invalid") from None
    if type(root) is not dict or root.get("status") != "ok" or type(root.get("message")) is not dict:
        raise UpdateLookupError("update_schema_invalid")
    message = root["message"]
    items, total = message.get("items"), message.get("total-results")
    if (type(items) is not list or len(items) > MAX_UPDATES
            or type(total) is not int or total < len(items)
            or any(type(i) is not dict for i in items)):
        raise UpdateLookupError("update_schema_invalid")
    notices: list[dict[str, str]] = []
    seen: set[str] = set()
    incomplete = total > len(items)
    for item in items:
        notice_doi = checked_doi(item.get("DOI"))
        if notice_doi.casefold() in seen:
            raise UpdateLookupError("update_duplicate_notice")
        seen.add(notice_doi.casefold())
        links = item.get("update-to")
        if type(links) is not list or not 1 <= len(links) <= 16:
            raise UpdateLookupError("update_links_invalid")
        matches = []
        for link in links:
            if type(link) is not dict:
                raise UpdateLookupError("update_links_invalid")
            target = checked_doi(link.get("DOI"))
            kind = link.get("type")
            if type(kind) is not str or not 1 <= len(kind) <= 60 or not kind.isascii():
                raise UpdateLookupError("update_type_invalid")
            when = _date(link.get("updated"))
            if target.casefold() == known.casefold():
                matches.append((kind.lower(), when))
        if not matches or notice_doi.casefold() == known.casefold():
            # A contradictory API result must NEVER be treated as no notice.
            raise UpdateLookupError("update_relation_mismatch")
        for kind, when in matches:
            notices.append({
                "doi": notice_doi,
                "notice_type": NOTICE_TYPES.get(kind, "OTHER_OR_UNKNOWN_NOTICE"),
                "published": when,
                "source": "CROSSREF_REVERSE_UPDATE_METADATA",
            })
    if not notices and total:
        raise UpdateLookupError("update_incomplete_result")
    categories = sorted({n["notice_type"] for n in notices})
    return {
        "doi": known,
        "status": "REVIEW_REQUIRED" if notices or incomplete else "NOT_FOUND_WITH_COVERAGE",
        "coverage": ("CROSSREF_FILTER_TRUNCATED" if incomplete
                     else "CROSSREF_REVERSE_UPDATES_ONLY"),
        "total_results_reported": total,
        "notices": notices,
        "notice_codes": categories,
        "source": "CROSSREF",
        "authoritative_notice_clearance": False,
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "manual_review_required": True,
    }


def _invalid_constant() -> Any:
    raise UpdateLookupError("update_json_invalid")


def inspect(
    doi: str, *, transport: Callable[[str], bytes] = fetch,
) -> dict[str, object]:
    doi = checked_doi(doi)
    return parse(transport(doi), doi=doi)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One explicit Crossref reverse-update lookup")
    parser.add_argument("--doi", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "requests_attempted": 0}))
        return 0
    try:
        result = inspect(args.doi)
    except UpdateLookupError as exc:
        print(json.dumps({"status": "UNKNOWN", "reason": str(exc),
                          "publisher_clearance": False}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
