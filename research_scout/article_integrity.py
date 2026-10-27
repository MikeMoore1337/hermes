"""H-03: bounded official Europe PMC article metadata integrity review.

Only explicit one-article fetch. Citation-metadata correction/retraction
signals become HOLD; absent DOI and missing signals never prove article safety.
No LLM, credentials, article full text, or publication.
"""
from __future__ import annotations

import argparse
import http.client
import json
from typing import Any, Callable

from .europe_pmc import EuropePMCError, PinnedHTTPS, resolve_public, ID, HOST, unique_json
from .pubmed_fetch import DOI

MAX_BODY = 48_000
MAX_NOTICES = 12
SOURCES = frozenset({"MED", "PMC"})
CORRECTION_TYPES = frozenset({
    "Erratum in", "Erratum for", "Corrected and republished in",
    "Corrected and republished from",
})
RETRACTION_TYPES = frozenset({
    "Retraction in", "Retraction of", "Retracted publication",
    "Retraction notice", "Partial retraction in", "Partial retraction of",
})
CONCERN_TYPES = frozenset({
    "Expression of concern in", "Expression of concern for",
})
# A missing notice is not proof the publisher has no correction.
ABSENT = "NOT_REPORTED_IN_THIS_METADATA"


class ArticleIntegrityError(ValueError):
    """Only fixed error codes; never expose untrusted upstream strings."""


def checked_identity(source: object, identifier: object) -> tuple[str, str]:
    if (type(source) is not str or source not in SOURCES
            or type(identifier) is not str or ID.fullmatch(identifier) is None
            or (source == "PMC") != identifier.startswith("PMC")):
        raise ArticleIntegrityError("article_identifier_not_allowlisted")
    return source, identifier


def fetch(source: str, identifier: str) -> bytes:
    source, identifier = checked_identity(source, identifier)
    conn = PinnedHTTPS(resolve_public())
    try:
        conn.request(
            "GET",
            f"/europepmc/webservices/rest/article/{source}/{identifier}"
            "?format=json&resultType=core",
            headers={
                "Host": HOST, "Accept": "application/json",
                "Accept-Encoding": "identity", "Connection": "close",
                "User-Agent": "HermesResearchScout/0.4",
            },
        )
        response = conn.getresponse()
        if response.status != 200:  # Includes redirect and API limitations.
            raise ArticleIntegrityError("article_http_unavailable")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise ArticleIntegrityError("article_content_type_invalid")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ArticleIntegrityError("article_encoding_invalid")
        size = response.getheader("Content-Length")
        if size is not None and (not size.isdigit() or int(size) > MAX_BODY):
            raise ArticleIntegrityError("article_body_oversize")
        raw = response.read(MAX_BODY + 1)
        if not raw or len(raw) > MAX_BODY:
            raise ArticleIntegrityError("article_body_invalid")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException):
        raise ArticleIntegrityError("article_network_or_tls_unavailable") from None
    finally:
        conn.close()


def _notice_codes(source: object) -> tuple[str, ...]:
    if source is None:
        return ()
    if type(source) is not dict or set(source) != {"commentCorrection"}:
        raise ArticleIntegrityError("article_notice_schema_invalid")
    entries = source["commentCorrection"]
    if type(entries) is not list or len(entries) > MAX_NOTICES:
        raise ArticleIntegrityError("article_notice_list_invalid")
    categories = set()
    for item in entries:
        if type(item) is not dict:
            raise ArticleIntegrityError("article_notice_item_invalid")
        name = item.get("type")
        if type(name) is not str or len(name) > 80:
            raise ArticleIntegrityError("article_notice_type_invalid")
        if name in RETRACTION_TYPES:
            categories.add("RETRACTION_OR_WITHDRAWAL_NOTICE")
        elif name in CORRECTION_TYPES:
            categories.add("CORRECTION_NOTICE")
        elif name in CONCERN_TYPES:
            categories.add("EXPRESSION_OF_CONCERN")
        else:
            categories.add("OTHER_OR_UNKNOWN_NOTICE")
    return tuple(sorted(categories))


def parse(raw: bytes, *, source: str, identifier: str) -> dict[str, object]:
    source, identifier = checked_identity(source, identifier)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BODY:
        raise ArticleIntegrityError("article_response_invalid")
    try:
        document = json.loads(raw, object_pairs_hook=unique_json)
    except EuropePMCError:
        raise ArticleIntegrityError("article_duplicate_json_key") from None
    except (ValueError, UnicodeError):
        raise ArticleIntegrityError("article_json_invalid") from None
    if (type(document) is not dict or document.get("hitCount") != 1
            or type(document.get("hitCount")) is not int
            or any(key in document for key in ("error", "errors", "warningList"))
            or type(document.get("result")) is not dict):
        raise ArticleIntegrityError("article_schema_invalid")
    result: dict[str, Any] = document["result"]
    if source == "PMC":
        # Europe PMC can answer a PMCID lookup with a canonical MED/PMID
        # citation record. Do not confuse returned citation source/id with
        # the requested PMCID: the explicit pmcid must ALWAYS match.
        if result.get("pmcid") != identifier:
            raise ArticleIntegrityError("article_pmcid_mismatch")
        response_source = result.get("source")
        response_id = result.get("id")
        if response_source == "PMC":
            if response_id != identifier:
                raise ArticleIntegrityError("article_identity_mismatch")
        elif response_source == "MED":
            # Permit only the canonical MED alias, not arbitrary records or
            # absent/unrelated PubMed IDs. PMID format is validated below.
            if (type(response_id) is not str or not response_id
                    or response_id != result.get("pmid")):
                raise ArticleIntegrityError("article_identity_mismatch")
        else:
            raise ArticleIntegrityError("article_identity_mismatch")
    else:
        if result.get("source") != source or result.get("id") != identifier:
            raise ArticleIntegrityError("article_identity_mismatch")
        if result.get("pmid") != identifier:
            raise ArticleIntegrityError("article_pmid_mismatch")
    doi = result.get("doi")
    if doi is not None and (type(doi) is not str or DOI.fullmatch(doi) is None):
        raise ArticleIntegrityError("article_doi_invalid")
    pmid = result.get("pmid")
    pmcid = result.get("pmcid")
    if pmid is not None and (
        type(pmid) is not str or ID.fullmatch(pmid) is None
        or pmid.startswith("PMC")
    ):
        raise ArticleIntegrityError("article_related_pmid_invalid")
    if pmcid is not None and (
        type(pmcid) is not str or ID.fullmatch(pmcid) is None
        or not pmcid.startswith("PMC")
    ):
        raise ArticleIntegrityError("article_related_pmcid_invalid")
    # Omission is unverified metadata. Explicit null is a malformed notice
    # container, not evidence that this article has no integrity warnings.
    if "commentCorrectionList" in result and result["commentCorrectionList"] is None:
        raise ArticleIntegrityError("article_notice_schema_invalid")
    categories = _notice_codes(result.get("commentCorrectionList"))
    status = "HOLD" if categories or doi is None else "MANUAL_REVIEW"
    return {
        "status": status,
        "article_source": source,
        "article_identifier": identifier,
        "pmid": pmid, "pmcid": pmcid, "doi": doi,
        "doi_state": "IN_METADATA" if doi is not None else "MISSING_IN_THIS_METADATA",
        "notice_state": "REVIEW_REQUIRED" if categories else ABSENT,
        "notice_codes": list(categories),
        "authoritative_notice_clearance": False,
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }


def inspect(
    source: str, identifier: str,
    *, transport: Callable[[str, str], bytes] = fetch,
) -> dict[str, object]:
    source, identifier = checked_identity(source, identifier)
    return parse(transport(source, identifier), source=source, identifier=identifier)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One official article metadata integrity lookup")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source", choices=sorted(SOURCES), required=True)
    parser.add_argument("--id", required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        report = inspect(args.source, args.id)
    except ArticleIntegrityError as exc:
        print(json.dumps({"status": "UNKNOWN", "reason": str(exc)}))
        return 2
    # No publisher text, title, references, personal data or URLs in journal.
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
