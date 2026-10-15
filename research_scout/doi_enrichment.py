"""H-03: explicitly requested, bounded missing-DOI enrichment.

A Europe PMC lite row with no DOI can have its identifiers recovered from
official core metadata and cross-checked by Crossref. This is not scientific
verification and is NOT connected to the daily production metadata pipeline.
No arbitrary URL, article full text, LLM, tokens or auto-publication.
"""
from __future__ import annotations

from typing import Any, Callable

from .article_integrity import ArticleIntegrityError, inspect as inspect_article
from .crossref import CrossrefError, valid_doi, verify as verify_doi
from .daily_digest import DigestError, TOPIC_IDS, _review_item
from .europe_pmc import ID
from .core import PROMPT_INJECTION

NOTICE_CODES = frozenset({
    "CORRECTION_NOTICE", "RETRACTION_OR_WITHDRAWAL_NOTICE",
    "EXPRESSION_OF_CONCERN", "OTHER_OR_UNKNOWN_NOTICE",
})


class EnrichmentDenied(ValueError):
    """Fail closed with fixed diagnostic codes, never raw article text."""


def _result(identifier: str, status: str, reason: str, *, calls: int,
            doi: str | None = None, pmid: str | None = None,
            pmcid: str | None = None) -> dict[str, Any]:
    return {
        "identifier": identifier,
        "status": status,
        "reason": reason,
        "doi": doi,
        "pmid": pmid,
        "pmcid": pmcid,
        "requests_attempted": calls,
        "scientific_claims_verified": False,
        "publisher_correction_clearance_verified": False,
        "automatic_publication": False,
        "manual_review_required": True,
    }


def review_missing_doi(
    candidate: object, *, topic: str,
    integrity_verifier: Callable[[str, str], dict[str, Any]] = inspect_article,
    doi_verifier: Callable[[str], dict[str, Any]] = verify_doi,
) -> dict[str, Any]:
    """At most one core lookup and one DOI lookup for a validated candidate."""
    if topic not in TOPIC_IDS or type(candidate) is not dict:
        raise EnrichmentDenied("candidate_invalid")
    if (candidate.get("status") != "MANUAL_REVIEW"
            or candidate.get("reason") != "metadata_only"
            or candidate.get("doi") is not None):
        raise EnrichmentDenied("candidate_not_missing_doi")
    try:
        reviewed = _review_item(candidate, topic)
    except DigestError:
        raise EnrichmentDenied("candidate_invalid") from None
    if (reviewed["reason"] != "doi_missing" or reviewed["status"] != "HOLD"
            or PROMPT_INJECTION.search(reviewed["title"])):
        raise EnrichmentDenied("candidate_not_missing_doi")
    identifier = reviewed["identifier"]
    source = "PMC" if identifier.startswith("PMC") else "MED"
    try:
        article = integrity_verifier(source, identifier)
    except ArticleIntegrityError:
        return _result(identifier, "HOLD", "core_unavailable", calls=1)
    if (type(article) is not dict
            or article.get("article_source") != source
            or article.get("article_identifier") != identifier
            or article.get("status") not in ("MANUAL_REVIEW", "HOLD")
            or article.get("scientific_claims_verified") is not False
            or article.get("automatic_publication") is not False):
        return _result(identifier, "HOLD", "core_invalid", calls=1)
    state, notices = article.get("notice_state"), article.get("notice_codes")
    if (state not in ("REVIEW_REQUIRED", "NOT_REPORTED_IN_THIS_METADATA")
            or type(notices) is not list or len(notices) > 4
            or any(type(code) is not str or code not in NOTICE_CODES for code in notices)
            or len(notices) != len(set(notices))
            or (state == "REVIEW_REQUIRED") != bool(notices)):
        return _result(identifier, "HOLD", "core_invalid", calls=1)
    if state == "REVIEW_REQUIRED" or article["status"] == "HOLD":
        return _result(identifier, "HOLD", "publisher_notice_or_hold", calls=1)
    raw_pmid, raw_pmcid = article.get("pmid"), article.get("pmcid")
    if (raw_pmid is not None and
            (type(raw_pmid) is not str or ID.fullmatch(raw_pmid) is None
             or raw_pmid.startswith("PMC"))):
        return _result(identifier, "HOLD", "related_id_invalid", calls=1)
    if (raw_pmcid is not None and
            (type(raw_pmcid) is not str or ID.fullmatch(raw_pmcid) is None
             or not raw_pmcid.startswith("PMC"))):
        return _result(identifier, "HOLD", "related_id_invalid", calls=1)
    if ((source == "MED" and raw_pmid != identifier)
            or (source == "PMC" and raw_pmcid != identifier)):
        return _result(identifier, "HOLD", "related_id_invalid", calls=1)
    try:
        doi = valid_doi(article.get("doi"))
    except CrossrefError:
        return _result(identifier, "HOLD", "doi_still_missing_or_invalid", calls=1)
    try:
        checked = doi_verifier(doi)
    except CrossrefError:
        return _result(identifier, "HOLD", "doi_registry_unknown", calls=2)
    if (type(checked) is not dict or checked.get("status") != "DOI_METADATA_MATCH"
            or checked.get("doi") != doi
            or checked.get("scientific_claims_verified") is not False
            or checked.get("automatic_publication") is not False):
        return _result(identifier, "HOLD", "doi_registry_untrusted", calls=2)
    return _result(identifier, "MANUAL_REVIEW", "doi_from_core_metadata",
                   calls=2, doi=doi, pmid=raw_pmid, pmcid=raw_pmcid)

