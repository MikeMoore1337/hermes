"""Bounded offline triage of already retrieved official NCBI citation metadata.

No API calls, downloads, model use, autonomous publishing or factual truth scores.
A fresh, complete citation date makes metadata eligible for HUMAN review only.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .core import PROMPT_INJECTION
from .pubmed_fetch import DOI, validate_pmid, PubmedFetchError

MAX_ITEMS = 50
MAX_AGE_DAYS = 45
SCHEMA_KEYS = frozenset({
    "status", "pmid", "source_url", "citation_title", "citation_doi",
    "publication_date_candidate", "source_api",
})
DATE_PATTERN = re.compile(r"((?:19|20)[0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{1,2})")
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class CitationInputError(ValueError):
    """Fixed diagnostic codes: no untrusted citation text or credentials."""


def _date(value: Any) -> date:
    """Do not fabricate a day for NCBI's year-only/range date candidates."""
    if type(value) is not str or not DATE_PATTERN.fullmatch(value):
        raise CitationInputError("incomplete_or_ambiguous_date")
    matched = DATE_PATTERN.fullmatch(value)
    assert matched is not None
    year, month, day = matched.groups()
    try:
        return date(int(year), MONTHS[month], int(day))
    except ValueError as exc:
        raise CitationInputError("invalid_calendar_date") from exc


def _item(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != SCHEMA_KEYS:
        raise CitationInputError("unexpected_citation_schema")
    if value["status"] != "UNVERIFIED_METADATA" or value["source_api"] != "NCBI_ESUMMARY":
        raise CitationInputError("unapproved_citation_origin")
    try:
        pmid = validate_pmid(value["pmid"])
    except PubmedFetchError as exc:
        raise CitationInputError("invalid_citation_pmid") from exc
    url = f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/"
    if value["source_url"] != url:
        raise CitationInputError("citation_url_mismatch")
    title = value["citation_title"]
    if (type(title) is not str or not 1 <= len(title.strip()) <= 180
            or any(ord(char) < 32 for char in title)):
        raise CitationInputError("invalid_citation_title")
    if PROMPT_INJECTION.search(title):
        raise CitationInputError("suspicious_citation_title")
    doi = value["citation_doi"]
    if doi is not None and (type(doi) is not str or DOI.fullmatch(doi) is None):
        raise CitationInputError("invalid_citation_doi")
    return {
        "pmid": pmid,
        "url": url,
        "title": title.strip(),
        "doi": doi,
        "date_candidate": value["publication_date_candidate"],
    }


def review_batch(citations: Any, *, now: datetime) -> dict[str, Any]:
    """Group for manual review, never infer scientific validity or publication rights."""
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise CitationInputError("now_timezone_required")
    if type(citations) is not list or len(citations) > MAX_ITEMS:
        raise CitationInputError("batch_invalid")
    if not citations:
        return {"status": "NO_DATA", "items": [], "rejections": [],
                "scientific_claims_verified": False}
    utc_today = now.astimezone(UTC).date()
    candidates: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    for index, item in enumerate(citations):
        try:
            entry = _item(item)
        except CitationInputError as exc:
            rejections.append({"index": index, "reason": str(exc)})
            continue
        try:
            published = _date(entry.pop("date_candidate"))
        except CitationInputError as exc:
            entry["status"] = "HOLD"
            entry["reason"] = str(exc)
        else:
            entry["published_date"] = published.isoformat()
            if published > utc_today + timedelta(days=1):
                entry["status"] = "HOLD"
                entry["reason"] = "future_publication_date"
            elif utc_today - published > timedelta(days=MAX_AGE_DAYS):
                entry["status"] = "HOLD"
                entry["reason"] = "stale_publication"
            else:
                entry["status"] = "MANUAL_REVIEW"
                entry["reason"] = "citation_metadata_only"
        candidates.append(entry)

    pmids = Counter(item["pmid"] for item in candidates)
    dois = Counter(item["doi"].casefold() for item in candidates if item["doi"])
    for item in candidates:
        # Duplicate PMID or DOI may be metadata variation, do not treat it
        # as independent scientific corroboration or silently de-duplicate.
        if pmids[item["pmid"]] > 1:
            item["status"] = "HOLD"
            item["reason"] = "duplicate_pmid"
        elif item["doi"] is not None and dois[item["doi"].casefold()] > 1:
            item["status"] = "HOLD"
            item["reason"] = "duplicate_doi"
    candidates.sort(key=lambda item: (item["status"] != "MANUAL_REVIEW", item["pmid"]))
    return {
        "status": "MANUAL_REVIEW" if any(
            item["status"] == "MANUAL_REVIEW" for item in candidates
        ) else "HOLD",
        "items": candidates,
        "rejections": rejections,
        "scientific_claims_verified": False,
    }
