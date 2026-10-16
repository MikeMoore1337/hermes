"""H-23 offline OpenAlex Works candidate normalization (no HTTP or credentials).

Never use this parser as proof of article validity or publisher notice clearance.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable

from .crossref import CrossrefError, valid_doi

MAX_BYTES = 65_536
MAX_WORKS = 20
ID = re.compile(r"https://openalex\.org/W[1-9][0-9]{0,15}\Z")
DOI_PREFIX = "https://doi.org/"
SCHEMA = "hermes-h23-openalex-offline-v1"


class OpenAlexEvidenceInvalid(ValueError):
    """Fixed reason codes, never untrusted source fields."""


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise OpenAlexEvidenceInvalid("duplicate_json_key")
        result[key] = value
    return result


def _normalize_doi(value: object) -> str | None:
    if type(value) is not str:
        return None
    doi = value[len(DOI_PREFIX):] if value.startswith(DOI_PREFIX) else value
    try:
        return valid_doi(doi).casefold()
    except CrossrefError:
        return None


def _utc(value: object) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise OpenAlexEvidenceInvalid("retrieval_timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise OpenAlexEvidenceInvalid("retrieval_timestamp_invalid") from None
    if stamp.utcoffset() != timedelta(0):
        raise OpenAlexEvidenceInvalid("retrieval_timestamp_invalid")
    return value


def _valid_update(value: object) -> bool:
    if type(value) is not str or not (value.endswith("Z") or value.endswith("+00:00")):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() == timedelta(0)
    except ValueError:
        return False


def _valid_date(value: object) -> bool:
    if type(value) is not str or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", value) is None:
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def inspect_works(raw: bytes, *, retrieved_at: str, existing_dois: Iterable[str] = ()) -> dict:
    """Read pre-supplied untrusted OpenAlex-shaped JSON; never contact OpenAlex."""
    retrieved_at = _utc(retrieved_at)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise OpenAlexEvidenceInvalid("payload_missing_or_oversize")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except OpenAlexEvidenceInvalid:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise OpenAlexEvidenceInvalid("invalid_json") from None
    if type(payload) is not dict or type(payload.get("results")) is not list:
        raise OpenAlexEvidenceInvalid("invalid_results")
    works = payload["results"]
    if not 1 <= len(works) <= MAX_WORKS or any(type(w) is not dict for w in works):
        raise OpenAlexEvidenceInvalid("invalid_results")

    known = set()
    for item in existing_dois:
        normalized = _normalize_doi(item)
        if normalized is None:
            raise OpenAlexEvidenceInvalid("existing_doi_invalid")
        known.add(normalized)
    page_seen = set()
    reviewed = []
    for work in works:
        work_id = work.get("id")
        if type(work_id) is not str or ID.fullmatch(work_id) is None:
            # Never expose malformed URL or identity from an untrusted source.
            raise OpenAlexEvidenceInvalid("invalid_work_id")
        doi = _normalize_doi(work.get("doi"))
        identifiers = work.get("ids")
        same_doi = (type(identifiers) is not dict or identifiers.get("doi") is None
                    or _normalize_doi(identifiers["doi"]) == doi)
        state, reason = "MANUAL_REVIEW", "metadata_only_not_scientific_evidence"
        if type(work.get("is_retracted")) is not bool:
            state, reason = "HOLD", "retraction_status_unknown"
        elif work["is_retracted"]:
            state, reason = "HOLD", "retraction_flag"
        elif type(work.get("type")) is not str or not work["type"]:
            state, reason = "HOLD", "work_type_unknown"
        elif work["type"] == "paratext":
            state, reason = "HOLD", "paratext_not_study"
        elif doi is None:
            state, reason = "HOLD", "doi_missing_or_invalid"
        elif not same_doi:
            state, reason = "HOLD", "conflicting_doi_identifiers"
        elif not _valid_date(work.get("publication_date")):
            state, reason = "HOLD", "publication_date_invalid"
        elif not _valid_update(work.get("updated_date")):
            state, reason = "HOLD", "updated_date_invalid"
        elif doi in known:
            state, reason = "DUPLICATE", "doi_already_in_existing_sources"
        elif doi in page_seen:
            state, reason = "DUPLICATE", "doi_already_in_openalex_page"

        if doi is not None:
            page_seen.add(doi)
        reviewed.append({
            "openalex_id": work_id,
            "doi": doi,
            "source_url": work_id,
            "retrieved_at": retrieved_at,
            "status": state,
            "reason": reason,
            "manual_review_required": state != "DUPLICATE",
            "scientific_claims_verified": False,
            "publisher_notices_cleared": False,
            "automatic_publication": False,
        })

    return {
        "schema": SCHEMA, "source": "OpenAlex Works (offline supplied)",
        "status": "OFFLINE_ONLY", "retrieved_at": retrieved_at,
        "unique_candidates_for_manual_review": sum(w["status"] == "MANUAL_REVIEW" for w in reviewed),
        "duplicates": sum(w["status"] == "DUPLICATE" for w in reviewed),
        "held": sum(w["status"] == "HOLD" for w in reviewed),
        "real_api_calls": 0, "provider_cost_usd": 0, "automatic_publication": False,
        "resident_agent_allowed": False, "works": reviewed,
    }