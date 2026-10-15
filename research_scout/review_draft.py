"""Structured, source-bound research drafts for manual expert review only.

This module consumes already retrieved metadata. It does not fetch articles,
infer methods or effects from titles, call a model, write a report, or publish.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .core import PROMPT_INJECTION
from .pubmed_fetch import DOI, validate_pmid

SCHEMA = "hermes-research-review-draft-v1"
MAX_INPUT_BYTES = 65_536
MAX_DRAFTS = 10
UNKNOWN = "UNKNOWN"
MANUAL_REVIEW = "MANUAL_REVIEW"
# A bibliographic index, DOI resolver or publisher landing page is not
# evidence that the full study text was retrieved and checked.
SOURCE_KINDS = {
    "europepmc.org": "bibliographic_index",
    "pubmed.ncbi.nlm.nih.gov": "bibliographic_index",
    "doi.org": "doi_resolver",
    "bjsm.bmj.com": "publisher_page",
    "www.acsm.org": "professional_organization",
    "www.sciencedaily.com": "secondary",
    "medicalxpress.com": "secondary",
}
CONFIRMED_FIELDS = frozenset({
    "research_question", "study_type", "population", "sample_size",
    "methods", "main_results", "limitations", "effect_size",
    "correction_status",
})
PMCID = re.compile(r"PMC[1-9][0-9]{1,11}\Z")


class ReviewDraftError(ValueError):
    """Fixed refusal code; never includes untrusted article text."""


def _text(value: Any, name: str, maximum: int = 2_000) -> str:
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ReviewDraftError(f"{name}_invalid")
    return value.strip()


def _optional_text(value: Any, name: str) -> str:
    if value is None:
        return UNKNOWN
    return _text(value, name)


def _url(value: Any, name: str = "source_url") -> tuple[str, str]:
    raw = _text(value, name, 900)
    try:
        parts = urlsplit(raw)
        host = parts.hostname.lower() if parts.hostname else None
        port = parts.port
    except ValueError:
        raise ReviewDraftError(f"{name}_invalid") from None
    if (parts.scheme != "https" or host not in SOURCE_KINDS
            or parts.username is not None or parts.password is not None
            or port not in (None, 443) or parts.query or parts.fragment
            or not parts.path.startswith("/")):
        raise ReviewDraftError(f"{name}_not_allowlisted")
    return urlunsplit(("https", host, parts.path, "", "")), SOURCE_KINDS[host]


def _date(value: Any) -> str:
    if value is None:
        return UNKNOWN
    raw = _text(value, "publication_date", 20)
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        raise ReviewDraftError("publication_date_invalid") from None


def _identifier(value: Any, name: str) -> str:
    if value is None:
        return UNKNOWN
    if name == "pmid":
        try:
            return validate_pmid(value)
        except ValueError:
            raise ReviewDraftError("pmid_invalid") from None
    if name == "doi" and (type(value) is not str or DOI.fullmatch(value) is None):
        raise ReviewDraftError("doi_invalid")
    return value


def _confirmed(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if type(value) is not dict or not set(value).issubset(CONFIRMED_FIELDS):
        raise ReviewDraftError("confirmed_fields_invalid")
    result: dict[str, Any] = {}
    for field, record in value.items():
        if type(record) is not dict or set(record) != {
            "value", "source_url", "review_basis", "supporting_excerpt",
        }:
            raise ReviewDraftError("confirmed_field_provenance_invalid")
        source_url, source_kind = _url(record["source_url"], "confirmed_source_url")
        # Source domains alone cannot attest article access. Require explicit
        # operator-provided full-text evidence; do not call this independently
        # verified research. Metadata index/DOI links must not qualify.
        if source_kind != "publisher_page" or record["review_basis"] != "operator_reviewed_full_text":
            raise ReviewDraftError("confirmed_field_requires_full_text_evidence")
        excerpt = _text(record["supporting_excerpt"], "supporting_excerpt", 900)
        if PROMPT_INJECTION.search(excerpt):
            raise ReviewDraftError("supporting_excerpt_suspicious")
        item = record["value"]
        if field == "sample_size":
            if type(item) is not int or not 1 <= item <= 1_000_000_000:
                raise ReviewDraftError("sample_size_invalid")
        else:
            item = _text(item, "confirmed_value")
            if PROMPT_INJECTION.search(item):
                raise ReviewDraftError("confirmed_value_suspicious")
        result[field] = {
            "value": item,
            "source_url": source_url,
            "review_basis": "operator_reviewed_full_text",
            "supporting_excerpt": excerpt,
        }
    return result


def build_draft(candidate: Any) -> dict[str, Any]:
    """Build a 15-field draft without filling unknown scientific facts."""
    if type(candidate) is not dict:
        raise ReviewDraftError("candidate_invalid")
    allowed = {
        "source", "id", "source_url", "title", "doi", "pmid", "status",
        "reason", "first_publication_date", "scientific_claims_verified",
        "confirmed",
    }
    if not set(candidate).issubset(allowed):
        raise ReviewDraftError("candidate_schema_invalid")
    source_url, source_kind = _url(candidate.get("source_url"))
    title = _text(candidate.get("title"), "title", 300)
    if PROMPT_INJECTION.search(title):
        raise ReviewDraftError("title_suspicious")
    if candidate.get("status") not in {"MANUAL_REVIEW", "HOLD"}:
        raise ReviewDraftError("candidate_status_invalid")
    if candidate.get("scientific_claims_verified") is True:
        raise ReviewDraftError("scientific_verification_not_allowed")
    record_id = candidate.get("id")
    if type(record_id) is not str or not (record_id.isdigit() or PMCID.fullmatch(record_id)):
        raise ReviewDraftError("record_id_invalid")
    confirmed = _confirmed(candidate.get("confirmed"))
    identifier = {
        "doi": _identifier(candidate.get("doi"), "doi"),
        "pmid": _identifier(candidate.get("pmid"), "pmid"),
        "record_id": record_id,
    }
    def field(name: str) -> Any:
        return confirmed[name]["value"] if name in confirmed else UNKNOWN

    status = MANUAL_REVIEW if candidate["status"] == MANUAL_REVIEW else "HOLD"
    # Only an explicit manual review record can identify a candidate original
    # study text; publisher hostname and DOI resolution are not sufficient.
    reviewed_urls = {record["source_url"] for record in confirmed.values()}
    reviewed_primary_url = next(iter(reviewed_urls)) if len(reviewed_urls) == 1 else UNKNOWN
    return {
        "schema": SCHEMA,
        "status": status,
        "title": title,
        "publication_date": _date(candidate.get("first_publication_date")),
        "identifiers": identifier,
        "source_link": source_url,
        "source_kind": source_kind,
        "primary_source_link": reviewed_primary_url,
        "primary_source_access": (
            "OPERATOR_REVIEW_ATTESTED_NOT_INDEPENDENTLY_VERIFIED"
            if reviewed_primary_url != UNKNOWN else "NOT_VERIFIED"
        ),
        "research_question": field("research_question"),
        "study_type": field("study_type"),
        "population": field("population"),
        "sample_size": field("sample_size"),
        "methods": field("methods"),
        "main_results": field("main_results"),
        "limitations": field("limitations"),
        "effect_size": field("effect_size"),
        "correction_status": field("correction_status"),
        "what_it_supports": (
            "Только описание явно подтверждённых библиографических и методических полей; "
            "эффект и причинность не установлены."
        ),
        "what_it_does_not_support": (
            "Не подтверждает медицинское назначение, причинный эффект, консенсус, "
            "переносимость результата на другую популяцию или публикацию."
        ),
        "practical_significance": {
            "YFC": "NOT_ASSESSED_UNTIL_EXPERT_REVIEW",
            "Second Brain": "NOT_ASSESSED_UNTIL_EXPERT_REVIEW",
            "Hermes Agent": "NOT_ASSESSED_UNTIL_EXPERT_REVIEW",
            "QA/Python": "NOT_ASSESSED_UNTIL_EXPERT_REVIEW",
        },
        "uncertainty": "high",
        "expert_review_status": "MANUAL_REVIEW_REQUIRED",
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "provenance": {
            "bibliographic_metadata": source_url,
            "bibliographic_source_kind": source_kind,
            "full_text_independently_verified": False,
            "operator_supplied_full_text_excerpts": {
                name: {
                    "source_url": data["source_url"],
                    "review_basis": data["review_basis"],
                    "supporting_excerpt": data["supporting_excerpt"],
                }
                for name, data in confirmed.items()
            },
            "confirmed_fields": {
                name: data["source_url"] for name, data in confirmed.items()
            },
            "unknown_fields": [
                name for name in (
                    "study_type", "population", "sample_size", "methods",
                    "main_results", "limitations",
                ) if name not in confirmed
            ],
        },
    }


def compare_drafts(drafts: Any) -> dict[str, Any]:
    """Prepare a comparison frame; never infer contradiction or consensus."""
    if type(drafts) is not list or not 1 <= len(drafts) <= MAX_DRAFTS:
        raise ReviewDraftError("draft_batch_invalid")
    for item in drafts:
        if type(item) is not dict or item.get("schema") != SCHEMA:
            raise ReviewDraftError("draft_schema_invalid")
    questions = {item.get("research_question", UNKNOWN) for item in drafts}
    same_question = len(questions) == 1 and UNKNOWN not in questions
    return {
        "schema": "hermes-research-comparison-v1",
        "status": MANUAL_REVIEW,
        "study_count": len(drafts),
        "similar_research_question": "EXPLICITLY_SAME" if same_question else UNKNOWN,
        "methodological_differences": "MANUAL_REVIEW_REQUIRED",
        "population_differences": "MANUAL_REVIEW_REQUIRED",
        "contradictory_results": "NOT_ASSESSED_WITHOUT_EXPERT_REVIEW",
        "shared_conclusions": "NOT_ASSESSED_WITHOUT_EXPERT_REVIEW",
        "limitations_of_comparison": [
            "Библиографических metadata недостаточно для метаанализа.",
            "Различия популяций, методов и эффектов не выводятся автоматически.",
        ],
        "meta_analysis": "NOT_PERFORMED",
        "expert_review_status": "MANUAL_REVIEW_REQUIRED",
    }


def _read_stdin() -> Any:
    payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(payload) > MAX_INPUT_BYTES:
        raise ReviewDraftError("input_size_invalid")
    try:
        return json.loads(payload)
    except (ValueError, UnicodeError):
        raise ReviewDraftError("input_json_invalid") from None


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Offline Research Scout review draft")
    parser.add_argument("--review-stdin", action="store_true")
    parser.add_argument("--compare-stdin", action="store_true")
    args = parser.parse_args(argv)
    if args.review_stdin == args.compare_stdin:
        print(json.dumps({"status": "REJECTED", "reason": "explicit_mode_required"}))
        return 2
    try:
        payload = _read_stdin()
        result = (
            build_draft(payload) if args.review_stdin else compare_drafts(payload)
        )
    except (OSError, ReviewDraftError) as exc:
        reason = str(exc) if isinstance(exc, ReviewDraftError) else "stdin_unavailable"
        print(json.dumps({"status": "REJECTED", "reason": reason}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
