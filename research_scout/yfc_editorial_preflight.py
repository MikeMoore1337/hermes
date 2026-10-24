"""I3: offline fail-closed scientific-to-YFC handoff preflight.

This is not a YFC intake client, scientific reviewer, or publishing adapter.
The current Research Scout expert packet contains unresolved human review gates;
there is intentionally no "approve" input or output payload for either YFC API.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import Any

from .science_handoff import EXPECTED_DOIS, REVIEW_GATES, SCHEMA, packet

RESULT_SCHEMA = "hermes-i3-yfc-science-preflight-v1"
YFC_ARTICLE_SCHEMA = "hermes-web-article-intake-v1"
YFC_NEWS_SCHEMA = "hermes-editorial-intake-v2"

_PACKET_FIELDS = frozenset({
    "schema", "generated_at", "source_scope", "studies", "study_count",
    "incomplete_gate_count", "conclusion", "scientific_claims_verified",
    "full_text_independently_reviewed", "external_publication_allowed",
    "reviewer_signoff_supported_by_this_tool",
})
_STUDY_FIELDS = frozenset({
    "pmid", "doi", "source_title", "original_candidate_status",
    "scientific_review_status", "scientific_claims_verified",
    "reviewer_approval", "publisher_clearance_verified",
    "publication_allowed", "gates", "gates_incomplete",
})
_GATE_FIELDS = frozenset({
    "id", "question", "reference_url", "source_coverage", "review_state",
    "effect_size", "confidence_interval", "reviewer", "review_signature",
    "editorial_approval",
})


class SciencePreflightRefused(ValueError):
    """Fixed reason codes only; never embed external or private text."""


def _require(condition: bool) -> None:
    if not condition:
        raise SciencePreflightRefused("science_handoff_not_authorized")


def assess_science_handoff(candidate: object) -> dict[str, Any]:
    """Check the *current unresolved* expert packet and return only a HOLD receipt.

    Any unexpected change (including future expert approval) requires a new,
    separately reviewed integration contract. Self-attested approval is never
    sufficient for a YFC payload.
    """
    _require(type(candidate) is dict and set(candidate) == _PACKET_FIELDS)
    value = candidate
    _require(
        value["schema"] == SCHEMA
        and value["source_scope"] == "FOUR_FIXED_OWNER_CURATED_REPORTS_AND_PUBLIC_SOURCE_POINTERS"
        and value["conclusion"] == "HOLD_FOR_INDEPENDENT_SCIENTIFIC_REVIEW"
        and value["scientific_claims_verified"] is False
        and value["full_text_independently_reviewed"] is False
        and value["external_publication_allowed"] is False
        and value["reviewer_signoff_supported_by_this_tool"] is False
        and type(value["study_count"]) is int
        and value["study_count"] == 4
        and type(value["incomplete_gate_count"]) is int
        and value["incomplete_gate_count"] == 19
    )
    raw_generated_at = value["generated_at"]
    _require(type(raw_generated_at) is str and len(raw_generated_at) <= 40)
    try:
        generated_at = datetime.fromisoformat(raw_generated_at)
    except ValueError:
        raise SciencePreflightRefused("science_handoff_not_authorized") from None
    _require(generated_at.tzinfo is not None and generated_at.utcoffset().total_seconds() == 0)

    studies = value["studies"]
    _require(type(studies) is list and len(studies) == 4)
    observed: set[str] = set()
    result_sources: list[dict[str, Any]] = []
    for study in studies:
        _require(type(study) is dict and set(study) == _STUDY_FIELDS)
        pmid = study["pmid"]
        _require(type(pmid) is str and pmid in EXPECTED_DOIS and pmid not in observed)
        observed.add(pmid)
        _require(
            study["doi"] == EXPECTED_DOIS[pmid]
            and type(study["source_title"]) is str
            and 1 <= len(study["source_title"]) <= 500
            and study["original_candidate_status"] in ("HOLD", "MANUAL_REVIEW")
            and study["scientific_review_status"] == "NEEDS_EXPERT_REVIEW"
            and study["scientific_claims_verified"] is False
            and study["reviewer_approval"] is False
            and study["publisher_clearance_verified"] is False
            and study["publication_allowed"] is False
        )
        if pmid == "42771055":
            _require(study["original_candidate_status"] == "HOLD")
        gates = study["gates"]
        canonical = REVIEW_GATES[pmid]
        _require(
            type(gates) is list
            and len(gates) == len(canonical)
            and type(study["gates_incomplete"]) is int
            and study["gates_incomplete"] == len(canonical)
        )
        for gate, (gate_id, question, reference, coverage) in zip(gates, canonical):
            _require(type(gate) is dict and set(gate) == _GATE_FIELDS)
            _require(
                gate["id"] == gate_id
                and gate["question"] == question
                and gate["reference_url"] == reference
                and gate["source_coverage"] == coverage
                and gate["review_state"] == "NOT_INDEPENDENTLY_REVIEWED"
                and gate["effect_size"] == "NOT_INDEPENDENTLY_VERIFIED"
                and gate["confidence_interval"] == "NOT_INDEPENDENTLY_VERIFIED"
                and gate["reviewer"] is None
                and gate["review_signature"] is None
                and gate["editorial_approval"] is False
            )
        result_sources.append({
            "pmid": pmid,
            "doi": EXPECTED_DOIS[pmid],
            "pubmed_url": "https://pubmed.ncbi.nlm.nih.gov/" + pmid + "/",
            "independent_review": "NOT_RUN",
            "incomplete_gates": len(canonical),
            "source_freshness": "NOT_RECHECKED_LIVE",
            "publisher_license_clearance": "NOT_VERIFIED",
            "correction_status": (
                "KNOWN_CORRECTION_UNREVIEWED" if pmid == "42771055"
                else "PUBLISHER_NOTICE_CLEARANCE_UNVERIFIED"
            ),
            "claim_text": None,
            "population": "UNKNOWN",
            "evidence_level": "UNKNOWN",
            "forwardable": False,
        })
    _require(observed == set(EXPECTED_DOIS))
    _require(sum(row["incomplete_gates"] for row in result_sources) == 19)

    return {
        "schema": RESULT_SCHEMA,
        "status": "HOLD",
        "reason_codes": [
            "independent_scientific_review_missing",
            "source_freshness_and_license_unverified",
            "yfc_claim_level_transport_not_approved",
            "owner_editorial_review_missing",
        ],
        "original_handoff_schema": SCHEMA,
        "study_count": 4,
        "expert_checks_pending": 19,
        "sources": sorted(result_sources, key=lambda row: row["pmid"]),
        "intended_yfc_asset": "web_article_evidence_review_candidate",
        "yfc_web_article_schema": YFC_ARTICLE_SCHEMA,
        "yfc_news_intake_schema": YFC_NEWS_SCHEMA,
        "yfc_request_payload": None,
        "claim_level_contract_compatible": False,
        "scientific_claims_verified": False,
        "editorial_approval_verified": False,
        "publication_allowed": False,
        "network_calls": 0,
        "vault_access": False,
    }


def current_preflight(*, now: datetime) -> dict[str, Any]:
    """Read already-curated offline facts, without network, secrets or YFC I/O."""
    return assess_science_handoff(packet(now=now))


def main() -> int:
    try:
        output = current_preflight(now=datetime.now(UTC))
    except (SciencePreflightRefused, ValueError):
        print(json.dumps({"status": "REFUSED", "reason": "science_handoff_not_authorized"}))
        return 2
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
