"""#599: assemble bounded RU article drafts from operator-curated claim packets.

No claims are inferred from metadata or source text. No live network/model calls,
HMAC submission, automatic science approval, or publication. The output remains
pending human editorial review, and all source hashes are checked by handoff.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
import re

from . import yfc_draft_handoff as handoff

SCHEMA = "hermes-i4-claim-packets-v1"
LICENSE_URLS = {
    "CC-BY-4.0": "https://creativecommons.org/licenses/by/4.0/",
    "CC-BY-SA-4.0": "https://creativecommons.org/licenses/by-sa/4.0/",
    "CC0-1.0": "https://creativecommons.org/publicdomain/zero/1.0/",
}
ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
UNTRUSTED_MARKUP = re.compile(r"(?i)<\s*/?\s*(script|iframe|style)\b")


class ComposerHold(ValueError):
    """Fixed rejection reason without any source data."""


def check(condition: bool, reason: str) -> None:
    if not condition:
        raise ComposerHold(reason)


def checked_text(value: object, minimum: int, maximum: int) -> str:
    check(type(value) is str and minimum <= len(value.strip()) <= maximum
          and not UNTRUSTED_MARKUP.search(value)
          and all(ord(c) >= 32 or c in "\t\n" for c in value),
          "CONTENT_UNTRUSTED_OR_INCOMPLETE")
    return value.strip()


def compose(packet: object, *, source_dir: Path = handoff.SOURCE_DIR) -> dict:
    """Build a complete handoff document ONLY from explicitly curated prose.

    Licence/notice review is an operator declaration, NOT independently
    established source-rights clearance or scientific sign-off.
    """
    check(type(packet) is dict and set(packet) == {
        "schema", "research_version", "metadata", "sources",
        "source_receipts", "licence_reviews", "claims",
    } and packet["schema"] == SCHEMA, "PACKET_SCHEMA_INVALID")
    meta = packet["metadata"]
    check(type(meta) is dict and set(meta) == {
        "slug", "title", "description", "lead", "topics", "primary_query",
        "risk_level", "evidence_level",
    }, "METADATA_SCHEMA_INVALID")
    check(meta["risk_level"] in ("low", "moderate", "unknown") and
          meta["evidence_level"] in ("limited", "preliminary", "conflicting", "unknown")
          and type(meta["topics"]) is list and 1 <= len(meta["topics"]) <= 12,
          "METADATA_SCIENCE_HOLD")
    for field, limit in (("title", 180), ("description", 320),
                         ("lead", 1200), ("primary_query", 240)):
        checked_text(meta[field], 5, limit)
    sources, reviews, claims = (
        packet["sources"], packet["licence_reviews"], packet["claims"])
    check(type(sources) is list and 2 <= len(sources) <= 16
          and type(reviews) is list and len(reviews) == len(sources)
          and type(claims) is list and 1 <= len(claims) <= 8,
          "SOURCE_OR_CLAIM_EVIDENCE_MISSING")
    check(all(type(s) is dict and type(s.get("source_id")) is str
              and ID.fullmatch(s["source_id"]) is not None for s in sources),
          "SOURCE_ID_INVALID")
    source_ids = [s["source_id"] for s in sources]
    check(len(set(source_ids)) == len(source_ids), "SOURCE_DUPLICATE")
    seen = set()
    for review in reviews:
        check(type(review) is dict and set(review) == {
            "source_id", "licence_id", "licence_url", "notice_status",
            "checked_on", "basis",
        }, "SOURCE_RIGHTS_RECEIPT_MISSING")
        source_id = review["source_id"]
        check(source_id in source_ids and source_id not in seen,
              "SOURCE_RIGHTS_RECEIPT_MISMATCH")
        seen.add(source_id)
        check(review["licence_id"] in LICENSE_URLS
              and review["licence_url"] == LICENSE_URLS[review["licence_id"]]
              and review["notice_status"] == "NO_UNRESOLVED_NOTICE_REPORTED"
              and review["basis"] == "OPERATOR_READ_PUBLISHER_FULL_TEXT",
              "SOURCE_RIGHTS_OR_NOTICE_HOLD")
        try:
            day = date.fromisoformat(review["checked_on"])
        except (TypeError, ValueError):
            raise ComposerHold("SOURCE_RIGHTS_DATE_INVALID") from None
        check(0 <= (date.today() - day).days <= 30, "SOURCE_RIGHTS_CHECK_STALE")
    check(seen == set(source_ids), "SOURCE_RIGHTS_RECEIPT_MISMATCH")

    yfc_claims, matrix, observed, limitations = [], [], [], []
    seen_claims = set()
    for claim in claims:
        check(type(claim) is dict and set(claim) == {
            "claim_id", "claim_text", "normalized_claim",
            "interpretation", "limitations", "source_ids",
        }, "CLAIM_PACKET_INVALID")
        cid = claim["claim_id"]
        check(type(cid) is str and ID.fullmatch(cid) is not None
              and cid not in seen_claims, "CLAIM_ID_INVALID")
        seen_claims.add(cid)
        refs = claim["source_ids"]
        check(type(refs) is list and len(refs) >= 2
              and len(refs) == len(set(refs)) and set(refs) <= set(source_ids),
              "CLAIM_NOT_BACKED_BY_TWO_REFERENCES")
        statement = checked_text(claim["claim_text"], 10, 800)
        norm = checked_text(claim["normalized_claim"], 10, 800)
        context = checked_text(claim["interpretation"], 40, 2400)
        caveat = checked_text(claim["limitations"], 40, 1000)
        yfc_claims.append({"claim_id": cid, "claim_text": statement,
                           "normalized_claim": norm})
        observed.append("Тезис для научной проверки: " + statement + ". " + context)
        limitations.append(caveat)
        matrix.append({"claim_id": cid, "source_ids": refs,
                       "support_level": "unclear", "limitations": caveat,
                       "review_status": "pending"})
    article = {
        **meta, "article_kind": "evidence_review", "search_intent": "evidence",
        "secondary_queries": [],
        "body_sections": [
            {"heading": "Что сообщают рассмотренные источники",
             "paragraphs": observed},
            {"heading": "Ограничения интерпретации", "paragraphs": limitations},
        ],
        "claims": yfc_claims, "sources": sources,
        "claim_source_matrix": matrix,
        "author": {"name": "Research Scout", "type": "Organization"},
        "editor": {"name": "YFC Editorial", "type": "Organization"},
        "domain_reviewer": None, "related_slugs": [], "cta": {},
        "evergreen_score": 0, "product_relevance": 0, "editorial_value": 0,
        "web_article_potential_reasons": ["awaiting_independent_scientific_review"],
    }
    dossier = {"schema": handoff.SCHEMA,
               "research_version": packet["research_version"],
               "article": article, "source_receipts": packet["source_receipts"]}
    try:
        handoff.build_payload(dossier, source_dir=source_dir)
    except (handoff.HandoffHold, KeyError, ValueError, TypeError):
        raise ComposerHold("PROVENANCE_OR_HANDOFF_GATE_HOLD") from None
    return {"status": "READY_NOT_SUBMITTED",
            "policy": "AUTO_DRAFT_ONLY", "document": dossier,
            "scientific_claims_verified": False,
            "rights_independently_verified": False,
            "hmac_submission_allowed": False, "automatic_publication": False,
            "model_calls": 0, "network_calls": 0}
