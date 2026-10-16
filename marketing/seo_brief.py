"""Turn *existing* Research Scout public metadata into operator-only SEO briefs.

Never fetch search statistics, generate scientific claims, mutate YFC or publish.
This is a handoff skeleton, not a competing SEO Growth Operator.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from research_scout.review_draft import ReviewDraftError, build_daily_item_draft

SCHEMA = "hermes-content-research-brief-v1"
NO_DATA = "NO_DATA"
THEMES: dict[str, dict[str, str]] = {
    "training_recovery": {
        "question": "Чем ощущение восстановления отличается от восстановления работоспособности?",
        "working_title": "Как читать исследования о восстановлении после тренировки",
    },
    "nutrition_and_sport": {
        "question": "Какие выводы о питании и тренировках действительно подтверждены исследованиями?",
        "working_title": "Что исследование говорит о питании и нагрузках — и чего не доказывает",
    },
    "research_quality": {
        "question": "Как отличить результаты наблюдений от причинных выводов исследования?",
        "working_title": "Как интерпретировать выборку, ограничения и исправления научной статьи",
    },
}


class ContentBriefError(ValueError):
    """Reject unknown source, theme, or attempts to promote unreviewed evidence."""


def from_daily_item(item: Any, *, theme: str) -> dict[str, Any]:
    """Prepare a source-preserving editorial *proposal*, not a ready article."""
    if type(theme) is not str or theme not in THEMES:
        raise ContentBriefError("theme_not_allowed")
    try:
        source = build_daily_item_draft(item)
    except (ReviewDraftError, KeyError, TypeError, ValueError) as exc:
        raise ContentBriefError("invalid_research_source") from exc
    if (source["schema"] != "hermes-research-review-draft-v1"
            or source["status"] not in {"HOLD", "MANUAL_REVIEW"}
            or source["scientific_claims_verified"] is not False
            or source["automatic_publication"] is not False
            or source["expert_review_status"] != "MANUAL_REVIEW_REQUIRED"
            or source["primary_source_access"] != "NOT_VERIFIED"):
        raise ContentBriefError("source_not_approved_for_handoff")
    metadata = source["source_daily_report"]
    if metadata["article_notice_state"] in {"REVIEW_REQUIRED", "UNAVAILABLE"}:
        gate = "HOLD"
    elif source["status"] == "HOLD":
        gate = "HOLD"
    else:
        gate = "MANUAL_REVIEW"
    proposal = THEMES[theme]
    return {
        "schema": SCHEMA,
        "status": gate,
        "purpose": "RESEARCH_TO_EDITORIAL_PROPOSAL_ONLY",
        "theme": theme,
        "proposed_question": proposal["question"],
        "proposed_working_title": proposal["working_title"],
        "research_provenance": {
            "title": source["title"],
            "publication_date": source["publication_date"],
            "source_url": source["source_link"],
            "identifiers": dict(source["identifiers"]),
            "source_status": source["status"],
            "bibliographic_source_kind": source["source_kind"],
            "article_notice_state": metadata["article_notice_state"],
            "correction_codes": list(metadata["article_notice_codes"]),
            "scientific_claims_verified": False,
            "full_text_reviewed": False,
        },
        "proposed_scientific_claims": [],
        "verified_search_metrics": {
            "search_volume": NO_DATA,
            "keyword_difficulty": NO_DATA,
            "competition_gap": NO_DATA,
            "checked_at": NO_DATA,
            "source": NO_DATA,
        },
        "editorial_gates": [
            "RESEARCH_SCOUT_EXPERT_REVIEW_REQUIRED",
            "YFC_EDITORIAL_REVIEW_REQUIRED",
            "YFC_OWNER_APPROVAL_REQUIRED",
            "SEARCH_DATA_SOURCE_REQUIRED_FOR_SEO_METRICS",
        ],
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "outbound_messages_allowed": False,
        "ai_generation_performed": False,
        "ownership": {
            "scientific_evidence": "Hermes Research Scout #4",
            "market_research": "Hermes #64",
            "seo_and_publication": "YFC #320/#322",
        },
    }


def run_cli(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Offline public research SEO proposal")
    parser.add_argument("--from-daily-stdin", action="store_true", required=True)
    parser.add_argument("--theme", choices=sorted(THEMES), required=True)
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        raw = sys.stdin.buffer.read(16_385)
        if len(raw) > 16_384:
            raise ContentBriefError("input_too_large")
        data = json.loads(raw)
        result = from_daily_item(data, theme=args.theme)
    except (ValueError, TypeError) as exc:
        print(json.dumps({
            "status": "REJECTED",
            "reason": str(exc) if isinstance(exc, ContentBriefError) else "input_invalid",
        }, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
