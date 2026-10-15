"""Curated public abstract facts for an evidence-grounded Research Scout pilot.

These are paraphrases verified against the publicly available PubMed abstract,
not full-text quotations or a human-approved systematic evidence assessment.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SOURCE_URL = "https://pubmed.ncbi.nlm.nih.gov/42797032/"
SOURCE_DOI = "10.3390/nu18183049"
EVIDENCE_BASIS = "curated_public_abstract_facts_not_full_text"

ABSTRACT_FACTS = {
    "F1": "A systematic review included 36 human intervention studies.",
    "F2": "Eligible studies involved physically active people aged at least 14 years.",
    "F3": "Foods included tart cherry, pomegranate, berries, beetroot, watermelon, banana, honey and other plant foods.",
    "F4": "Some studies showed reduced perceived muscle soreness within 24 to 72 hours, but findings differed.",
    "F5": "Evidence did not establish consistent improvements in muscle function, later performance or biochemical outcomes.",
    "F6": "Because interventions, participants, doses and outcomes varied, no quantitative meta-analysis was conducted.",
    "F7": "Of 35 randomized studies, 11 had low overall risk of bias and 24 raised some concerns; the nonrandomized study had serious overall risk.",
    "F8": "No particular food intervention, dose or timing can be recommended from the available evidence.",
}

def with_abstract_facts(draft: Mapping[str, object]) -> dict[str, object]:
    """Attach only the fixed, independently cross-checked public fact list."""
    result = dict(draft)
    if result["source_link"] != SOURCE_URL or result["identifiers"]["pmid"] != "42797032":
        raise ValueError("abstract_source_mismatch")
    result["public_abstract_facts"] = dict(ABSTRACT_FACTS)
    result["abstract_source_provenance"] = {
        "url": SOURCE_URL,
        "doi": SOURCE_DOI,
        "scope": "CURATED_PUBLIC_ABSTRACT_PARAPHRASES",
        "full_text_reviewed": False,
        "expert_review": "NOT_RUN",
    }
    return result

def mock_abstract_result(draft: Mapping[str, object]) -> dict[str, object]:
    """Exercise the grounded schema; this is NOT a real model response."""
    unknown = "UNKNOWN"
    return {
        "status": "MANUAL_REVIEW_REQUIRED",
        "study_type": "Систематический обзор 36 интервенционных исследований.",
        "population": "Физически активные люди от 14 лет.",
        "sample_size": unknown,
        "intervention": "Растительные цельные продукты и пищевые добавки на их основе.",
        "control": unknown,
        "main_results": "Уменьшение субъективной болезненности описано в части исследований, но улучшение функции мышц не доказано последовательно.",
        "subjective_outcomes": "В части работ уменьшалась болезненность мышц через 24-72 часа, результаты неоднородны.",
        "objective_outcomes": "Нет устойчиво подтверждённого улучшения функции мышц и последующей работоспособности.",
        "limitations": "Большая неоднородность: метаанализ не проводился; часть исследований имеет риск систематических ошибок.",
        "correction_status": unknown,
        "practical_significance": "Без универсальных рекомендаций по продукту, дозе или времени приёма.",
        "uncertainty": "high",
        "identifiers": dict(draft["identifiers"]),
        "primary_sources": [draft["source_link"]],
        "evidence_basis": EVIDENCE_BASIS,
        "field_evidence": {
            "study_type": ["F1"],
            "population": ["F2"],
            "intervention": ["F3"],
            "main_results": ["F4","F5"],
            "subjective_outcomes": ["F4"],
            "objective_outcomes": ["F5"],
            "limitations": ["F6","F7"],
            "practical_significance": ["F8"],
        },
    }
