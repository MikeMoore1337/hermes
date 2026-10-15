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

# Public abstract paraphrases; correction entry is cross-checked against the
# separately published Springer erratum (NOT inferred from the abstract).
OTHER_ABSTRACTS: dict[str, dict[str, object]] = {
    "42840492": {
        "url": "https://pubmed.ncbi.nlm.nih.gov/42840492/",
        "doi": "10.3389/fcimb.2026.1918695",
        "facts": {
            "F1": "The publication is a review of whey protein, resistance training and microbiota-mediated gut-brain communication, not a new combined clinical trial.",
            "F2": "It synthesizes preclinical and clinical studies and mechanistic hypotheses about microbes, gut hormones and short-chain fatty acids.",
            "F3": "Direct evidence for combined whey protein and resistance training interventions on cognition remains limited.",
            "F4": "Microbiota-derived metabolites and gut hormones are proposed links, not fully confirmed causal mechanisms for humans.",
            "F5": "Findings vary with whey dosage, exercise protocol, duration, population and personal microbiome differences.",
            "F6": "More direct well-designed human studies assessing the gut microbiome, gut-brain signaling and cognition are needed.",
        },
        "sample_size": "UNKNOWN",
        "correction_status": "UNKNOWN",
        "fields": {
            "study_type": ("Обзор преимущественно механистических и разнородных данных.", ["F1"]),
            "intervention": ("Сывороточный белок и силовые тренировки обсуждаются как возможное сочетание.", ["F1"]),
            "main_results": ("Возможны механизмы влияния через микробиоту; прямые данные о когнитивном эффекте сочетания ограничены.", ["F3","F4"]),
            "limitations": ("Прямые данные для совместного применения ограничены, исследования неоднородны.", ["F3","F5"]),
            "practical_significance": ("Нельзя заявлять подтверждённое улучшение памяти или когнитивной функции.", ["F3","F6"]),
        },
    },
    "42771055": {
        "url": "https://pubmed.ncbi.nlm.nih.gov/42771055/",
        "doi": "10.1007/s00520-026-11251-3",
        "correction_url": "https://link.springer.com/article/10.1007/s00520-026-11294-6",
        "facts": {
            "F1": "An observational descriptive IRONMAN registry analysis concerns advanced prostate cancer; participation was measured, not randomized to exercise.",
            "F2": "The reported registry analysis included 2485 participants.",
            "F3": "Aerobic guidelines used at least 150 minutes per week and resistance training guidelines at least twice weekly.",
            "F4": "Across timepoints about 58-63% met aerobic guidelines and 19-23% met strength training guidelines.",
            "F5": "Regional and racial differences were observed; observational associations do not prove interventions improve cancer outcomes.",
            "F6": "Publisher issued a separately documented correction on 2026-10-02 to the reported median duration of moderate activity.",
            "F7": "The corrected median is about 150 minutes per week, replacing the erroneous 50 minutes per week in descriptive results.",
            "F8": "The publisher explicitly states this correction does not affect the analyses, interpretation or conclusions.",
        },
        "sample_size": "2485",
        "correction_status": "CORRECTION_REPORTED_50_TO_150_MIN_PER_WEEK",
        "fields": {
            "study_type": ("Наблюдательное описательное исследование регистра, не РКИ.", ["F1"]),
            "population": ("2485 участников регистра IRONMAN с распространённым раком простаты.", ["F1","F2"]),
            "sample_size": ("2485", ["F2"]),
            "main_results": ("Доля соответствия аэробным рекомендациям 58–63%, силовым 19–23%; это участие, а не лечебный эффект.", ["F4","F5"]),
            "limitations": ("Наблюдательная оценка не доказывает причинность или эффективность тренировочного лечения.", ["F1","F5"]),
            "correction_status": ("CORRECTION_REPORTED_50_TO_150_MIN_PER_WEEK", ["F6","F7","F8"]),
            "practical_significance": ("Не переносить наблюдательную статистику пациентов на доказанные результаты лечения.", ["F1","F5"]),
        },
    },
    "42733310": {
        "url": "https://pubmed.ncbi.nlm.nih.gov/42733310/",
        "doi": "10.1002/ejsc.70246",
        "facts": {
            "F1": "The study was a randomized single-blind sham-controlled crossover clinical trial in athletes.",
            "F2": "It enrolled 25 athletes.",
            "F3": "After a Wingate anaerobic effort the participants received massage plus active CRET or massage plus sham CRET.",
            "F4": "Lactate levels at 60 min post-exercise were lower with active CRET, reported p = 0.029.",
            "F5": "Ultrasound muscle thickness and echogenicity differed at some time points, with p < 0.05.",
            "F6": "Wingate performance, knee extension force, muscle activity and oxygenation showed no significant between-condition improvement.",
            "F7": "These changes did not establish a clear short-term functional recovery benefit.",
        },
        "sample_size": "25",
        "correction_status": "UNKNOWN",
        "fields": {
            "study_type": ("Рандомизированное слепое перекрёстное исследование с имитацией процедуры.", ["F1"]),
            "population": ("25 спортсменов.", ["F2"]),
            "sample_size": ("25", ["F2"]),
            "intervention": ("Массаж плюс активная CRET.", ["F3"]),
            "control": ("Массаж плюс фиктивная CRET.", ["F3"]),
            "main_results": ("Лактат и отдельные УЗ-показатели различались, но функциональное восстановление не было убедительно улучшено.", ["F4","F5","F6","F7"]),
            "objective_outcomes": ("Нет значимых различий по мощности, силе, мышечной активности и оксигенации между условиями.", ["F6"]),
            "limitations": ("Малая выборка и различия биомаркеров не доказывают улучшение функции.", ["F2","F7"]),
            "practical_significance": ("Нельзя рекомендовать CRET как доказанно ускоряющую функциональное восстановление.", ["F6","F7"]),
        },
    },
}

def with_abstract_facts(draft: Mapping[str, object]) -> dict[str, object]:
    """Attach only the fixed, independently cross-checked public fact list."""
    result = dict(draft)
    pmid = result["identifiers"]["pmid"]
    if pmid == "42797032":
        case: dict[str, object] = {
            "url": SOURCE_URL, "doi": SOURCE_DOI, "facts": ABSTRACT_FACTS,
            "sample_size": "UNKNOWN", "correction_status": "UNKNOWN",
        }
    else:
        case = OTHER_ABSTRACTS.get(pmid, {})
    if not case or result["source_link"] != case["url"] or (
            result["identifiers"]["doi"] != case["doi"]):
        raise ValueError("abstract_source_mismatch")
    result["public_abstract_facts"] = dict(case["facts"])
    result["abstract_source_provenance"] = {
        "url": case["url"],
        "doi": case["doi"],
        "correction_url": case.get("correction_url", "UNKNOWN"),
        "scope": "CURATED_PUBLIC_ABSTRACT_PARAPHRASES",
        "full_text_reviewed": False,
        "expert_review": "NOT_RUN",
        "expected_sample_size": case["sample_size"],
        "expected_correction_status": case["correction_status"],
        "sample_size_citations": ["F2"] if case["sample_size"] != "UNKNOWN" else [],
        "correction_citations": ["F6", "F7", "F8"] if pmid == "42771055" else [],
    }
    return result

def mock_abstract_result(draft: Mapping[str, object]) -> dict[str, object]:
    """Exercise the grounded schema; this is NOT a real model response."""
    unknown = "UNKNOWN"
    pmid = draft["identifiers"]["pmid"]
    if pmid in OTHER_ABSTRACTS:
        case = OTHER_ABSTRACTS[pmid]
        fields = case["fields"]
        values = {
            "study_type": unknown, "population": unknown,
            "sample_size": unknown, "intervention": unknown,
            "control": unknown, "main_results": unknown,
            "subjective_outcomes": unknown, "objective_outcomes": unknown,
            "limitations": unknown, "correction_status": unknown,
            "practical_significance": unknown,
        }
        values.update({name: content for name, (content, _) in fields.items()})
        return {
            "status": "MANUAL_REVIEW_REQUIRED",
            **values,
            "uncertainty": "high",
            "identifiers": dict(draft["identifiers"]),
            "primary_sources": [draft["source_link"]],
            "evidence_basis": EVIDENCE_BASIS,
            "field_evidence": {
                name: list(facts) for name, (_, facts) in fields.items()
            },
        }
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
