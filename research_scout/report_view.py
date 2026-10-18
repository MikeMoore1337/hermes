"""Offline, source-bound Research Scout read model for the owner Control Center.

Reads the EXISTING root-owned daily packet. No network, new service, LLM,
scientific verification or publication. Curated abstracts are editorial aids,
never independently verified full-text reviews.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .abstract_quality import ABSTRACT_FACTS, OTHER_ABSTRACTS, SOURCE_DOI, SOURCE_URL
from .daily_digest import SCHEMA as PACKET_SCHEMA, MAX_OUTPUT, TOPIC_IDS
from .review_draft import ReviewDraftError, build_daily_item_draft

PACKET = Path("/var/lib/hermes-research-scout/latest-citations.json")
REPORT_SCHEMA = "hermes-research-owner-view-v1"

# Bibliography checked against PubMed 2026-10-17. These fields are not
# inferred from a generated model answer or the daily lite search results.
CASE_METADATA = (
    ("42840492", "Сывороточный протеин, силовые тренировки и ось кишечник-мозг",
     "Frontiers in Cellular and Infection Microbiology", "2026-09-22",
     "Нарративный обзор", "UNKNOWN", "MANUAL_REVIEW"),
    ("42771055", "Активность при распространённом раке простаты: регистр IRONMAN",
     "Supportive Care in Cancer", "2026-09-22",
     "Наблюдательное исследование", "2485", "HOLD"),
    ("42797032", "Растительные продукты и восстановление после нагрузок",
     "Nutrients", "2026-09-18", "Систематический обзор, 36 исследований",
     "UNKNOWN", "MANUAL_REVIEW"),
    ("42733310", "Массаж с CRET и восстановление спортсменов",
     "European Journal of Sport Science", "2026-10",
     "Рандомизированное перекрёстное исследование", "25", "MANUAL_REVIEW"),
)

# Deliberately limited to what is grounded in the curated public abstracts.
EXPLANATIONS = {
    "42840492": {
        "question": "Возможные связи сывороточного белка, силовых тренировок, микробиоты и когнитивной функции",
        "design": "Обзор доклинических и клинических данных; не испытание сочетания вмешательств",
        "comparison": "Не единое контролируемое сравнение",
        "finding": "Биологические механизмы правдоподобны; прямых данных об улучшении когнитивных показателей при сочетании недостаточно",
        "limits": "Разные дозы, упражнения, популяции и исходы; причинность не установлена",
        "application": "Не обосновывает обещаний когнитивного эффекта в YFC",
        "confirmed": "Обзор обсуждает механизмы и нехватку прямых исследований",
        "unconfirmed": "Улучшение памяти, причинный эффект и оптимальная доза",
        "ids": ["F1", "F3", "F4", "F5", "F6"],
    },
    "42771055": {
        "question": "Какая доля пациентов с распространённым раком простаты выполняет рекомендации по активности",
        "design": "Анализ наблюдательного международного регистра IRONMAN, без рандомизации активности",
        "comparison": "Группы по региону и самоидентифицированной расе, по данным наблюдения",
        "finding": "58-63% соответствовали аэробным рекомендациям, 19-23% - силовым; исправленная медиана умеренной активности около 150 минут в неделю",
        "limits": "Самоотчёт; 2485 из 4538 участников предоставили данные активности, различия между ответившими и остальными; частота силовых занятий выведена косвенно из минут (15 минут за сессию). Вывод о причинной эффективности лечения невозможен",
        "application": "Статистика участия в активности, не доказательство эффективности лечения",
        "confirmed": "N=2485, наблюдательный характер; отдельно опубликовано исправление 50 на 150 минут",
        "unconfirmed": "Эффективность тренировок для онкологических исходов",
        "ids": ["F1", "F2", "F4", "F5", "F6", "F7", "F8"],
    },
    "42797032": {
        "question": "Связаны ли растительные продукты со снижением болезненности и восстановлением функции после нагрузки",
        "design": "Систематический обзор 36 интервенционных исследований, не единое РКИ",
        "comparison": "Разные продукты и дозы в исследованиях с неоднородными группами сравнения",
        "finding": "В части исследований меньше субъективная болезненность в пределах 24-72 часов; устойчивое улучшение функции не установлено",
        "limits": "Высокая неоднородность; метаанализ не проводился; 24 из 35 РКИ имели некоторые сомнения по риску смещения",
        "application": "Нет оснований рекомендовать универсальные продукт, дозу или время употребления",
        "confirmed": "36 исследований; часть положительных результатов по субъективной болезненности",
        "unconfirmed": "Универсальное улучшение работоспособности и конкретная эффективная доза",
        "ids": ["F1", "F4", "F5", "F6", "F7", "F8"],
    },
    "42733310": {
        "question": "Добавляет ли активная CRET пользу к массажу после анаэробной нагрузки",
        "design": "Рандомизированное односторонне слепое sham-контролируемое перекрёстное исследование",
        "comparison": "Массаж + активная CRET против массажа + имитация CRET",
        "finding": "Лактат через 60 минут ниже (p=0,029), отдельные УЗ-маркеры отличались; улучшение силы или мощности не показано",
        "limits": "25 спортсменов, кратковременные показатели; суррогатные маркеры не равны функциональной пользе",
        "application": "Недостаточно для рекомендации CRET ради ускорения восстановления функции",
        "confirmed": "Сравнение активной и имитированной CRET, различие по лактату",
        "unconfirmed": "Улучшение силы, мощности и спортивных результатов",
        "ids": ["F1", "F2", "F3", "F4", "F6", "F7"],
    },
}


# Human-curated *field-level* source pointers. A link to the publication in
# general is not evidence for every individual scientific assertion.
# In particular IRONMAN's amended 150-minute figure comes from the separate
# Springer notice rather than the original uncorrected abstract.
FIELD_FACT_IDS: dict[str, dict[str, tuple[str, ...]]] = {
    "42840492": {
        "question": ("F1",), "design": ("F1", "F2"),
        "comparison": ("F1",), "finding": ("F3", "F4"),
        "limits": ("F3", "F5"), "application": ("F3", "F6"),
        "confirmed": ("F1", "F3"), "unconfirmed": ("F3", "F6"),
    },
    "42771055": {
        "question": ("F1",), "design": ("F1",),
        "comparison": ("F1", "F5"), "finding": ("F4", "F7"),
        "limits": ("F1", "F5"), "application": ("F1", "F5"),
        "confirmed": ("F2", "F6", "F7", "F8"),
        "unconfirmed": ("F1", "F5"),
    },
    "42797032": {
        "question": ("F1",), "design": ("F1",),
        "comparison": ("F3",), "finding": ("F4", "F5"),
        "limits": ("F6", "F7"), "application": ("F8",),
        "confirmed": ("F1", "F4"), "unconfirmed": ("F5", "F8"),
    },
    "42733310": {
        "question": ("F3",), "design": ("F1",),
        "comparison": ("F3",), "finding": ("F4", "F5", "F6", "F7"),
        "limits": ("F2", "F7"), "application": ("F6", "F7"),
        "confirmed": ("F1", "F4"), "unconfirmed": ("F6", "F7"),
    },
}
CORRECTION_FACT_IDS = frozenset({"F6", "F7", "F8"})
IRONMAN_CORRECTION_URL = "https://link.springer.com/article/10.1007/s00520-026-11294-6"
IRONMAN_CORRECTION_DOI = "10.1007/s00520-026-11294-6"
IRONMAN_ORIGINAL_URL = "https://link.springer.com/article/10.1007/s00520-026-11251-3"
# Exactly two additional limitations observed in the publisher's Methods and
# Results. Not an expert risk-of-bias assessment of the full study or dataset.
IRONMAN_PUBLISHER_METHOD_FACTS = {
    "P1": (
        "Of 4538 IRONMAN registry participants, 2485 answered at least one "
        "activity questionnaire; responders differed from nonresponders "
        "in baseline characteristics.",
        "Results / participant flow",
    ),
    "P2": (
        "Resistance training frequency was not recorded directly by the "
        "questionnaire; the authors approximated weekly sessions using "
        "a threshold of 15 minutes per session.",
        "Measurements and procedures / physical activity levels",
    ),
}


def _ironman_method_reference(
    pmid: str, article_doi: str, fact_id: str,
) -> dict[str, object]:
    if pmid != "42771055" or fact_id not in IRONMAN_PUBLISHER_METHOD_FACTS:
        raise ValueError("publisher_method_source_not_allowlisted")
    summary, section = IRONMAN_PUBLISHER_METHOD_FACTS[fact_id]
    return {
        "id": fact_id, "pmid": pmid, "doi": article_doi,
        "source_doi": article_doi,
        "source_type": "PUBLISHER_FULL_TEXT_SECTION",
        "source_url": IRONMAN_ORIGINAL_URL,
        "source_section": section,
        "supporting_paraphrase": summary,
        "evidence_completeness": "SELECTED_FULL_TEXT_SECTION_ONLY",
        "review_status": "NEEDS_EXPERT_REVIEW",
        "scientifically_approved": False,
    }



def _fact_reference(pmid: str, doi: str, fact_id: str, fact: str,
                    abstract_url: str) -> dict[str, object]:
    corrected = pmid == "42771055" and fact_id in CORRECTION_FACT_IDS
    return {
        "id": fact_id, "pmid": pmid, "doi": doi,
        # Keep the historical "doi" field as the original *article* DOI;
        # source_doi uniquely identifies the supporting document. A notice
        # is a separate publication with its own DOI.
        "source_doi": IRONMAN_CORRECTION_DOI if corrected else doi,
        "source_type": "PUBLISHER_CORRECTION" if corrected else "CURATED_PUBLIC_ABSTRACT",
        "source_url": IRONMAN_CORRECTION_URL if corrected else abstract_url,
        "supporting_paraphrase": fact,
        "evidence_completeness": "CORRECTION_NOTICE" if corrected else "ABSTRACT_ONLY",
        "review_status": "NEEDS_EXPERT_REVIEW",
        "scientifically_approved": False,
    }


def _field_evidence(pmid: str, doi: str, url: str,
                    facts: dict[str, str]) -> dict[str, list[dict[str, object]]]:
    """Require individually linked, correctly scoped curated facts per field.

    Structural provenance is NOT an automated judgement of scientific truth.
    """
    mapping = FIELD_FACT_IDS[pmid]
    expected = set(EXPLANATIONS[pmid]) - {"ids"}
    if set(mapping) != expected:
        raise ValueError("curated_fields_without_evidence")
    evidence: dict[str, list[dict[str, object]]] = {}
    for field, ids in mapping.items():
        if not ids or len(ids) != len(set(ids)) or any(fid not in facts for fid in ids):
            raise ValueError("curated_evidence_missing_or_invalid")
        evidence[field] = [
            _fact_reference(pmid, doi, fid, facts[fid], url) for fid in ids
        ]
        if pmid == "42771055" and field == "limits":
            evidence[field] += [
                _ironman_method_reference(pmid, doi, fid)
                for fid in ("P1", "P2")
            ]
    return evidence


def curated_reports() -> list[dict[str, Any]]:
    """Four fixed public-abstract review aids, never a claim of expert approval."""
    records = []
    for pmid, title, journal, published, design, sample, status in CASE_METADATA:
        case = OTHER_ABSTRACTS.get(pmid)
        url = case["url"] if case is not None else SOURCE_URL
        doi = case["doi"] if case is not None else SOURCE_DOI
        facts = case["facts"] if case is not None else ABSTRACT_FACTS
        explanation = EXPLANATIONS[pmid]
        field_evidence = _field_evidence(pmid, doi, url, facts)
        records.append({
            "pmid": pmid, "title": title, "journal": journal,
            "publication_date": published, "doi": doi, "url": url,
            "study_type": design, "sample_size": sample,
            "status": status, "review_status": "NEEDS_EXPERT_REVIEW",
            "evidence_basis": (
                "CURATED_PUBLIC_ABSTRACT_AND_SCOPED_PUBLISHER_NOTES"
                if pmid == "42771055"
                else "CURATED_PUBLIC_ABSTRACT_NOT_FULL_TEXT"
            ),
            "effect_size": "NOT_REPORTED_IN_CURATED_ABSTRACT",
            "statistical_uncertainty": "NOT_ASSESSED_FROM_FULL_TEXT",
            "causal_conclusion": "NOT_ESTABLISHED_BY_THIS_REVIEW",
            "correction_status": (
                "CORRECTION_REPORTED_REVIEW_REQUIRED" if pmid == "42771055"
                else "UNKNOWN_NOT_FULLY_CLEARED"),
            "correction_url": (
                "https://link.springer.com/article/10.1007/s00520-026-11294-6"
                if pmid == "42771055" else None),
            "question": explanation["question"], "design": explanation["design"],
            "comparison": explanation["comparison"],
            "finding": explanation["finding"], "limits": explanation["limits"],
            "application": explanation["application"],
            "confirmed": explanation["confirmed"], "unconfirmed": explanation["unconfirmed"],
            "evidence": [
                {**_fact_reference(pmid, doi, fid, facts[fid], url),
                 "abstract_paraphrase": facts[fid],
                 "url": (IRONMAN_CORRECTION_URL
                         if pmid == "42771055" and fid in CORRECTION_FACT_IDS
                         else url)}
                for fid in explanation["ids"]
            ],
            "field_evidence": field_evidence,
            "claim_coverage": "FIELD_LINKED_CURATED_EVIDENCE_NOT_SEMANTIC_VALIDATION",
            "full_text_reviewed": False,
            "expert_review": "NOT_RUN",
            "checked_at": "2026-10-17",
            "scientific_claims_verified": False,
        })
    return records


def unavailable() -> dict[str, Any]:
    return {"schema": REPORT_SCHEMA, "availability": "UNAVAILABLE",
            "status": "UNKNOWN", "items": [], "errors": "SOURCE_UNAVAILABLE",
            "curated_reports": curated_reports(), "scientific_claims_verified": False}


def project_packet(packet: Any) -> dict[str, Any]:
    """Reject false upgrades and malformed packets before sanitized owner display."""
    if not isinstance(packet, dict) or packet.get("schema") != PACKET_SCHEMA:
        raise ValueError("invalid_packet_schema")
    if (packet.get("scientific_claims_verified") is not False
            or packet.get("automatic_publication") is not False
            or packet.get("report_requires_manual_review") is not True):
        raise ValueError("unsafe_packet")
    moment = datetime.fromisoformat(packet["observed_at"])
    if moment.tzinfo is None or moment.utcoffset().total_seconds() != 0:
        raise ValueError("invalid_packet_time")
    if packet.get("topics") != list(TOPIC_IDS):
        raise ValueError("invalid_topics")
    calls = packet.get("requests_attempted")
    if type(calls) is not int or not 3 <= calls <= 5:
        raise ValueError("invalid_budget")
    items, errors = packet.get("items"), packet.get("errors")
    if (type(items) is not list or len(items) > 6
            or type(errors) is not list or len(errors) > 4):
        raise ValueError("invalid_entries")
    if errors and packet.get("status") != "HOLD":
        raise ValueError("error_state_promoted")
    result = []
    seen = set()
    for item in items:
        draft = build_daily_item_draft(item)
        doi = item["doi"]
        if doi is None and item["status"] != "HOLD":
            raise ValueError("missing_doi_promoted")
        unique = doi.casefold() if doi else item["identifier"]
        if unique in seen and item["status"] != "HOLD":
            raise ValueError("duplicate_promoted")
        seen.add(unique)
        result.append({
            "title": draft["title"],
            "identifier": item["identifier"],
            "source_url": draft["source_link"],
            "publication_date": draft["publication_date"],
            "doi": doi, "status": item["status"], "reason": item["reason"],
            "crossref_doi_status": item["crossref_doi_status"],
            "article_notice_state": item["article_notice_state"],
            "article_notice_codes": item["article_notice_codes"],
            "scientific_claims_verified": False,
        })
    computed = "HOLD" if errors or any(i["status"] == "HOLD" for i in items) else ("MANUAL_REVIEW" if items else "NO_DATA")
    if packet.get("status") != computed:
        raise ValueError("packet_status_promoted")
    return {
        "schema": REPORT_SCHEMA, "availability": "AVAILABLE",
        "status": computed, "observed_at": moment.isoformat(),
        "requests_attempted": calls, "error_count": len(errors),
        "items": result, "curated_reports": curated_reports(),
        "scientific_claims_verified": False,
    }


def read_owner_view(path: Path = PACKET) -> dict[str, Any]:
    """Read only the already-produced local packet (root snapshot collector)."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_OUTPUT:
            return unavailable()
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_OUTPUT:
            return unavailable()
        return project_packet(json.loads(raw))
    except (OSError, ValueError, TypeError, KeyError, ReviewDraftError):
        return unavailable()
