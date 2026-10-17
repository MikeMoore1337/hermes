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
        "limits": "Самоотчёт, возможные смешивающие факторы, без причинного вывода об эффективности лечения",
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


def curated_reports() -> list[dict[str, Any]]:
    """Four fixed public-abstract review aids, never a claim of expert approval."""
    records = []
    for pmid, title, journal, published, design, sample, status in CASE_METADATA:
        case = OTHER_ABSTRACTS.get(pmid)
        url = case["url"] if case is not None else SOURCE_URL
        doi = case["doi"] if case is not None else SOURCE_DOI
        facts = case["facts"] if case is not None else ABSTRACT_FACTS
        explanation = EXPLANATIONS[pmid]
        records.append({
            "pmid": pmid, "title": title, "journal": journal,
            "publication_date": published, "doi": doi, "url": url,
            "study_type": design, "sample_size": sample,
            "status": status, "review_status": "NEEDS_EXPERT_REVIEW",
            "evidence_basis": "CURATED_PUBLIC_ABSTRACT_NOT_FULL_TEXT",
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
                {"id": fid, "abstract_paraphrase": facts[fid], "url": url}
                for fid in explanation["ids"]
            ],
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
