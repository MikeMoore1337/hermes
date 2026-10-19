"""Bounded, offline SEO evidence packet for Hermes #64.

Compose *existing* Research Scout and Statejnik gap outputs. This module has
no HTTP, subprocess, CMS, YFC or filesystem write capability. An owner export
is an attestation, never cryptographic/provider verification of statistics.
"""
from __future__ import annotations

import json
import math
import re
from datetime import date
from typing import Any
from urllib.parse import urlsplit

from marketing.seo_brief import ContentBriefError, THEMES, from_daily_item

INPUT_SCHEMA = "hermes-h12-seo-offline-input-v1"
OUTPUT_SCHEMA = "hermes-h12-seo-research-packet-v1"
SOURCES = {
    "google_search_console": frozenset({"impressions", "clicks", "ctr", "average_position"}),
    "yandex_webmaster": frozenset({"impressions", "clicks", "ctr", "average_position"}),
    "yandex_wordstat": frozenset({"search_volume"}),
}
COMMON = frozenset({
    "source", "source_type", "observed_at", "period_start", "period_end",
    "query", "page", "country", "language", "search_intent", "limitations",
    "evidence_sha256", "owner_attested",
})
INTENTS = frozenset({"informational", "navigational", "commercial", "transactional"})
SAFE = re.compile(r"^[^<>{}|\x00-\x1f\x7f" + re.escape(r"\`") + r"]+$")
SHA = re.compile(r"^[0-9a-f]{64}$")
COUNTRY = re.compile(r"^[A-Z]{2}$")
LANGUAGE = re.compile(r"^[a-z]{2}(?:-[A-Z]{2})?$")
MAX_OBSERVATIONS = 50
STALE_DAYS = 90


class SeoResearchDenied(ValueError):
    """Only stable error codes: never echo untrusted input in diagnostics."""


def _text(value: object, limit: int = 180) -> str:
    if type(value) is not str or not 1 <= len(value) <= limit or not SAFE.fullmatch(value):
        raise SeoResearchDenied("text_invalid")
    return value


def _day(value: object) -> date:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise SeoResearchDenied("date_invalid")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise SeoResearchDenied("date_invalid") from None


def _public_url(value: object) -> str:
    value = _text(value, 300)
    try:
        p = urlsplit(value)
        host = p.hostname or ""
        if (p.scheme != "https" or not host or p.username is not None
                or p.password is not None or p.port not in (None, 443)
                or p.fragment or host in {"localhost", "0.0.0.0"}
                or host.endswith((".localhost", ".local", ".internal"))
                or not re.fullmatch(r"[a-zA-Z0-9.-]+", host)
                or "." not in host):
            raise SeoResearchDenied("url_invalid")
    except ValueError:
        raise SeoResearchDenied("url_invalid") from None
    return value


def _number(value: object, *, integer: bool = False) -> float | int:
    if integer:
        if type(value) is not int or value < 0:
            raise SeoResearchDenied("metric_invalid")
    elif type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise SeoResearchDenied("metric_invalid")
    return value


def normalize_observations(values: object, *, as_of: date) -> list[dict[str, Any]]:
    """Retain source-specific, non-additive metrics and honest provenance."""
    if type(values) is not list or len(values) > MAX_OBSERVATIONS:
        raise SeoResearchDenied("observations_invalid")
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for record in values:
        if type(record) is not dict:
            raise SeoResearchDenied("observation_invalid")
        source = record.get("source")
        if type(source) is not str or source not in SOURCES:
            raise SeoResearchDenied("source_not_admitted")
        if set(record) - COMMON - SOURCES[source]:
            raise SeoResearchDenied("observation_fields_invalid")
        kind = record.get("source_type")
        if kind not in ("synthetic_fixture", "owner_export"):
            raise SeoResearchDenied("source_type_invalid")
        observed = _day(record.get("observed_at"))
        start = _day(record.get("period_start"))
        end = _day(record.get("period_end"))
        if not start <= end <= observed <= as_of:
            raise SeoResearchDenied("period_invalid")
        query = _text(record.get("query"), 120)
        intent = record.get("search_intent")
        if intent not in INTENTS:
            raise SeoResearchDenied("intent_invalid")
        country = record.get("country")
        language = record.get("language")
        if country is not None and (type(country) is not str or not COUNTRY.fullmatch(country)):
            raise SeoResearchDenied("country_invalid")
        if language is not None and (type(language) is not str or not LANGUAGE.fullmatch(language)):
            raise SeoResearchDenied("language_invalid")
        page = _public_url(record["page"]) if "page" in record else None
        limits = _text(record.get("limitations"), 350)
        digest = record.get("evidence_sha256")
        attested = record.get("owner_attested", False)
        if type(attested) is not bool:
            raise SeoResearchDenied("attestation_invalid")
        if kind == "owner_export":
            if type(digest) is not str or not SHA.fullmatch(digest):
                raise SeoResearchDenied("evidence_digest_required")
        elif digest is not None or attested:
            raise SeoResearchDenied("fixture_provenance_invalid")
        provided = SOURCES[source].intersection(record)
        if not provided:
            raise SeoResearchDenied("metric_missing")
        metrics: dict[str, int | float] = {}
        for key in sorted(provided):
            val = record[key]
            if key in {"clicks", "impressions", "search_volume"}:
                metrics[key] = _number(val, integer=True)
            else:
                metrics[key] = _number(val)
        if "ctr" in metrics and metrics["ctr"] > 1:
            raise SeoResearchDenied("metric_invalid")
        if "average_position" in metrics and metrics["average_position"] <= 0:
            raise SeoResearchDenied("metric_invalid")
        if metrics.get("clicks", 0) > metrics.get("impressions", 0):
            raise SeoResearchDenied("metric_inconsistent")
        if "ctr" in metrics and "impressions" in metrics and "clicks" in metrics:
            expected = metrics["clicks"] / metrics["impressions"] if metrics["impressions"] else 0
            if abs(metrics["ctr"] - expected) > 0.01:
                raise SeoResearchDenied("metric_inconsistent")
        key = (source, kind, str(start), str(end), query.casefold(), str(page), str(country))
        if key in seen:
            raise SeoResearchDenied("duplicate_observation")
        seen.add(key)
        results.append({
            "source": source,
            "source_type": kind,
            "observed_at": str(observed),
            "period_start": str(start),
            "period_end": str(end),
            "query": query,
            "search_intent": intent,
            "page": page,
            "country": country,
            "language": language,
            "metrics": metrics,
            "data_quality": ("SYNTHETIC_TEST_ONLY" if kind == "synthetic_fixture"
                             else "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED" if attested
                             else "OWNER_EXPORT_UNVERIFIED"),
            "evidence_sha256": digest,
            "limitations": limits,
            "stale": (as_of - end).days > STALE_DAYS,
        })
    return results


def _gap_row(gap: object, query: str) -> dict[str, Any]:
    if type(gap) is not dict or set(gap) - {"site", "threshold", "pages", "clusters", "commercial"}:
        raise SeoResearchDenied("gap_invalid")
    _public_url(gap.get("site"))
    clusters = gap.get("clusters")
    if type(clusters) is not list or len(clusters) > 100:
        raise SeoResearchDenied("gap_invalid")
    matches = [x for x in clusters if type(x) is dict and x.get("cluster") == query]
    if len(matches) != 1:
        raise SeoResearchDenied("gap_cluster_missing_or_duplicate")
    row = matches[0]
    phrases = row.get("phrases")
    if type(phrases) is not list or not 1 <= len(phrases) <= 12:
        raise SeoResearchDenied("gap_invalid")
    for phrase in phrases:
        _text(phrase, 120)
    if row.get("volume") is not None:
        raise SeoResearchDenied("gap_unverified_volume_denied")
    if type(row.get("maybe_covered")) is not bool:
        raise SeoResearchDenied("gap_invalid")
    covered = _public_url(row["covered_by"]) if row.get("covered_by") else None
    nearest = row.get("nearest")
    nearest_url = None
    if nearest is not None:
        if type(nearest) is not dict:
            raise SeoResearchDenied("gap_invalid")
        nearest_url = _public_url(nearest.get("url"))
    return {"cluster": query, "phrases": phrases, "covered_by": covered,
            "maybe_covered": row["maybe_covered"], "nearest_url": nearest_url,
            "method": "STATEJNIK_OFFLINE_HEURISTIC_NOT_SEO_PROOF"}


def build_packet(payload: object) -> dict[str, Any]:
    """Construct one *non-publishable* evidence packet from existing outputs."""
    if type(payload) is not dict or set(payload) != {
        "schema", "theme", "research_item", "site_gap", "observations",
        "selected_query", "as_of"
    } or payload["schema"] != INPUT_SCHEMA:
        raise SeoResearchDenied("input_schema_invalid")
    theme = payload["theme"]
    if type(theme) is not str or theme not in THEMES:
        raise SeoResearchDenied("theme_invalid")
    query = _text(payload["selected_query"], 120)
    as_of = _day(payload["as_of"])
    try:
        science = from_daily_item(payload["research_item"], theme=theme)
    except ContentBriefError:
        raise SeoResearchDenied("research_source_invalid") from None
    gap = _gap_row(payload["site_gap"], query)
    observations = normalize_observations(payload["observations"], as_of=as_of)
    matching = [v for v in observations if v["query"].casefold() ==
                query.casefold() and query.casefold() in
                {p.casefold() for p in gap["phrases"]}]
    fresh = [v for v in matching if not v["stale"] and
             v["data_quality"] in {"SYNTHETIC_TEST_ONLY",
                                   "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED"}]
    positive = [v for v in fresh if v["metrics"].get("impressions", 0) > 0
                or v["metrics"].get("search_volume", 0) > 0]
    reasons: list[str] = []
    if science["status"] == "HOLD":
        reasons.append("SCIENTIFIC_HOLD")
    if gap["covered_by"] or gap["maybe_covered"]:
        reasons.append("EXISTING_PAGE_REQUIRES_EDITORIAL_COMPARISON")
    if not positive:
        reasons.append("NO_FRESH_ATTESTED_SEARCH_DEMAND")
    if len({v["search_intent"] for v in matching}) > 1:
        reasons.append("CONFLICTING_SEARCH_INTENT")
    status = ("HOLD" if "SCIENTIFIC_HOLD" in reasons or
              "EXISTING_PAGE_REQUIRES_EDITORIAL_COMPARISON" in reasons or
              "CONFLICTING_SEARCH_INTENT" in reasons else
              "NO_DATA" if not positive else "READY_FOR_REVIEW")
    packet: dict[str, Any] = {
        "schema": OUTPUT_SCHEMA,
        "status": status,
        "reasons": reasons,
        "as_of": str(as_of),
        "theme": theme,
        "selected_query": query,
        "search_intent": matching[0]["search_intent"] if matching and
                         "CONFLICTING_SEARCH_INTENT" not in reasons else "NEEDS_REVIEW",
        "observations": matching,
        "evidence_kind": ("SYNTHETIC_ONLY" if positive and
                          all(x["source_type"] == "synthetic_fixture" for x in positive)
                          else "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED" if positive
                          else "NO_CONFIRMED_DEMAND"),
        "search_metrics_combined": False,
        "site_gap": gap,
        "research_brief": science,
        "editorial": {
            "working_h1": science["proposed_working_title"],
            "h2": ["Что можно проверить по первоисточникам",
                   "Ограничения исследования", "Вопросы читателей"],
            "questions": [science["proposed_question"]],
            "suggested_internal_links": ([gap["nearest_url"]]
                                         if gap["nearest_url"] else []),
            "proposed_scientific_claims": [],
            "requires_expert_review": True,
            "requires_yfc_owner_ready": True,
        },
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "outbound_messages_allowed": False,
        "live_api_used": False,
        "paid_api_used": False,
    }
    packet["markdown"] = render_markdown(packet)
    return packet


def render_markdown(packet: dict[str, Any]) -> str:
    """Plain text editorial brief, using only validated source fields."""
    gap = packet["site_gap"]
    science = packet["research_brief"]
    lines = [
        "# SEO-исследование - черновик для редактора",
        "",
        "Тема: " + packet["selected_query"],
        "Статус: " + packet["status"],
        "Тип данных: " + packet["evidence_kind"],
        "Поисковое намерение: " + packet["search_intent"],
        "Существующая страница: " + (gap["covered_by"] or "NO_DATA"),
        "Ближайшая страница: " + (gap["nearest_url"] or "NO_DATA"),
        "Метод проверки покрытия: " + gap["method"],
        "",
        "## Источники поискового спроса",
    ]
    if not packet["observations"]:
        lines.append("NO_DATA - поисковые наблюдения отсутствуют.")
    for v in packet["observations"]:
        lines.append(
            "- " + v["source"] + " / " + v["source_type"] +
            " / " + v["period_start"] + "..." + v["period_end"] +
            " / quality=" + v["data_quality"] + " / " +
            json.dumps(v["metrics"], ensure_ascii=False, sort_keys=True) +
            " / ограничения: " + v["limitations"]
        )
    lines += [
        "",
        "## Редакционное предложение",
        "H1: " + packet["editorial"]["working_h1"],
        *["H2: " + x for x in packet["editorial"]["h2"]],
        "Вопрос читателя: " + science["proposed_question"],
        "Связанный первоисточник: " + science["research_provenance"]["source_url"],
        "Научный статус: " + science["status"],
        "Проверка научных утверждений: требуется экспертная оценка.",
        "YFC owner READY: обязателен до любой публикации.",
        "Автопубликация и запись в YFC: запрещены.",
        "",
        "## Основания ограничения",
        *(packet["reasons"] or ["Ожидается ручная редакционная проверка."]),
    ]
    return "\n".join(lines) + "\n"
