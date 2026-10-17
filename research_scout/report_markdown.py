"""Read-only Russian Markdown view of the existing Research Scout packet.

No network calls, external publication, model inference or disk writes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .daily_digest import SCHEMA, TOPIC_IDS
from .review_draft import ReviewDraftError, build_daily_item_draft

MAX_INPUT_BYTES = 65_536


class ReportError(ValueError):
    """Do not expose original third-party payload on validation failure."""


def _safe_text(value: object) -> str:
    if value is None or value == "UNKNOWN":
        return "Не установлено"
    if type(value) is not str or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ReportError("field_invalid")
    return (value.replace("\\", "\\\\").replace("[", "\\[")
            .replace("]", "\\]").replace("<", "&lt;")
            .replace(">", "&gt;").replace("*", "\\*")
            .replace("`", "\\`").replace("|", "\\|"))


def render(packet: Any) -> str:
    if (type(packet) is not dict or packet.get("schema") != SCHEMA
            or packet.get("scientific_claims_verified") is not False
            or packet.get("automatic_publication") is not False
            or packet.get("report_requires_manual_review") is not True
            or packet.get("status") not in {"HOLD", "MANUAL_REVIEW", "NO_DATA"}
            or packet.get("topics") != list(TOPIC_IDS)
            or type(packet.get("requests_attempted")) is not int
            or not 3 <= packet["requests_attempted"] <= 5
            or type(packet.get("items")) is not list
            or len(packet["items"]) > 6
            or type(packet.get("errors")) is not list
            or len(packet["errors"]) > 4):
        raise ReportError("packet_invalid")
    if any(type(item) is not dict for item in packet["items"]):
        raise ReportError("item_invalid")
    expected = ("HOLD" if packet["errors"] or any(
        i.get("status") == "HOLD" for i in packet["items"])
        else "MANUAL_REVIEW" if packet["items"] else "NO_DATA")
    if packet["status"] != expected:
        raise ReportError("aggregate_status_invalid")

    lines = [
        "# Hermes Research Scout - библиографический обзор", "",
        f"**Дата сбора:** {_safe_text(packet.get('observed_at'))}",
        f"**Состояние:** {packet['status']}",
        f"**Запросов:** {packet['requests_attempted']}", "",
        "> Этот документ не является научной экспертизой или медицинской рекомендацией.",
        "> Ни одна публикация не прошла независимую проверку научных выводов.", "",
    ]
    groups: dict[str, list[dict[str, Any]]] = {
        "Ожидают научной проверки": [],
        "Исправления / отзыв / неопределённый статус уведомлений": [],
        "Недостаточно данных": [],
    }
    seen: set[tuple[str, str]] = set()
    for item in packet["items"]:
        try:
            draft = build_daily_item_draft(item)
        except (ReviewDraftError, TypeError, KeyError) as exc:
            raise ReportError("item_invalid") from exc
        ids = draft["identifiers"]
        identity = (ids["record_id"], ids["doi"])
        if identity in seen:
            continue
        seen.add(identity)
        notice = item["article_notice_state"]
        group = ("Исправления / отзыв / неопределённый статус уведомлений"
                 if notice in {"REVIEW_REQUIRED", "UNAVAILABLE"}
                 else "Недостаточно данных" if item["status"] == "HOLD"
                 else "Ожидают научной проверки")
        groups[group].append(draft)

    for label, drafts in groups.items():
        lines.extend([f"## {label} ({len(drafts)})", ""])
        for d in drafts:
            lines.extend([f"### {_safe_text(d['title'])}", ""])
            for name, value in [
                ("Источник", d["source_link"]),
                ("Дата публикации", d["publication_date"]),
                ("DOI", d["identifiers"]["doi"]),
                ("PMID", d["identifiers"]["pmid"]),
                ("Тип исследования", d["study_type"]),
                ("Выборка", d["sample_size"]),
                ("Главный результат", d["main_results"]),
                ("Ограничения", d["limitations"]),
                ("Исправления", d["correction_status"]),
                ("Статус", d["status"]),
            ]:
                lines.append(f"- **{name}:** {_safe_text(value)}")
            lines.extend([
                "- **Подтверждено:** библиографическая запись в указанном источнике.",
                "- **Не подтверждено:** эффект, причинность и практические рекомендации.",
                "- **Применимость:** требует проверки полного текста специалистом.", "",
            ])
    lines.extend([
        "## Проверенные научные материалы (0)", "",
        "Независимая экспертиза в метаданных не представлена.", "",
    ])
    if packet["errors"]:
        lines.extend(["## Ошибки источников", "",
                      f"Количество ошибок: {len(packet['errors'])}.", ""])
    return "\n".join(lines)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, value in pairs:
        if key in record:
            raise ReportError("duplicate_json_key")
        record[key] = value
    return record


def _reject_constant(_: str) -> Any:
    raise ReportError("nonfinite_json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline readable Research Scout report")
    parser.add_argument("--stdin", action="store_true")
    args = parser.parse_args(argv)
    if not args.stdin:
        print("REJECTED: explicit_stdin_required", file=sys.stderr)
        return 2
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ReportError("input_too_large")
        data = json.loads(payload, object_pairs_hook=_unique_keys,
                          parse_constant=_reject_constant)
        print(render(data))
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        print("REJECTED: invalid_packet", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
