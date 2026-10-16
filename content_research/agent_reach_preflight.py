"""Офлайн-проверка статуса Agent Reach без запуска самого Agent Reach.

Принимает ТОЛЬКО уже полученный оператором JSON от `agent-reach doctor --json`.
Не запускает команды, не делает сетевых запросов, не читает cookies/ключи,
не разрешает извлечение материалов и не изменяет файлы или состояние служб.
"""

from __future__ import annotations

import json
import sys
from typing import Any

SCHEMA = "hermes-agent-reach-preflight-v1"
MAX_INPUT_BYTES = 65_536

# Явно ограниченный список публичных каналов для будущих ручных испытаний.
# Это НЕ список разрешённых сетевых адресов, сервисов или инструментов агента.
CHANNEL_EVIDENCE = {
    "web": "DECLARED_WITHOUT_NETWORK_CHECK",
    "rss": "LOCAL_IMPORT_ONLY",
    "youtube": "LOCAL_TOOL_PROBE_ONLY",
    "github": "LOCAL_TOOL_AUTH_UNVERIFIED",
    "exa_search": "LOCAL_CONFIG_UNVERIFIED",
}
VALID_STATUSES = frozenset({"ok", "warn", "off", "error"})


class PreflightError(ValueError):
    """Отказ с фиксированным кодом, без вывода недоверенного JSON."""


def inspect_report(report: Any) -> dict[str, Any]:
    """Вернуть ограниченный отчёт. Ни один doctor-статус не доказывает чтение URL."""
    if type(report) is not dict or len(report) > 64:
        raise PreflightError("report_invalid")

    channels: list[dict[str, Any]] = []
    for name, evidence in CHANNEL_EVIDENCE.items():
        row = report.get(name)
        if row is None:
            status = "absent"
        else:
            if type(row) is not dict or type(row.get("status")) is not str:
                raise PreflightError("channel_invalid")
            status = row["status"]
            if status not in VALID_STATUSES:
                raise PreflightError("channel_status_invalid")
        readiness = {
            "ok": "LOCAL_CHECK_ONLY",
            "warn": "NEEDS_MANUAL_CONFIGURATION_OR_PROBE",
            "off": "UNAVAILABLE",
            "error": "UNAVAILABLE",
            "absent": "NOT_IN_REPORT",
        }[status]
        channels.append({
            "channel": name,
            "doctor_status": status,
            "evidence": evidence,
            "readiness": readiness,
            "source_read_verified": False,
        })

    return {
        "schema": SCHEMA,
        "channel_count": len(channels),
        "channels": channels,
        "remote_read_verified": False,
        "production_integration_approved": False,
        "publication_allowed": False,
    }


def inspect_json(payload: bytes) -> dict[str, Any]:
    """Обработать не более 64 КиБ и никогда не отразить исходный JSON в ошибке."""
    if type(payload) is not bytes or not payload or len(payload) > MAX_INPUT_BYTES:
        raise PreflightError("input_size_invalid")
    try:
        report = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PreflightError("input_json_invalid") from None
    return inspect_report(report)


def main() -> int:
    """Читать только stdin и выдавать только очищенный JSON в stdout."""
    try:
        result = inspect_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    except PreflightError as exc:
        print(f"agent_reach_preflight: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
