"""Sanitized human-readable incident previews; no outbound delivery.

All descriptions and actions are fixed reviewed strings keyed by known codes.
Never interpolate source data, user content, URLs or model output.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .core import INCIDENT_CODES, InputError

TITLES: dict[str, str] = {
    "snapshot_stale": "Данные мониторинга устарели",
    "timer_disabled": "Отключён таймер новостей",
    "timer_inactive": "Таймер новостей неактивен",
    "discovery_stalled": "Сбор новых материалов остановился",
    "discovery_failures": "Повторяются ошибки сбора новостей",
    "drain_failures": "Повторяются ошибки обработки очереди",
    "outbox_backlog": "Накопилась очередь новостей",
    "outbox_oldest": "Есть слишком старые задания",
    "provider_rate_limited": "Ограничения на запросы к провайдеру",
    "telegram_polling_down": "Бот не подтверждает получение обновлений",
    "backend_unhealthy": "Недоступен сервер приложения",
    "worker_unhealthy": "Не работает обработчик задач",
    "ci_failed": "Не прошла проверка кода",
    "deploy_failed": "Не выполнено развёртывание",
    "agent_guard_missing": "Отсутствует защита сети Hermes Agent",
    "agent_guard_disabled": "Автозагрузка сетевой защиты отключена",
    "agent_guard_inactive": "Защита сети Hermes Agent неактивна",
    "alert_sender_missing": "Отсутствует таймер доставки Ops Watch",
    "alert_sender_disabled": "Отключена автоматическая доставка Ops Watch",
    "alert_sender_inactive": "Неактивен таймер доставки Ops Watch",
    "alert_sender_failed": "Ошибка службы отправки уведомлений Ops Watch",
}
CRITICAL = frozenset({
    "timer_disabled", "timer_inactive", "discovery_failures", "drain_failures",
    "telegram_polling_down", "backend_unhealthy", "deploy_failed",
    "agent_guard_missing", "agent_guard_inactive",
    "alert_sender_missing", "alert_sender_disabled", "alert_sender_inactive",
    "alert_sender_failed",
})
ACTIONS: dict[str, str] = {
    "snapshot_stale": "Проверить журнал службы мониторинга вручную",
    "timer_disabled": "Проверить состояние таймера, без автоматического перезапуска",
    "timer_inactive": "Проверить состояние таймера, без автоматического перезапуска",
    "discovery_stalled": "Проверить время последнего успешного сбора",
    "discovery_failures": "Просмотреть очищенную диагностику сборщика",
    "drain_failures": "Проверить очищенную диагностику обработчика",
    "outbox_backlog": "Проверить состояние очереди без удаления заданий",
    "outbox_oldest": "Проверить старые задания без удаления",
    "provider_rate_limited": "Проверить квоты провайдера без повторных запросов",
    "telegram_polling_down": "Проверить подтверждённый сигнал получения обновлений",
    "backend_unhealthy": "Проверить отдельный источник здоровья сервера",
    "worker_unhealthy": "Проверить обработчик без перезапуска",
    "ci_failed": "Проверить результаты CI вручную",
    "deploy_failed": "Проверить журнал развёртывания вручную",
    "agent_guard_missing": "Проверить сетевую защиту до запуска агента",
    "agent_guard_disabled": "Проверить автозагрузку защитной службы",
    "agent_guard_inactive": "Проверить точные правила nftables до запуска агента",
    "alert_sender_missing": "Проверить установку таймера доставки без автоматического восстановления",
    "alert_sender_disabled": "Проверить автозапуск доставки без изменения службы новостей",
    "alert_sender_inactive": "Проверить журнал и состояние отправителя без перезапуска",
    "alert_sender_failed": "Проверить результат последнего запуска Telegram-отправителя",
}
if set(TITLES) != INCIDENT_CODES or set(ACTIONS) != INCIDENT_CODES:
    raise RuntimeError("incident_preview_catalog_incomplete")


def _codes(value: Any, phase: str) -> list[str]:
    if not isinstance(value, list) or len(value) > len(INCIDENT_CODES):
        raise InputError("invalid_incident_transition")
    items: list[str] = []
    for fingerprint in value:
        if type(fingerprint) is not str or not fingerprint.startswith("ops:"):
            raise InputError("invalid_incident_transition")
        code = fingerprint[4:]
        if code not in INCIDENT_CODES or fingerprint != f"ops:{code}":
            raise InputError("invalid_incident_transition")
        items.append(code)
    if len(set(items)) != len(items):
        raise InputError("duplicate_incident_transition")
    return sorted(items)


def render(delta: Mapping[str, Any], current: list[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Render only approved fixed descriptions; never read untrusted values."""
    if not isinstance(delta, dict) or set(delta) != {"raised", "resolved"}:
        raise InputError("invalid_incident_changes")
    raised = _codes(delta["raised"], "raised")
    resolved = _codes(delta["resolved"], "resolved")
    if set(raised) & set(resolved):
        raise InputError("conflicting_incident_transition")
    if not isinstance(current, list) or len(current) > len(INCIDENT_CODES):
        raise InputError("invalid_current_incidents")
    active: set[str] = set()
    for item in current:
        if not isinstance(item, dict) or type(item.get("code")) is not str:
            raise InputError("invalid_current_incidents")
        code = item["code"]
        if code not in INCIDENT_CODES or item.get("fingerprint") != f"ops:{code}":
            raise InputError("invalid_current_incidents")
        active.add(code)
    if not set(raised).issubset(active) or set(resolved) & active:
        raise InputError("transition_state_mismatch")
    messages: list[dict[str, str]] = []
    for code in raised:
        messages.append({
            "code": code, "phase": "new",
            "severity": "critical" if code in CRITICAL else "warning",
            "title": TITLES[code], "action": ACTIONS[code],
        })
    for code in resolved:
        messages.append({
            "code": code, "phase": "resolved", "severity": "resolved",
            "title": "Восстановлено: " + TITLES[code],
            "action": "Дополнительные действия не требуются",
        })
    return messages
