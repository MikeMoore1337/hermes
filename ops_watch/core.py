"""Pure offline evaluator for normalized Hermes and YFC health snapshots."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

SCHEMA = "hermes-ops-snapshot-v1"
INCIDENT_CODES = frozenset({
    "snapshot_stale", "timer_disabled", "timer_inactive", "discovery_stalled",
    "discovery_failures", "drain_failures", "outbox_backlog", "outbox_oldest",
    "provider_rate_limited", "telegram_polling_down", "backend_unhealthy",
    "worker_unhealthy", "ci_failed", "deploy_failed",
    "agent_guard_missing", "agent_guard_disabled", "agent_guard_inactive",
    "alert_sender_missing", "alert_sender_disabled", "alert_sender_inactive",
    "alert_sender_failed",
    "codex_low", "codex_exhausted", "codex_auth_required", "codex_stale",
})


class InputError(ValueError):
    """Невалидный снимок, не свидетельствующий о здоровье системы."""


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{name}: object required")
    return value


def _bool(data: Mapping[str, Any], key: str) -> bool:
    value = data.get(key)
    if type(value) is not bool:
        raise InputError(f"{key}: boolean required")
    return value


def _count(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise InputError(f"{key}: invalid nonnegative count")
    return value


def _time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise InputError(f"{name}: timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"{name}: invalid time") from exc
    if parsed.tzinfo is None:
        raise InputError(f"{name}: timezone required")
    return parsed.astimezone(UTC)


def _state(data: Mapping[str, Any], key: str, options: frozenset[str]) -> str:
    value = data.get(key, "unknown")
    if not isinstance(value, str) or value not in options:
        raise InputError(f"{key}: invalid status")
    return value


def _finding(code: str, severity: str, value: int | None = None) -> dict[str, str | int]:
    finding: dict[str, str | int] = {
        "code": code, "severity": severity, "fingerprint": f"ops:{code}",
    }
    if value is not None:
        finding["observed_value"] = value
    return finding


def analyze(snapshot: Mapping[str, Any], *, now: datetime) -> list[dict[str, str | int]]:
    """Найти аварии без сетевых операций, отправки сообщений и доступа к данным."""
    data = _mapping(snapshot, "snapshot")
    if data.get("schema") != SCHEMA:
        raise InputError("unexpected snapshot schema")
    observed = _time(data.get("observed_at"), "observed_at")
    if now.tzinfo is None:
        raise InputError("now: timezone required")
    now = now.astimezone(UTC)
    if observed > now + timedelta(minutes=1):
        raise InputError("observed_at: future value")
    if now - observed > timedelta(minutes=15):
        return [_finding("snapshot_stale", "warning")]

    news = _mapping(data.get("news"), "news")
    enabled = _bool(news, "timer_enabled")
    active = _bool(news, "timer_active")
    discovery_failures = _count(news, "consecutive_discovery_failures")
    drain_failures = _count(news, "consecutive_drain_failures")
    pending = _count(news, "pending_jobs")
    oldest = _count(news, "oldest_pending_age_seconds")
    recent_rate_limits = _count(news, "recent_provider_rate_limits")
    last = news.get("last_successful_discovery_at")
    last_success = _time(last, "last_successful_discovery_at") if last is not None else None
    if last_success is not None and last_success > observed + timedelta(minutes=1):
        raise InputError("last_successful_discovery_at: future value")
    found: list[dict[str, str | int]] = []
    if not enabled:
        found.append(_finding("timer_disabled", "critical"))
    if not active:
        found.append(_finding("timer_inactive", "critical"))
    if active and enabled and (last_success is None or observed - last_success > timedelta(hours=3)):
        found.append(_finding("discovery_stalled", "warning"))
    for value, minimum, code, severity in [
        (discovery_failures, 3, "discovery_failures", "critical"),
        (drain_failures, 3, "drain_failures", "critical"),
        (pending, 100, "outbox_backlog", "warning"),
        (oldest, 172_800, "outbox_oldest", "warning"),
        (recent_rate_limits, 5, "provider_rate_limited", "warning"),
    ]:
        if value >= minimum:
            found.append(_finding(code, severity, value))

    if data.get("agent_guard") is not None:
        agent_guard = _mapping(data["agent_guard"], "agent_guard")
        loaded = _bool(agent_guard, "loaded")
        active = _bool(agent_guard, "active")
        enabled = _bool(agent_guard, "enabled")
        if not loaded:
            found.append(_finding("agent_guard_missing", "critical"))
        else:
            if not enabled:
                found.append(_finding("agent_guard_disabled", "warning"))
            if not active:
                found.append(_finding("agent_guard_inactive", "critical"))

    if data.get("alerts_timer") is not None:
        alerts = _mapping(data["alerts_timer"], "alerts_timer")
        loaded = _bool(alerts, "loaded")
        enabled = _bool(alerts, "enabled")
        timer_running = _bool(alerts, "active")
        if not loaded:
            found.append(_finding("alert_sender_missing", "critical"))
        else:
            if not enabled:
                found.append(_finding("alert_sender_disabled", "critical"))
            if not timer_running:
                found.append(_finding("alert_sender_inactive", "critical"))

    if data.get("alerts_service") is not None:
        service = _mapping(data["alerts_service"], "alerts_service")
        if _bool(service, "failed"):
            found.append(_finding("alert_sender_failed", "critical"))

    if data.get("yfc") is not None:
        yfc = _mapping(data["yfc"], "yfc")
        status = frozenset({"healthy", "unhealthy", "unknown"})
        backend = _state(yfc, "backend", status)
        worker = _state(yfc, "worker", status)
        # Docker Up не равно подтверждённому Telegram polling heartbeat.
        polling = _state(yfc, "bot_polling", status)
        if backend == "unhealthy":
            found.append(_finding("backend_unhealthy", "critical"))
        if worker == "unhealthy":
            found.append(_finding("worker_unhealthy", "warning"))
        if backend == "healthy" and polling == "unhealthy":
            found.append(_finding("telegram_polling_down", "critical"))

    if data.get("actions") is not None:
        actions = _mapping(data["actions"], "actions")
        options = frozenset({"success", "failure", "running", "unknown"})
        if _state(actions, "ci", options) == "failure":
            found.append(_finding("ci_failed", "warning"))
        if _state(actions, "deploy", options) == "failure":
            found.append(_finding("deploy_failed", "critical"))
    # Optional isolated Codex account telemetry, never a reset-time prediction.
    if data.get("codex") is not None:
        codex = _mapping(data["codex"], "codex")
        state = _state(codex, "status", frozenset({
            "available", "low", "limited", "exhausted", "unknown", "stale",
            "auth_required", "unavailable", "not_configured",
        }))
        allowance = codex.get("ordinary_usage_allowed")
        if allowance is not None and type(allowance) is not bool:
            raise InputError("invalid_codex_allowance")
        if state == "auth_required":
            found.append(_finding("codex_auth_required", "warning"))
        elif state in ("stale", "unavailable", "unknown") or (
            state == "available" and allowance is not True
        ):
            found.append(_finding("codex_stale", "warning"))
        elif state in ("exhausted", "limited") or allowance is False:
            found.append(_finding("codex_exhausted", "warning"))
        elif state == "low":
            found.append(_finding("codex_low", "warning"))
    return found


def changes(previous: list[Mapping[str, Any]], current: list[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Вычислить только новые и устранённые сигналы, без повтора существующих."""
    def fingerprints(items: list[Mapping[str, Any]]) -> set[str]:
        found: set[str] = set()
        for item in items:
            item = _mapping(item, "finding")
            code = item.get("code")
            fingerprint = item.get("fingerprint")
            if not isinstance(code, str) or code not in INCIDENT_CODES or fingerprint != f"ops:{code}":
                raise InputError("invalid incident fingerprint")
            found.add(fingerprint)
        return found

    before = fingerprints(previous)
    after = fingerprints(current)
    return {"raised": sorted(after - before), "resolved": sorted(before - after)}
