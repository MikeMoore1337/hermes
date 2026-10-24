"""Read-only projection from the existing Ops Watch SQLite event journal.

This module never creates a database, acknowledges an event, changes the
queue, sends a message, or reads production by default. Callers must provide
an explicit local snapshot directory.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import INCIDENT_CODES, InputError
from .incident_advisor import INPUT_SCHEMA, prepare_context
from .incident_preview import ACTIONS, CRITICAL, TITLES, resolved_action, resolved_title
from .state_store import inspect

ADAPTER_SCHEMA = "hermes-ops-watch-advisor-event-v1"
MAX_EVENTS = 50
PROVENANCES = frozenset({"synthetic", "anonymized_copy", "readonly_snapshot"})

# The historical event journal stores the reviewed action text immutably.
# Narrowly accept only the two pre-ask-before-cleanup disk actions that were
# emitted before the preview copy changed; other legacy or arbitrary text
# must continue failing closed. No old incident is rewritten or reprocessed.
LEGACY_DISK_ACTIONS = {
    "infra_hermes_disk_high": "Проверить диск VPS Hermes без автоматического удаления данных",
    "infra_yfc_disk_high": "Проверить диск VPS YFC без автоматического удаления данных",
}

# The source journal stores stable incident codes, not free-form root causes.
CODE_MAPPING: dict[str, tuple[str, str, str, str]] = {
    "snapshot_stale": ("monitoring_stale", "SNAPSHOT_STALE", "unknown", "ops-monitor"),
    "timer_disabled": ("systemd_timer_failure", "SYSTEMD_TIMER_DISABLED", "unhealthy", "news-timer"),
    "timer_inactive": ("systemd_timer_failure", "SYSTEMD_TIMER_INACTIVE", "unhealthy", "news-timer"),
    "discovery_stalled": ("systemd_timer_failure", "DISCOVERY_STALLED", "degraded", "news-discovery"),
    "discovery_failures": ("systemd_timer_failure", "SYSTEMD_RESULT_FAILED", "unhealthy", "news-discovery"),
    "drain_failures": ("notification_queue_stopped", "QUEUE_DRAIN_FAILURE", "degraded", "ops-outbox"),
    "outbox_backlog": ("notification_queue_stopped", "QUEUE_BACKLOG", "degraded", "ops-outbox"),
    "outbox_oldest": ("notification_queue_stopped", "QUEUE_AGE_LIMIT", "degraded", "ops-outbox"),
    "provider_rate_limited": ("provider_rate_limited", "HTTP_429", "degraded", "provider"),
    "telegram_polling_down": ("service_health_failure", "TELEGRAM_POLLING_DOWN", "unhealthy", "telegram-polling"),
    "backend_unhealthy": ("service_health_failure", "BACKEND_UNHEALTHY", "unhealthy", "backend"),
    "worker_unhealthy": ("service_health_failure", "WORKER_UNHEALTHY", "degraded", "worker"),
    "ci_failed": ("github_actions_failure", "CI_FAILURE", "degraded", "github-actions"),
    "deploy_failed": ("github_actions_failure", "DEPLOY_FAILURE", "unhealthy", "github-actions"),
    "agent_guard_missing": ("network_guard_failure", "GUARD_MISSING", "unhealthy", "network-guard"),
    "agent_guard_disabled": ("network_guard_failure", "GUARD_DISABLED", "degraded", "network-guard"),
    "agent_guard_inactive": ("network_guard_failure", "GUARD_INACTIVE", "unhealthy", "network-guard"),
    "alert_sender_missing": ("telegram_sender_failure", "ALERT_SENDER_MISSING", "unhealthy", "alert-sender"),
    "alert_sender_disabled": ("telegram_sender_failure", "ALERT_SENDER_DISABLED", "unhealthy", "alert-sender"),
    "alert_sender_inactive": ("telegram_sender_failure", "ALERT_SENDER_INACTIVE", "unhealthy", "alert-sender"),
    "alert_sender_failed": ("telegram_sender_failure", "TELEGRAM_SEND_TIMEOUT", "unhealthy", "alert-sender"),
    # Subscription telemetry is an Ops Watch signal, not a request to invoke H-01.
    "codex_low": ("provider_rate_limited", "CODEX_QUOTA_LOW", "degraded", "codex-usage"),
    "codex_exhausted": ("provider_rate_limited", "CODEX_QUOTA_EXHAUSTED", "degraded", "codex-usage"),
    "codex_auth_required": ("monitoring_stale", "CODEX_AUTH_REQUIRED", "unknown", "codex-usage"),
    "codex_stale": ("monitoring_stale", "CODEX_QUOTA_STALE", "unknown", "codex-usage"),
    # Fixed per-host resource incidents are rules-only, never tool execution.
    "infra_hermes_unavailable": ("monitoring_stale", "HERMES_METRICS_UNAVAILABLE", "unknown", "vps-hermes"),
    "infra_hermes_cpu_high": ("service_health_failure", "HERMES_CPU_HIGH", "degraded", "vps-hermes"),
    "infra_hermes_ram_high": ("service_health_failure", "HERMES_RAM_HIGH", "degraded", "vps-hermes"),
    "infra_hermes_disk_high": ("service_health_failure", "HERMES_DISK_HIGH", "unhealthy", "vps-hermes"),
    "infra_yfc_unavailable": ("monitoring_stale", "YFC_METRICS_UNAVAILABLE", "unknown", "vps-yfc"),
    "infra_yfc_cpu_high": ("service_health_failure", "YFC_CPU_HIGH", "degraded", "vps-yfc"),
    "infra_yfc_ram_high": ("service_health_failure", "YFC_RAM_HIGH", "degraded", "vps-yfc"),
    "infra_yfc_disk_high": ("service_health_failure", "YFC_DISK_HIGH", "unhealthy", "vps-yfc"),
    "quota_desktop_80": ("provider_rate_limited", "DC_QUOTA_80", "degraded", "desktop-commander"),
    "quota_desktop_95": ("provider_rate_limited", "DC_QUOTA_95", "degraded", "desktop-commander"),
    "quota_desktop_exhausted": ("provider_rate_limited", "DC_QUOTA_EXHAUSTED", "unhealthy", "desktop-commander"),
    "quota_desktop_auth": ("monitoring_stale", "DC_AUTH_REQUIRED", "unknown", "desktop-commander"),
    "quota_desktop_stale": ("monitoring_stale", "DC_STALE", "unknown", "desktop-commander"),
    "quota_github_80": ("provider_rate_limited", "GH_QUOTA_80", "degraded", "github-token"),
    "quota_github_95": ("provider_rate_limited", "GH_QUOTA_95", "degraded", "github-token"),
    "quota_github_exhausted": ("provider_rate_limited", "GH_QUOTA_EXHAUSTED", "unhealthy", "github-token"),
    "quota_github_auth": ("monitoring_stale", "GH_QUOTA_AUTH", "unknown", "github-token"),
    "quota_github_stale": ("monitoring_stale", "GH_QUOTA_STALE", "unknown", "github-token"),
    "device_windows_pc_unavailable": ("service_health_failure", "WINDOWS_PRESENCE_OFFLINE", "degraded", "device-windows"),
    "device_linux_vps_unavailable": ("service_health_failure", "LINUX_PRESENCE_OFFLINE", "unhealthy", "device-linux"),
    "device_tls_expiring": ("service_health_failure", "WSS_CERT_EXPIRING", "degraded", "device-wss"),
    "device_tls_expired": ("service_health_failure", "WSS_CERT_EXPIRED", "unhealthy", "device-wss"),
}

# New stable Ops codes must never crash the active H-01 timer during projection.
if set(CODE_MAPPING) != INCIDENT_CODES:
    raise RuntimeError("advisor_code_mapping_incomplete")


class AdvisorAdapterError(ValueError):
    """Sanitized refusal for an unavailable or malformed read-only source."""


def _timestamp(value: Any) -> str:
    if type(value) is not str or len(value) > 40:
        raise AdvisorAdapterError("event_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AdvisorAdapterError("event_timestamp_invalid") from None
    if parsed.tzinfo is None:
        raise AdvisorAdapterError("event_timestamp_invalid")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _row(row: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) != {
        "id", "fingerprint", "phase", "severity", "title", "action", "created_at",
    }:
        raise AdvisorAdapterError("event_record_invalid")
    event_id = row["id"]
    if type(event_id) is not int or event_id <= 0:
        raise AdvisorAdapterError("event_record_invalid")
    fingerprint = row["fingerprint"]
    if (type(fingerprint) is not str or not fingerprint.startswith("ops:")
            or fingerprint[4:] not in INCIDENT_CODES):
        raise AdvisorAdapterError("unknown_event_code")
    code = fingerprint[4:]
    expected_title = TITLES[code]
    expected_action = ACTIONS[code]
    phase = row["phase"]
    expected_severity = (
        "critical" if code in CRITICAL else "warning"
    )
    if phase == "resolved":
        expected_title = resolved_title(code)
        expected_action = resolved_action(code)
        expected_severity = "resolved"
    action_matches = row["action"] == expected_action or (
        phase == "new" and code in LEGACY_DISK_ACTIONS
        and row["action"] == LEGACY_DISK_ACTIONS[code]
    )
    if (phase not in {"new", "resolved"} or row["severity"] != expected_severity
            or row["title"] != expected_title or not action_matches):
        raise AdvisorAdapterError("event_record_invalid")
    return {
        "id": event_id,
        "code": code,
        "phase": phase,
        "created_at": _timestamp(row["created_at"]),
    }


def _analysis_decision(code: str, phase: str, repeat_count: int) -> dict[str, str]:
    if phase == "resolved":
        return {"decision": "RULES_ONLY", "reason": "fixed_recovery_transition"}
    # Repeat counts greater than one must come from a future trusted
    # observation counter, never from this transition-only journal.
    if repeat_count > 1:
        return {"decision": "ADVISOR_CANDIDATE", "reason": "verified_repeat_needs_context"}
    if code in {"outbox_backlog", "outbox_oldest", "drain_failures", "worker_unhealthy"}:
        return {"decision": "ADVISOR_CANDIDATE", "reason": "operator_context_may_help"}
    return {"decision": "RULES_ONLY", "reason": "deterministic_code_and_action"}


def _adapt(row: dict[str, Any], *, repeat_count: int, provenance: str) -> dict[str, Any]:
    incident_type, error_code, active_state, component = CODE_MAPPING[row["code"]]
    recovered = row["phase"] == "resolved"
    environment = "synthetic" if provenance == "synthetic" else "local"
    event = {
        "schema": INPUT_SCHEMA,
        "incident_type": incident_type,
        "source": "ops_watch",
        "detected_at": row["created_at"],
        "service_state": "healthy" if recovered else active_state,
        "error_code": "RECOVERY_CONFIRMED" if recovered else error_code,
        "repeat_count": repeat_count,
        "previous_similar": repeat_count > 1,
        "recovery_state": "recovered" if recovered else "active",
        "technical_metadata": {
            "component": component,
            "environment": environment,
            "active_codes": [] if recovered else [row["code"]],
        },
    }
    # Re-run the strict Advisor input validator at this trust boundary.
    prepare_context(event)
    return {
        "schema": ADAPTER_SCHEMA,
        "event_id": row["id"],
        "provenance": provenance,
        "phase": row["phase"],
        "event": event,
        "analysis": _analysis_decision(row["code"], row["phase"], repeat_count),
    }


def read_events(
    directory: Path, *, provenance: str, max_items: int = MAX_EVENTS,
    event_id: int | None = None,
) -> list[dict[str, Any]]:
    """Read existing event rows through the source module's SQLite read-only API."""
    if not isinstance(directory, Path) or directory.is_symlink():
        raise AdvisorAdapterError("source_directory_invalid")
    if provenance not in PROVENANCES:
        raise AdvisorAdapterError("event_provenance_invalid")
    if type(max_items) is not int or not 1 <= max_items <= MAX_EVENTS:
        raise AdvisorAdapterError("event_limit_invalid")
    if event_id is not None and (type(event_id) is not int or event_id <= 0):
        raise AdvisorAdapterError("event_id_invalid")
    try:
        rows = inspect(directory, max_items=max_items)
    except (InputError, OSError, AttributeError):
        raise AdvisorAdapterError("source_unavailable") from None
    parsed = [_row(item) for item in rows]
    if event_id is not None:
        parsed = [item for item in parsed if item["id"] == event_id]
        if not parsed:
            raise AdvisorAdapterError("event_not_found")
    # The journal records transitions, not observations or retries. Counting
    # matching codes across the last 50 rows would mix recoveries and distinct
    # episodes and invent a repeat count. One "new" transition represents one
    # episode; a "resolved" transition is not a new incident.
    return [
        _adapt(
            item, repeat_count=1 if item["phase"] == "new" else 0,
            provenance=provenance,
        )
        for item in parsed
    ]


def rules_assessment(adapted: Mapping[str, Any]) -> dict[str, Any]:
    """Return the deterministic baseline for the same adapted event."""
    if not isinstance(adapted, dict) or adapted.get("schema") != ADAPTER_SCHEMA:
        raise AdvisorAdapterError("adapted_event_invalid")
    event = adapted.get("event")
    if not isinstance(event, dict):
        raise AdvisorAdapterError("adapted_event_invalid")
    code = event["technical_metadata"]["active_codes"]
    code = code[0] if code else None
    if adapted["phase"] == "resolved":
        return {
            "status": "resolved", "priority": "low",
            "recommendation": "Дополнительные действия не требуются",
            "source": "ops_watch_rules",
        }
    if code is None or code not in CODE_MAPPING:
        return {
            "status": "insufficient_data", "priority": "low",
            "recommendation": "Сверить последний безопасный сигнал состояния с источником события.",
            "source": "ops_watch_rules",
        }
    if event["service_state"] == "unknown":
        priority = "low"
        status = "insufficient_data"
    elif code in CRITICAL:
        priority = "critical"
        status = "active"
    elif event["service_state"] == "degraded":
        priority = "high"
        status = "active"
    else:
        priority = "medium"
        status = "active"
    return {
        "status": status,
        "priority": priority,
        "recommendation": ACTIONS[code],
        "source": "ops_watch_rules",
    }
