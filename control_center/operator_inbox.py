"""Hermes #468 owner-only operator inbox: bounded read-only projection.

Existing systemd and scheduler status are read from their already-approved
snapshots. No new collector, BRC call, incident log, shell, model or action.
Missing evidence becomes NOT_AVAILABLE, never a fabricated green status.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from control_center.snapshot import UNITS
from control_center.github_observe_view import (
    FeedRefused, validate as validate_github_feed, fresh as github_feed_fresh,
)

MAX_SNAPSHOT_BYTES = 131072
MAX_EVENTS = 24
MAX_AGE_SECONDS = 180
FUTURE_SKEW_SECONDS = 120
ALLOWED_STATES = {"active", "inactive", "failed", "unknown", "blocked", "unexpected_active"}
LABELS = {key: (label, kind) for key, label, _unit, kind in UNITS}
SCHEMA = 1

class InboxUnavailable(ValueError):
    pass


def _utc(value):
    if not isinstance(value, str) or len(value) > 40:
        raise InboxUnavailable("invalid_timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone_required")
        return parsed.astimezone(dt.timezone.utc)
    except ValueError as exc:
        raise InboxUnavailable("invalid_timestamp") from exc


def load_overview(path: Path) -> dict:
    """Use a fixed, already-configured snapshot path, never caller input."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise InboxUnavailable("overview_unavailable")
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_SNAPSHOT_BYTES:
            raise InboxUnavailable("overview_unavailable")
        value = json.loads(raw)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise InboxUnavailable("overview_unavailable") from exc
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or value.get("mode") != "read_only":
        raise InboxUnavailable("overview_invalid")
    _utc(value.get("generated_at"))
    if not isinstance(value.get("services"), list) or len(value["services"]) > len(UNITS):
        raise InboxUnavailable("overview_invalid")
    return value


def _event(source, key, *, category, severity, status, observed, hint, evidence):
    return {
        "source": source, "event_id": f"{source}:{key}", "status": status,
        "severity": severity, "category": category, "observed_at": observed,
        "last_verified_at": observed, "action_hint": hint,
        "evidence_link": evidence, "scope": "owner_read_only",
    }



# Labels are fixed in source. GitHub never supplies UI text or an action.
_GITHUB_CANDIDATES = {
    "REVIEW_ISSUE": ("Новая задача GitHub", "Задача", "issues"),
    "REVIEW_FOLLOWUP": ("Новое обсуждение GitHub", "Обсуждение", "issues"),
    "REVIEW_PR": ("Обновление PR GitHub", "PR", "pull"),
    "REVIEW_CI_FAILURE": ("Сбой CI GitHub", "Проверка CI", "actions/runs"),
    "REVIEW_CI_UNCERTAIN": ("Результат CI не подтверждён", "Проверка CI", "actions/runs"),
}


def _add_github_observations(overview, now, coverage, events):
    source = "github_observe"
    if not isinstance(overview, dict):
        return
    raw = overview.get("github_observe_feed")
    if raw is None:
        return
    try:
        value = validate_github_feed(raw)
    except (FeedRefused, AttributeError, TypeError, ValueError):
        coverage[source]["status"] = "PARTIAL"
        coverage[source]["details"] = "Недопустимый снимок GitHub; записи скрыты"
        return
    captured = value["observed_at"]
    if not github_feed_fresh(value, now=now):
        coverage[source]["status"] = "STALE"
        coverage[source]["details"] = "Проверка GitHub давно не подтверждена"
        events.append({
            **_event(source, "stale", category="needs_review", severity="warning",
                     status="needs_review", observed=captured,
                     hint="Проверить доступность наблюдателя и существующего QA Advisor.",
                     evidence=None),
            "title": "Наблюдения GitHub устарели",
            "detail": "Старый снимок не доказывает наличие новых или отсутствие ошибок.",
        })
        return
    coverage[source]["status"] = "PARTIAL"
    coverage[source]["details"] = (
        "Только последние 12 запусков GitHub Actions; не полный журнал"
    )
    for record in value["events"]:
        candidate = record["candidate"]
        label, subject_label, route = _GITHUB_CANDIDATES[candidate]
        number, run_id = record["subject_number"], record["run_id"]
        is_failure = candidate == "REVIEW_CI_FAILURE"
        events.append({
            **_event(source, f'{record["event"]}:{number}',
                     category="failure" if is_failure else "needs_review",
                     severity="critical" if is_failure else "warning",
                     status="failure" if is_failure else "needs_review",
                     observed=record["occurred_at"],
                     hint=(f"Проверить {subject_label.lower()} №{number} в "
                           "MikeMoore1337/hermes и текущие разрешения. "
                           "Наблюдение не запускает задачи."),
                     evidence=None),
            "title": f"{label} №{number}",
            "detail": (f"Подтверждён запуск наблюдателя №{run_id}; "
                       "содержимое GitHub не проверялось. "
                       "Это рекомендация оператору, не разрешение на выполнение."),
        })


def assemble(overview: dict | None, scheduler: dict | None, *, now: dt.datetime | None = None) -> dict:
    """Only fixed labels and counts are copied. Never expose raw job IDs or error strings."""
    clock = now or dt.datetime.now(dt.timezone.utc)
    clock = clock.astimezone(dt.timezone.utc)
    events = []
    coverage = {
        "systemd": {"status": "NOT_AVAILABLE", "label": "Службы и Ops Watch", "details": "Нет проверенного снимка"},
        "scheduler": {"status": "NOT_AVAILABLE", "label": "Планировщик задач", "details": "Очередь не подтверждена"},
        "brc": {"status": "NOT_AVAILABLE", "label": "Hermes BRC", "details": "Нет подключённого источника состояния"},
        "delivery": {"status": "NOT_AVAILABLE", "label": "Подтверждение доставки", "details": "Нет отдельной квитанции"},
        "ops_incidents": {"status": "NOT_AVAILABLE", "label": "События Ops Watch", "details": "Журнал инцидентов не подключён"},
        "github_observe": {"status": "NOT_AVAILABLE", "label": "GitHub Observe", "details": "Нет проверенного снимка наблюдений"},
    }
    if overview is not None:
        if not isinstance(overview, dict) or overview.get("schema") != SCHEMA or overview.get("mode") != "read_only":
            raise InboxUnavailable("overview_invalid")
        stamp = _utc(overview.get("generated_at"))
        age = (clock - stamp).total_seconds()
        recent = -FUTURE_SKEW_SECONDS <= age <= MAX_AGE_SECONDS
        raw = overview.get("services")
        if not isinstance(raw, list) or len(raw) > len(UNITS):
            raise InboxUnavailable("overview_invalid")
        names = set()
        valid = True
        for item in raw:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    or item["id"] not in LABELS or item["id"] in names
                    or not isinstance(item.get("state"), str) or item["state"] not in ALLOWED_STATES
                    or not isinstance(item.get("unit"), str)
                    or item["unit"] != next(unit for key, _label, unit, _kind in UNITS if key == item["id"])):
                valid = False
                break
            names.add(item["id"])
        if valid and len(raw) == len(UNITS) and recent:
            coverage["systemd"] = {"status": "SUPPORTED", "label": "Службы и Ops Watch",
                                   "details": "Актуальный защищённый снимок systemd"}
            for item in raw:
                code = item["state"]
                ident = item["id"]
                # The intentionally disabled full Agent is never treated as failed.
                if ident == "agent" and code == "blocked":
                    continue
                if code == "active":
                    continue
                if code in ("failed", "unexpected_active"):
                    severity, status, category = "critical", "failure", "failure"
                elif code == "blocked":
                    severity, status, category = "warning", "blocked", "blocked"
                else:
                    severity, status, category = "warning", "needs_review", "needs_review"
                events.append({
                    **_event("systemd", ident, category=category, severity=severity,
                             status=status, observed=stamp.isoformat().replace("+00:00", "Z"),
                             hint="Проверить состояние службы в реестре; запуск недоступен.",
                             evidence="/api/overview"),
                    "title": LABELS[ident][0], "detail": f"Наблюдаемое состояние: {code}",
                })
        else:
            coverage["systemd"]["status"] = "STALE" if valid and not recent else "PARTIAL"
            coverage["systemd"]["details"] = "Снимок устарел" if valid and not recent else "Некорректный или неполный список"
            events.append({
                **_event("systemd", "unverified", category="needs_review", severity="warning",
                         status="needs_review", observed=stamp.isoformat().replace("+00:00", "Z"),
                         hint="Обновить исходный снимок. Не считать состояние служб здоровым.",
                         evidence="/api/overview"),
                "title": "Нет подтверждения свежести служб", "detail": coverage["systemd"]["details"],
            })
    if scheduler is not None:
        if (isinstance(scheduler, dict) and scheduler.get("schema") == 1
                and scheduler.get("mode") == "read_only" and scheduler.get("queue_state") == "available"
                and isinstance(scheduler.get("counts"), dict)
                and all(type(scheduler["counts"].get(k)) is int and
                        0 <= scheduler["counts"][k] <= 100000
                        for k in ("queued", "deferred", "running", "blocked", "completed"))):
            coverage["scheduler"] = {"status": "PARTIAL", "label": "Планировщик задач",
                                     "details": "Агрегированные счётчики без доказательств отдельных действий"}
            for category, status, severity, title, hint in (
                ("blocked", "blocked", "warning", "Заблокированные задания", "Проверить причину блокировки в планировщике."),
                ("deferred", "needs_review", "warning", "Отложенные задания", "Проверить окно и условия запуска."),
            ):
                count = scheduler["counts"][category]
                if count:
                    events.append({
                        **_event("scheduler", category, category="blocked" if category == "blocked" else "needs_review",
                                 severity=severity, status=status, observed=None,
                                 hint=hint, evidence="/api/codex/tasks"),
                        "title": title, "detail": f"Заданий: {count}. Время проверки отдельных задач не подтверждено.",
                    })
        else:
            coverage["scheduler"]["details"] = "Данные отсутствуют или недостаточны"
    _add_github_observations(overview, clock, coverage, events)
    seen = set()
    unique = []
    for ev in events:
        if ev["event_id"] in seen:
            continue
        seen.add(ev["event_id"])
        unique.append(ev)
    unique.sort(key=lambda ev: ({"critical": 0, "warning": 1, "info": 2}[ev["severity"]], ev["event_id"]))
    unique = unique[:MAX_EVENTS]
    summary = {
        "total": len(unique),
        "critical": sum(x["severity"] == "critical" for x in unique),
        "review": sum(x["category"] == "needs_review" for x in unique),
        "blocked": sum(x["category"] == "blocked" for x in unique),
        "available_sources": sum(v["status"] in ("SUPPORTED", "PARTIAL") for v in coverage.values()),
        "source_count": len(coverage),
    }
    return {"schema": SCHEMA, "mode": "read_only", "generated_at": clock.isoformat().replace("+00:00", "Z"),
            "events": unique, "sources": coverage, "summary": summary,
            "actions_enabled": False, "completeness": "PARTIAL",
            "note": "Отсутствие событий не доказывает отсутствие неисправностей."}
