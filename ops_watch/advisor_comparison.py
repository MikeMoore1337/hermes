"""Bounded comparison of deterministic Ops Watch rules and Advisor output."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .incident_advisor import (
    SCENARIOS,
    PRIORITY_RANK,
    _priority_for,
    _status_for,
    mock_result,
    prepare_context,
    validate_result,
)
from .incident_preview import ACTIONS


def rules_assessment(context: Mapping[str, Any]) -> dict[str, Any]:
    """Return only what the existing factual rules can establish."""
    incident = context.get("incident")
    if not isinstance(incident, dict):
        raise ValueError("comparison_context_invalid")
    status = _status_for(incident)
    priority = _priority_for(incident, status)
    codes = incident["technical_metadata"].get("active_codes", [])
    recommendation = "Сверить последний безопасный сигнал состояния с источником события."
    if codes:
        recommendation = " ".join(ACTIONS[code] for code in codes if code in ACTIONS)
    return {
        "status": status,
        "priority": priority,
        "recommendation": recommendation,
        "known_codes": list(codes),
        "root_cause": "NOT_ESTABLISHED_BY_RULES",
        "source": "ops_watch_rules",
    }


def compare_result(
    context: Mapping[str, Any], *, advisor_result: Mapping[str, Any] | None = None,
    execution: str = "NOT_RUN",
) -> dict[str, Any]:
    """Compare one case without treating a mock response as live AI evidence."""
    rules = rules_assessment(context)
    if advisor_result is None:
        ai = {
            "execution": "NOT_RUN",
            "status": "NOT_RUN",
            "priority": "NOT_RUN",
            "root_cause": "NOT_RUN",
        }
        difference = "NOT_RUN"
        use_ai = "NOT_RUN"
    else:
        result = validate_result(advisor_result, context)
        ai = {
            "execution": execution,
            "status": result["status"],
            "priority": result["priority"],
            "root_cause": "UNVERIFIED_LANGUAGE_OUTPUT",
        }
        difference = {
            "status_match": result["status"] == rules["status"],
            "priority_not_overstated": (
                PRIORITY_RANK[result["priority"]]
                <= PRIORITY_RANK[rules["priority"]]
            ),
            "recommendation_difference": result["recommendation"] != rules["recommendation"],
        }
        use_ai = "NOT_PROVEN" if execution == "MOCK_ONLY" else "MANUAL_REVIEW"
    return {
        "rules": rules,
        "ai": ai,
        "difference": difference,
        "worth_using_ai": use_ai,
    }


def compare_scenarios(*, include_mock: bool = False) -> list[dict[str, Any]]:
    """Use one fixed set for rules and Advisor; live providers are never called."""
    rows: list[dict[str, Any]] = []
    for name, event in SCENARIOS.items():
        if name in {"invalid_input", "prompt_injection"}:
            continue
        context = prepare_context(event)
        mock = mock_result(context) if include_mock else None
        rows.append({
            "scenario": name,
            "input_provenance": event["technical_metadata"]["environment"],
            **compare_result(
                context,
                advisor_result=mock,
                execution="MOCK_ONLY" if include_mock else "NOT_RUN",
            ),
        })
    return rows
