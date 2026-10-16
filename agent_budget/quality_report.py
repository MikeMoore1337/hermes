"""Deterministic evaluation rollup: mock success != real-model quality."""
from __future__ import annotations

import json
from collections import Counter
from decimal import Decimal
from typing import Any

from agent_budget.pilot import RESULT_SCHEMA

NO_DATA = "NOT_VERIFIED"
MODES = frozenset({
    "MOCK_ONLY", "NOT_RUN", "LIVE_OBSERVED",
    "LIVE_OBSERVED_FAILURE", "LIVE_OBSERVED_COST_NOT_VERIFIED",
})
STATUS = frozenset({"PASS", "REJECTED", "BLOCKED"})


class QualityReportError(ValueError):
    pass


def summarize(records: Any) -> dict[str, Any]:
    if type(records) is not list or not 1 <= len(records) <= 100:
        raise QualityReportError("results_list_invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for rec in records:
        if type(rec) is not dict or rec.get("schema") != RESULT_SCHEMA:
            raise QualityReportError("record_schema_invalid")
        case = rec.get("case")
        mode = rec.get("model_execution")
        status = rec.get("status")
        calls = rec.get("model_calls")
        task = rec.get("task")
        metrics = rec.get("metrics")
        if (type(case) is not str or not 1 <= len(case) <= 100
                or case in seen or mode not in MODES or status not in STATUS
                or type(calls) is not int or not 0 <= calls <= 3
                or task not in {"ops", "research"}
                or type(metrics) is not dict):
            raise QualityReportError("record_contract_invalid")
        if mode in {"NOT_RUN", "MOCK_ONLY"} and (
                (mode == "NOT_RUN" and calls != 0)
                or (mode == "MOCK_ONLY" and calls != 1)):
            raise QualityReportError("model_calls_inconsistent")
        seen.add(case)
        normalized.append(rec)
    live = [r for r in normalized if r["model_execution"].startswith("LIVE_OBSERVED")]
    recorded = [r for r in live if (
        type(r["metrics"].get("provider_cost_usd")) in {int, float}
        and r["metrics"]["provider_cost_usd"] >= 0
    )]
    neurons = [r["metrics"].get("provider_neurons") for r in live]
    neurons_complete = bool(live) and all(type(v) in {float, int} and v >= 0 for v in neurons)
    return {
        "schema": "hermes-ai-pilot-quality-rollup-v1",
        "cases": len(normalized),
        "by_execution": dict(sorted(Counter(r["model_execution"] for r in normalized).items())),
        "by_status": dict(sorted(Counter(r["status"] for r in normalized).items())),
        "mock_cases": sum(r["model_execution"] == "MOCK_ONLY" for r in normalized),
        "live_observed_cases": len(live),
        "live_schema_accepted_cases": sum(
            r.get("validation_status") == "PASS"
            or r["status"] == "PASS" for r in live
        ),
        "total_real_calls_reported": sum(r["model_calls"] for r in live),
        "reported_provider_cost_usd": (
            str(sum((Decimal(str(r["metrics"]["provider_cost_usd"])) for r in recorded),
                    Decimal("0"))) if live and len(recorded) == len(live)
            else NO_DATA if live else "NOT_RUN"
        ),
        "provider_neurons": sum(neurons) if neurons_complete else (
            NO_DATA if live else "NOT_RUN"
        ),
        "billing_guaranteed_free": False,
        "scientific_quality_verified": False,
        "llm_better_than_rules": "NOT_PROVEN",
        "interpretation": (
            "MOCK_AND_SCHEMA_COUNTS_ARE_NOT_LLM_QUALITY_EVIDENCE"
        ),
    }


def run_cli(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Offline Hermes AI pilot quality report")
    parser.add_argument("--stdin", action="store_true", required=True)
    parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        content = sys.stdin.buffer.read(262_145)
        if len(content) > 262_144:
            raise QualityReportError("input_too_large")
        output = summarize(json.loads(content))
    except (ValueError, TypeError):
        print(json.dumps({"status": "REJECTED", "reason": "invalid_report_input"}))
        return 2
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
