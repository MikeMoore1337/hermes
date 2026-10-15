"""Small offline/live CLI for the bounded Hermes AI quality pilot."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_budget.pilot import (
    PilotError,
    case_names,
    prepare_live_instructions,
    run_pilot,
    status,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".artifacts" / "hermes-ai-pilot" / "results.json"
DEFAULT_STATE = ROOT / ".artifacts" / "hermes-ai-pilot" / "state.json"


def _json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _cases() -> dict[str, list[str]]:
    names = case_names()
    return {
        "ops": [name for name in names if name.startswith("ops:")],
        "research": [name for name in names if name.startswith("research:")],
    }


def _report(records: list[dict[str, object]]) -> None:
    print("Hermes AI quality pilot")
    print("Задача | Правила или ручной эталон | Mock | Реальная LLM | Время | Качество")
    for record in records:
        task = str(record.get("task", "UNKNOWN"))
        rules = "готовы" if task == "ops" else "ручной эталон"
        mock = str(record.get("status", "UNKNOWN"))
        quality = record.get("quality", {})
        if isinstance(quality, dict):
            quality_label = str(
                quality.get("deterministic_quality")
                or quality.get("scientific_accuracy")
                or "NOT_ASSESSED"
            )
        else:
            quality_label = "NOT_ASSESSED"
        metrics = record.get("metrics", {})
        elapsed = metrics.get("process_elapsed_seconds", "NOT_RUN") if isinstance(metrics, dict) else "NOT_RUN"
        execution = record.get("model_execution")
        real = "NOT_RUN" if execution == "MOCK_ONLY" else str(execution or "NOT_RUN")
        print(f"{record.get('case', 'UNKNOWN')} | {rules} | {mock} | {real} | {elapsed} | {quality_label}")
    print(f"Сохранено случаев: {len(records)}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Офлайн-пилот качества Hermes AI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="показать финансовый допуск и лимиты")
    subparsers.add_parser("cases", help="показать эталонные случаи")
    subparsers.add_parser("prepare-live", help="показать условия подготовки живого запуска")

    compare = subparsers.add_parser("compare", help="запустить весь локальный mock-набор")
    compare.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    compare.add_argument("--json", action="store_true", dest="as_json")

    run = subparsers.add_parser("run", help="запустить выбранные случаи")
    run.add_argument("--engine", choices=("mock", "live"), default="mock")
    run.add_argument("--case", action="append", dest="cases")
    run.add_argument("--all", action="store_true", help="все случаи; только для mock")
    run.add_argument("--owner-approved", action="store_true")
    run.add_argument("--account-status", type=Path)
    run.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    run.add_argument("--state", type=Path, default=DEFAULT_STATE)
    run.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    args = _parser().parse_args(argv)
    try:
        if args.command == "status":
            _json(status())
            return 0
        if args.command == "cases":
            _json(_cases())
            return 0
        if args.command == "prepare-live":
            print(prepare_live_instructions())
            return 0
        if args.command == "compare":
            records = run_pilot(engine="mock", cases=case_names(), output=args.output)
            if args.as_json:
                _json(records)
            else:
                _report(records)
            return 0

        cases = list(args.cases or [])
        if args.all:
            if args.engine != "mock":
                raise PilotError("all_cases_live_denied")
            if cases:
                raise PilotError("all_and_case_conflict")
            cases = case_names()
        elif not cases:
            if args.engine == "mock":
                cases = case_names()
            else:
                raise PilotError("live_case_required")
        records = run_pilot(
            engine=args.engine,
            cases=cases,
            output=args.output,
            state=args.state,
            owner_approved=args.owner_approved,
            account_status=args.account_status,
        )
        if args.as_json:
            _json(records)
        else:
            _report(records)
        return 0
    except PilotError as exc:
        print(f"ОТКАЗ: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
