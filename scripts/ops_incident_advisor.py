"""Run one bounded Ops Incident Advisor experiment through Hermes Agent."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

from ops_watch.incident_advisor import (
    SCENARIOS,
    AdvisorInputError,
    AdvisorOutputError,
    build_prompt,
    evaluate_result,
    mock_result,
    prepare_context,
    validate_result,
)
from ops_watch.advisor_comparison import compare_scenarios
from ops_watch.advisor_adapter import (
    AdvisorAdapterError,
    read_events,
    rules_assessment as adapter_rules_assessment,
)
from scripts.bounded_subprocess import BoundedProcessError, run_bounded

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = "hermes-agent-v0221-native-tool-policy:20261015"
MAX_INPUT_BYTES = 16_384
MAX_STDOUT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_RUNTIME_SECONDS = 45
MOCK_MARKER = "__MOCK_REQUESTS__:"
EXPECTED_REJECTIONS = frozenset({"invalid_input", "prompt_injection"})


class AdvisorRuntimeError(RuntimeError):
    """A bounded local agent run could not produce a verified result."""


def _load_event(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise AdvisorInputError("invalid_input_file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AdvisorInputError("invalid_input_file") from exc
    if not isinstance(value, dict):
        raise AdvisorInputError("input_must_be_object")
    return value


def _stage_files(directory: Path) -> None:
    package = directory / "ops_watch"
    package.mkdir()
    for name in ("__init__.py", "core.py", "incident_advisor.py", "mock_provider.py"):
        shutil.copyfile(ROOT / "ops_watch" / name, package / name)
    config = """model:
  provider: custom
  default: ops-incident-mock-v1
  base_url: http://127.0.0.1:8765/v1
  api_key: no-key-required
toolsets: []
agent:
  max_turns: 1
  api_max_retries: 1
  auto_recovery_cycles: 0
  reasoning_effort: none
  disabled_toolsets:
    - hermes-cli
auxiliary:
  title_generation:
    enabled: false
memory:
  memory_enabled: false
  user_profile_enabled: false
"""
    (directory / "config.yaml").write_text(config, encoding="utf-8")


def docker_command(staging: Path, image: str, prompt: str) -> list[str]:
    """Build the only supported local container invocation."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", image):
        raise AdvisorRuntimeError("invalid_agent_image")
    mount = f"type=bind,src={staging.resolve()},dst=/opt/hermes-input,readonly"
    shell = (
        "mkdir -p /tmp/hermes-home || exit 125; "
        "cp /opt/hermes-input/config.yaml /tmp/hermes-home/config.yaml || exit 125; "
        "export HERMES_HOME=/tmp/hermes-home HOME=/tmp/hermes-home "
        "PYTHONPATH=/opt/hermes-input; "
        "/opt/hermes/.venv/bin/python -m ops_watch.mock_provider "
        "--port 8765 --count-file /tmp/mock-count >/tmp/mock-provider.log 2>&1 & "
        "server=$!; sleep 0.2; "
        "/opt/hermes/.venv/bin/hermes --ignore-rules "
        "--in /tmp/hermes-home -z \"$1\" --provider custom "
        "-m ops-incident-mock-v1 --reasoning none -t \"\"; "
        "rc=$?; count=0; "
        "if [ -f /tmp/mock-count ]; then count=$(cat /tmp/mock-count); fi; "
        "printf '\\n__MOCK_REQUESTS__:%s\\n' \"$count\"; "
        "kill \"$server\" 2>/dev/null || true; exit \"$rc\""
    )
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--init",
        "--network",
        "none",
        "--read-only",
        "--user",
        "10000:10000",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "96",
        "--cpus",
        "0.30",
        "--memory",
        "640m",
        "--memory-swap",
        "896m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=32m",
        "--tmpfs",
        "/run:rw,nosuid,nodev,size=8m",
        "--mount",
        mount,
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        shell,
        "hermes-incident-advisor",
        prompt,
    ]


def _run_docker(context: dict[str, object], image: str) -> tuple[str, int, float]:
    prompt = build_prompt(context)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="hermes-incident-advisor-") as raw_directory:
        staging = Path(raw_directory)
        _stage_files(staging)
        if shutil.which("docker") is None:
            raise AdvisorRuntimeError("docker_unavailable")
        try:
            completed = run_bounded(
                docker_command(staging, image, prompt),
                timeout=MAX_RUNTIME_SECONDS,
                stdout_limit=MAX_STDOUT_BYTES,
                stderr_limit=MAX_STDERR_BYTES,
            )
        except BoundedProcessError as exc:
            raise AdvisorRuntimeError(str(exc)) from None
    try:
        output = completed.stdout.decode("utf-8", "strict")
    except UnicodeError:
        raise AdvisorRuntimeError("invalid_agent_output_encoding") from None
    if MOCK_MARKER not in output:
        raise AdvisorRuntimeError("mock_request_count_unknown")
    raw_response, raw_count = output.rsplit(MOCK_MARKER, 1)
    try:
        request_count = int(raw_count.strip().splitlines()[0])
    except (IndexError, ValueError) as exc:
        raise AdvisorRuntimeError("invalid_mock_request_count") from exc
    if completed.returncode != 0:
        raise AdvisorRuntimeError("agent_process_failed")
    if request_count != 1:
        raise AdvisorRuntimeError("model_call_budget_violation")
    return raw_response.strip(), request_count, time.monotonic() - started


def run_event(
    event: dict[str, object], *, scenario: str, engine: str, image: str
) -> dict[str, object]:
    context = prepare_context(event)
    started = time.monotonic()
    if engine == "offline":
        raw = json.dumps(mock_result(context), ensure_ascii=False, sort_keys=True)
        request_count = 0
        agent_path = "NOT_RUN: in-process mock only"
        elapsed = time.monotonic() - started
    else:
        raw, request_count, elapsed = _run_docker(context, image)
        agent_path = "Hermes Agent one-shot via custom OpenAI-compatible mock provider"
    result = validate_result(raw, context)
    return {
        "status": "ok",
        "scenario": scenario,
        "provider_status": "MOCK_ONLY",
        "engine": engine,
        "agent_path": agent_path,
        "model_calls": request_count,
        "elapsed_seconds": round(elapsed, 3),
        "result": result,
        "evaluation": evaluate_result(context, result),
    }


def _one(name: str, event: dict[str, object], engine: str, image: str) -> dict[str, object]:
    try:
        return run_event(event, scenario=name, engine=engine, image=image)
    except AdvisorInputError as exc:
        return {"status": "rejected", "scenario": name, "reason": str(exc)}
    except (AdvisorOutputError, AdvisorRuntimeError) as exc:
        return {"status": "blocked", "scenario": name, "reason": str(exc)}


def _report(payload: dict[str, object]) -> None:
    print("Ops Incident Advisor")
    print(f"Сценарий: {payload.get('scenario', 'batch')}")
    print(f"Статус: {payload['status']}")
    if payload["status"] != "ok":
        print(f"Причина: {payload.get('reason', 'unknown')}")
        return
    print(f"Провайдер: {payload['provider_status']}")
    print(f"Контур: {payload['agent_path']}")
    print(f"Вызовов модели: {payload['model_calls']}")
    print(f"Время: {payload['elapsed_seconds']} с")
    result = payload["result"]
    print(f"\nЧто произошло: {result['what_happened']}")
    print(f"На что влияет: {result['impact']}")
    cause = result["probable_cause"]
    print(f"Вероятная причина: {cause['summary']} (неопределённость: {cause['uncertainty']})")
    print("Доказательства:")
    for item in result["evidence"]:
        print(f"- {item}")
    print("Что проверить:")
    for item in result["checks"]:
        print(f"- {item}")
    print(f"Рекомендация: {result['recommendation']}")
    print(f"Приоритет: {result['priority']}")
    print(f"Статус инцидента: {result['status']}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Bounded Ops Incident Advisor demo")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", choices=sorted(SCENARIOS))
    group.add_argument("--input", type=Path)
    group.add_argument("--all", action="store_true")
    group.add_argument("--compare", action="store_true")
    group.add_argument("--ops-watch-db", type=Path)
    parser.add_argument("--engine", choices=("docker", "offline"), default="docker")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument(
        "--provenance",
        choices=("synthetic", "anonymized_copy", "readonly_snapshot"),
        default="readonly_snapshot",
    )
    parser.add_argument("--event-id", type=int)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    if args.compare:
        rows = compare_scenarios(include_mock=args.engine == "offline")
        if args.as_json:
            print(json.dumps(rows, ensure_ascii=False, sort_keys=True))
        else:
            for row in rows:
                print(json.dumps(row, ensure_ascii=False, sort_keys=True))
        return 0
    if args.ops_watch_db:
        try:
            adapted = read_events(
                args.ops_watch_db,
                provenance=args.provenance,
                event_id=args.event_id,
            )
            payloads = []
            for item in adapted:
                scenario = f"ops_watch_event_{item['event_id']}"
                if item["analysis"]["decision"] == "RULES_ONLY":
                    payloads.append({
                        "status": "rules_only",
                        "scenario": scenario,
                        "provenance": item["provenance"],
                        "analysis": item["analysis"],
                        "rules": adapter_rules_assessment(item),
                    })
                else:
                    payload = _one(scenario, item["event"], args.engine, args.image)
                    payload["provenance"] = item["provenance"]
                    payload["analysis"] = item["analysis"]
                    payloads.append(payload)
        except AdvisorAdapterError as exc:
            payloads = [{
                "status": "rejected", "scenario": "ops_watch", "reason": str(exc),
            }]
    elif args.input:
        try:
            payloads = [
                _one(
                    "input",
                    _load_event(args.input),
                    args.engine,
                    args.image,
                )
            ]
        except AdvisorInputError as exc:
            payloads = [{"status": "rejected", "scenario": "input", "reason": str(exc)}]
    elif args.all:
        payloads = [_one(name, event, args.engine, args.image) for name, event in SCENARIOS.items()]
    else:
        assert args.scenario is not None
        payloads = [_one(args.scenario, SCENARIOS[args.scenario], args.engine, args.image)]

    if args.as_json:
        print(json.dumps(payloads if len(payloads) > 1 else payloads[0], ensure_ascii=False, sort_keys=True))
    elif len(payloads) == 1:
        _report(payloads[0])
    else:
        for payload in payloads:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))

    if len(payloads) > 1:
        unexpected = [
            item
            for item in payloads
            if item["status"] == "blocked"
            or (item["status"] == "rejected" and item.get("scenario") not in EXPECTED_REJECTIONS)
        ]
        return 1 if unexpected else 0
    return 0 if payloads[0]["status"] in {"ok", "rules_only"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
