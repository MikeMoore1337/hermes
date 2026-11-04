#!/usr/bin/env python3
"""H632 model-authored TDD probe in an offline pinned Hermes container.

Independent model-written tests and repair are strictly source-only outputs;
the only executor is the audited synthetic gate. No paid API or model tools.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from urllib.request import urlopen

HOME = Path("/test-home")
ECC_SHA = "8887afa786ef30de834e7567115d3df71934b343c3d9d849714f8ea43f979ee0"
HERMES_SHA = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"


def main() -> None:
    from h632_model_authored_tdd import execute
    original = HOME / ".hermes/skills/tdd-workflow/SKILL.md"
    if hashlib.sha256(original.read_bytes()).hexdigest() != ECC_SHA:
        raise RuntimeError("Unpinned original ECC skill")
    native = json.loads(Path("/opt/hermes/install-stamp.json").read_text())
    if native.get("commit") != HERMES_SHA:
        raise RuntimeError("Unpinned native Hermes runtime")
    guided = json.loads((HOME / "h632-tdd-receipt.json").read_text())
    if (guided.get("status") != "PASS_GUIDED_MODEL_TDD_CYCLE"
            or guided.get("model_read_original_tdd_skill") is not True
            or guided.get("causal_skill_result_precedes_execution") is not True):
        raise RuntimeError("Earlier native model skill_view not proven")
    for forbidden in ("/private-yfc", "/private-second-brain",
                      "/run/secrets", "/var/run/docker.sock"):
        if Path(forbidden).exists():
            raise RuntimeError("Forbidden mounted resource")
    for _ in range(50):
        try:
            with urlopen("http://127.0.0.1:8080/health", timeout=3) as response:
                if response.status == 200:
                    break
        except Exception:
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Offline llama.cpp is not healthy")

    from tools.tool_search import load_config
    if load_config().enabled != "off":
        raise RuntimeError("Hermes tool search must be disabled")
    from run_agent import AIAgent

    calls: list[int] = []
    common = dict(
        base_url="http://127.0.0.1:8080/v1", api_key="free-local-only",
        provider="custom", api_mode="chat_completions", model="h632-local",
        quiet_mode=True, skip_context_files=True, skip_memory=True,
        skip_background_review=True, save_trajectories=False,
    )

    def generate(prompt: str, tokens: int) -> str:
        agent = AIAgent(**common, enabled_toolsets=[], max_iterations=2,
                        max_tokens=tokens, run_budget_seconds=250)
        if agent.tools:
            raise RuntimeError("Code-generation agent unexpectedly has tools")
        output = agent.run_conversation(
            prompt, system_message=(
                "/no_think\nOutput only the requested Python source, no Markdown "
                "or narrative. Never access the shell, files, other projects or "
                "network resources. The test harness will check your output."
            ),
        )
        if not isinstance(output, dict):
            raise RuntimeError("Native model returned no result")
        messages = output.get("messages", [])
        if any(m.get("tool_calls") for m in messages if isinstance(m, dict)):
            raise RuntimeError("Unexpected model-origin tool dispatch")
        count = output.get("api_calls") or 0
        if count < 1:
            raise RuntimeError("Model did not make a real API call")
        calls.append(count)
        result = output.get("final_response")
        if not isinstance(result, str) or not result.strip():
            raise RuntimeError("Model did not generate source code")
        return result

    def generate_tests() -> str:
        return generate(
            "The original ECC tdd-workflow instructions were obtained through "
            "native skill_view in the preceding model session. Work TEST-FIRST "
            "on an offline disposable kata: current calc.add SUBTRACTS integers "
            "by mistake. Return the COMPLETE Python source of test_calc.py. "
            "Start with 'from calc import add'. Define exactly two functions "
            "with no parameters, test_add_positive and test_add_negative. "
            "Each contains exactly one assertion. Positive: "
            "assert add(20, 22) == 42. Negative: assert add(-2, 3) == 1. "
            "Do not write the fix yet; output Python code only.", 240,
        )

    def generate_fix() -> str:
        return generate(
            "Your own test_calc.py has now EXECUTED and produced two genuine "
            "AssertionError results against the subtracting implementation. "
            "Following original ECC RED then GREEN, output the COMPLETE "
            "replacement Python source calc.py. It must define exactly one "
            "function add(a: int, b: int) -> int and return the correct sum "
            "of the two operands. No imports or other declarations.", 128,
        )

    try:
        result = execute(HOME / "fixture/h632-model-authored-tdd",
                         generate_tests, generate_fix)
        result.update({
            "native_original_skill_view_preceded_code_generation": True,
            "original_skill_sha256": ECC_SHA,
            "hermes_sha": HERMES_SHA,
            "local_model": "Qwen3.5-2B-Q4_K_M",
            "model_generation_api_calls": calls,
            "model_tool_access": "NONE",
            "autonomous_step_selection": False,
        })
        if len(calls) != 2 or result.get("status") != "PASS_MODEL_WRITTEN_RED_GREEN":
            raise AssertionError("Model-authored TDD evidence incomplete")
        (HOME / "h632-model-authored-receipt.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("H632_REAL_NATIVE_MODEL_AUTHORED_TEST_AND_FIX=PASS")
    except Exception as exc:
        (HOME / "h632-model-authored-failure.json").write_text(
            json.dumps({"schema": "hermes-h632-model-authored-failure-v1",
                        "status": "FAIL_NOT_PROVEN", "kind": type(exc).__name__,
                        "diagnostic": str(exc)[:160], "api_calls": calls},
                       sort_keys=True) + "\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    main()
