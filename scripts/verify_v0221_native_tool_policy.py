"""Bounded offline proof of the v0.22.1 native tool-policy boundary.

The original pinned image and a local, explicitly patched derivative run the same
deterministic synthetic AIAgent/tool-call cases. No provider, shell, connector,
secret or production endpoint is used. The derivative is evidence for the
upstream patch only; it is not the official image or a deployment artifact.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import subprocess
import threading
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import patch

from . import verify_v0221_core_python as core
from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0221_local_image import IMAGE

PATCHED_IMAGE = "hermes-agent-v0221-native-tool-policy:20261015"
SCHEMA = "hermes-v0221-native-tool-policy-v1"
SECRET = "SYNTHETIC_SECRET_DO_NOT_PRINT"
MAX_REPLY = 80_000
BLOCKED_CASES = frozenset({
    "direct_terminal",
    "direct_alias",
    "agent_stale_native",
    "agent_full_loop",
    "agent_tool_search",
    "agent_unknown",
    "direct_bad_policy_shape",
    "request_hook_error",
    "pre_hook_error",
    "approval_error",
    "execution_hook_error",
    "registry_policy_error",
    "repeat_after_denial",
    "connector_batch",
})
REQUIRED_CASES = BLOCKED_CASES | {
    "direct_allowed",
    "agent_fresh_native",
    "execution_arg_recheck",
    "execute_code_nested_scope",
    "parallel_policy",
    "subagent_scope",
}


class NativePolicyDenied(ValueError):
    """Fixed evidence errors; never expose inspector output or exception text."""


INSPECTOR = r"""
import contextlib
import io
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import model_tools
import run_agent
from hermes_cli import middleware as middleware_module
from tools import delegate_tool_toolsets, tool_search

SECRET = "SYNTHETIC_SECRET_DO_NOT_PRINT"
secret_seen = False


class Recorder:
    def __init__(self):
        self.calls = 0
        self.args = []
        self.names = []
        self.lock = threading.Lock()

    def __call__(self, *args, **kwargs):
        with self.lock:
            self.calls += 1
            self.args.append(args[1] if len(args) > 1 else None)
            self.names.append(args[0] if args else None)
        return "SYNTHETIC_EXECUTOR_RESULT"


def run_quiet(fn):
    global secret_seen
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            value = fn()
        if SECRET in output.getvalue() or SECRET in repr(value):
            secret_seen = True
        return value, False
    except Exception:
        if SECRET in output.getvalue():
            secret_seen = True
        return None, True


def result_row(fn, recorder=None):
    value, failed = run_quiet(fn)
    row = {
        "exception": failed,
        "executor_reached": bool(recorder and recorder.calls),
    }
    if isinstance(value, dict):
        row.update({key: value for key, value in value.items()
                    if key in {
                        "modified_approval_seen", "nested_terminal_allowed",
                        "nested_web_search_allowed",
                    }})
    return row


def direct_case(name, args, enabled, disabled, *, execution_middleware=False):
    recorder = Recorder()

    def invoke():
        with patch.object(model_tools, "_execute_tool", side_effect=recorder):
            return model_tools.handle_function_call(
                name,
                args,
                enabled_toolsets=enabled,
                disabled_toolsets=disabled,
                skip_tool_execution_middleware=not execution_middleware,
            )

    return result_row(invoke, recorder)


def make_agent(disabled, *, max_iterations=9223372036854775807):
    return run_agent.AIAgent(
        base_url="http://127.0.0.1:9/v1",
        api_key="SYNTHETIC_PROVIDER_KEY",
        provider="openai",
        model="synthetic",
        max_iterations=max_iterations,
        enabled_toolsets=["hermes-cli"],
        disabled_toolsets=disabled,
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        skip_background_review=True,
        cwd="/tmp",
    )


def agent_case(name, args, disabled, *, stale=False):
    recorder = Recorder()

    def invoke():
        agent = make_agent([] if stale else disabled)
        if stale:
            agent.disabled_toolsets = ["terminal"]
        message = SimpleNamespace(
            content=None,
            tool_calls=[SimpleNamespace(
                id="synthetic-call",
                type="function",
                function=SimpleNamespace(
                    name=name,
                    arguments=json.dumps(args, separators=(",", ":")),
                ),
            )],
        )
        with patch.object(model_tools, "_execute_tool", side_effect=recorder):
            agent._execute_tool_calls(message, [], "synthetic-task")

    return result_row(invoke, recorder)


def agent_full_loop_case():
    recorder = Recorder()

    response = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(
                content=None,
                tool_calls=[SimpleNamespace(
                    id="synthetic-call",
                    type="function",
                    function=SimpleNamespace(
                        name="terminal",
                        arguments=json.dumps(
                            {"command": "SYNTHETIC_NO_EXEC"},
                            separators=(",", ":"),
                        ),
                    ),
                )],
            ),
            finish_reason="tool_calls",
        )],
        usage=None,
    )

    def invoke():
        agent = make_agent(["terminal"], max_iterations=1)
        agent._disable_streaming = True
        # Deliberately keep the model-facing cache permissive: the final dispatch
        # check must still enforce the session policy.
        agent.valid_tool_names = ["terminal"]
        with patch.object(agent, "_interruptible_api_call", return_value=response):
            with patch.object(agent, "_flush_messages_to_session_db", return_value=True):
                with patch.object(agent, "_persist_session", return_value=None):
                    with patch.object(model_tools, "_execute_tool", side_effect=recorder):
                        agent.run_conversation(
                            "SYNTHETIC_USER",
                            conversation_history=[],
                            task_id="synthetic-task",
                        )

    return result_row(invoke, recorder)


def failing_request_hook_case():
    recorder = Recorder()

    def invoke():
        with patch("hermes_cli.middleware.apply_tool_request_middleware",
                   side_effect=RuntimeError(SECRET)):
            with patch.object(model_tools, "_execute_tool", side_effect=recorder):
                return model_tools.handle_function_call(
                    "web_search", {"query": "SYNTHETIC_QUERY"},
                    enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    skip_tool_execution_middleware=True,
                )

    return result_row(invoke, recorder)


def failing_pre_hook_case():
    recorder = Recorder()

    def invoke():
        with patch("hermes_cli.plugins._dispatch_pre_tool_call_hooks",
                   side_effect=RuntimeError(SECRET)):
            with patch.object(model_tools, "_execute_tool", side_effect=recorder):
                return model_tools.handle_function_call(
                    "web_search", {"query": "SYNTHETIC_QUERY"},
                    enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    skip_tool_execution_middleware=True,
                )

    return result_row(invoke, recorder)


def failing_approval_case():
    recorder = Recorder()

    def invoke():
        with patch("acp_adapter.edit_approval.maybe_require_edit_approval",
                   side_effect=RuntimeError(SECRET)):
            with patch.object(model_tools, "_execute_tool", side_effect=recorder):
                return model_tools.handle_function_call(
                    "web_search", {"query": "SYNTHETIC_QUERY"},
                    enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    skip_tool_execution_middleware=True,
                )

    return result_row(invoke, recorder)


def failing_execution_hook_case():
    recorder = Recorder()

    def callback(**_kwargs):
        raise RuntimeError(SECRET)

    manager = SimpleNamespace(
        _middleware={middleware_module.TOOL_EXECUTION_MIDDLEWARE: [callback]},
        _report_hook_failure=lambda *_args, **_kwargs: None,
    )

    def invoke():
        with patch("hermes_cli.plugins._dispatch_pre_tool_call_hooks",
                   return_value=(None, None)):
            with patch("hermes_cli.plugins._delivery_manager", return_value=manager):
                with patch.object(model_tools.registry, "dispatch", side_effect=recorder):
                    return model_tools.handle_function_call(
                        "web_search", {"query": "SYNTHETIC_QUERY"},
                        enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    )

    return result_row(invoke, recorder)


def execution_arg_recheck_case():
    recorder = Recorder()
    approvals = []

    def callback(**kwargs):
        return kwargs["next_call"]({
            "path": "SYNTHETIC_MODIFIED",
            "content": "SYNTHETIC_CONTENT",
        })

    manager = SimpleNamespace(
        _middleware={middleware_module.TOOL_EXECUTION_MIDDLEWARE: [callback]},
        _report_hook_failure=lambda *_args, **_kwargs: None,
    )

    def approval(_name, args):
        approvals.append(dict(args))
        return None

    def invoke():
        with patch("hermes_cli.plugins._dispatch_pre_tool_call_hooks",
                   return_value=(None, None)):
            with patch("hermes_cli.plugins._delivery_manager", return_value=manager):
                with patch("acp_adapter.edit_approval.maybe_require_edit_approval",
                           side_effect=approval):
                    with patch.object(model_tools.registry, "dispatch", side_effect=recorder):
                        model_tools.handle_function_call(
                            "write_file",
                            {"path": "SYNTHETIC_ORIGINAL", "content": "SYNTHETIC_CONTENT"},
                            enabled_toolsets=["hermes-cli"], disabled_toolsets=[],
                        )
        return {"modified_approval_seen": any(
            item.get("path") == "SYNTHETIC_MODIFIED" for item in approvals
        )}

    return result_row(invoke, recorder)


def execute_code_nested_scope_case():
    recorder = Recorder()
    dispatched = []

    def dispatch(_name, _args, **kwargs):
        dispatched.append(list(kwargs.get("enabled_tools") or []))
        return recorder(_name, _args, **kwargs)

    def invoke():
        with patch.object(model_tools.registry, "dispatch", side_effect=dispatch):
            model_tools.handle_function_call(
                "execute_code",
                {"code": "SYNTHETIC_CODE"},
                enabled_tools=["terminal", "web_search"],
                enabled_toolsets=["code_execution", "hermes-cli"],
                disabled_toolsets=["terminal"],
                skip_tool_execution_middleware=True,
            )
        return {
            "nested_terminal_allowed": bool(dispatched and "terminal" in dispatched[-1]),
            "nested_web_search_allowed": bool(dispatched and "web_search" in dispatched[-1]),
        }

    return result_row(invoke, recorder)


def registry_policy_error_case():
    recorder = Recorder()

    def invoke():
        with patch.object(model_tools, "_select_tool_names",
                          side_effect=RuntimeError(SECRET)):
            with patch.object(model_tools, "_execute_tool", side_effect=recorder):
                return model_tools.handle_function_call(
                    "web_search", {"query": "SYNTHETIC_QUERY"},
                    enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    skip_tool_execution_middleware=True,
                )

    return result_row(invoke, recorder)


def repeat_after_denial_case():
    recorder = Recorder()

    def invoke():
        with patch.object(model_tools, "_execute_tool", side_effect=recorder):
            for _ in range(2):
                model_tools.handle_function_call(
                    "terminal", {"command": "SYNTHETIC_NO_EXEC"},
                    enabled_toolsets=["safe"], disabled_toolsets=["terminal"],
                    skip_tool_execution_middleware=True,
                )

    return result_row(invoke, recorder)


def parallel_policy_case():
    recorder = Recorder()
    barrier = threading.Barrier(2)

    def invoke(name, enabled, disabled):
        barrier.wait()
        model_tools.handle_function_call(
            name,
            {"query": "SYNTHETIC_QUERY"} if name == "web_search"
            else {"command": "SYNTHETIC_NO_EXEC"},
            enabled_toolsets=enabled,
            disabled_toolsets=disabled,
            skip_tool_execution_middleware=True,
        )

    def run_pair():
        with patch.object(model_tools, "_execute_tool", side_effect=recorder):
            with ThreadPoolExecutor(max_workers=2) as pool:
                restricted = pool.submit(
                    invoke, "terminal", ["hermes-cli"], ["terminal"],
                )
                allowed = pool.submit(
                    invoke, "web_search", ["safe"], ["terminal"],
                )
                restricted.result()
                allowed.result()

    _, failed = run_quiet(run_pair)
    names = list(recorder.names)
    return {
        "exception": failed,
        "executor_reached": bool(names),
        "restricted_executor_reached": "terminal" in names,
        "allowed_executor_reached": "web_search" in names,
    }


def connector_batch_case():
    recorder = Recorder()

    def invoke():
        with patch.object(model_tools, "_execute_tool", side_effect=recorder):
            model_tools.handle_function_call(
                "tool_call",
                {
                    "name": tool_search.CONNECTOR_BATCH_SENTINEL,
                    "arguments": {"calls": [{
                        "name": "connectors__synthetic__read",
                        "arguments": {},
                    }]},
                },
                enabled_toolsets=["safe"], disabled_toolsets=[],
                skip_tool_execution_middleware=True,
            )

    return result_row(invoke, recorder)


def subagent_scope_case():
    def invoke():
        parent = SimpleNamespace(
            enabled_toolsets=["hermes-cli"],
            disabled_toolsets=["terminal"],
            valid_tool_names=[],
        )
        enabled, disabled = delegate_tool_toolsets._resolve_child_toolsets(
            parent, ["hermes-cli"], "leaf",
        )
        selected = model_tools._select_tool_names(enabled, disabled, quiet_mode=True)
        return {
            "terminal_in_child": "terminal" in selected,
            "terminal_in_disabled": "terminal" in disabled,
        }

    value, failed = run_quiet(invoke)
    return {
        "exception": failed,
        "executor_reached": False,
        "terminal_in_child": bool(value and value.get("terminal_in_child")),
        "terminal_in_disabled": bool(value and value.get("terminal_in_disabled")),
    }


def main():
    cases = {
        "direct_terminal": direct_case(
            "terminal", {"command": "SYNTHETIC_NO_EXEC"}, ["safe"], ["terminal"],
        ),
        "direct_alias": direct_case(
            "process", {"action": "list"}, ["safe"], ["terminal"],
        ),
        "direct_allowed": direct_case(
            "web_search", {"query": "SYNTHETIC_QUERY"}, ["safe"], ["terminal"],
        ),
        "agent_fresh_native": agent_case(
            "terminal", {"command": "SYNTHETIC_NO_EXEC"}, ["terminal"],
        ),
        "agent_stale_native": agent_case(
            "terminal", {"command": "SYNTHETIC_NO_EXEC"}, [], stale=True,
        ),
        "agent_full_loop": agent_full_loop_case(),
        "agent_tool_search": agent_case(
            "tool_call",
            {"name": "terminal", "arguments": {"command": "SYNTHETIC_NO_EXEC"}},
            ["terminal"],
        ),
        "agent_unknown": agent_case(
            "synthetic_unknown", {}, [],
        ),
        "direct_bad_policy_shape": direct_case(
            "web_search", {"query": "SYNTHETIC_QUERY"}, "safe", [],
        ),
        "request_hook_error": failing_request_hook_case(),
        "pre_hook_error": failing_pre_hook_case(),
        "approval_error": failing_approval_case(),
        "execution_hook_error": failing_execution_hook_case(),
        "execution_arg_recheck": execution_arg_recheck_case(),
        "execute_code_nested_scope": execute_code_nested_scope_case(),
        "registry_policy_error": registry_policy_error_case(),
        "repeat_after_denial": repeat_after_denial_case(),
        "parallel_policy": parallel_policy_case(),
        "connector_batch": connector_batch_case(),
        "subagent_scope": subagent_scope_case(),
    }
    print(json.dumps({
        "schema": "hermes-v0221-native-tool-policy-v1",
        "mode": os.environ.get("HERMES_SCOPE_PROBE_MODE", "unknown"),
        "cases": cases,
        "secret_exposed": secret_seen,
        "model_executed": False,
        "real_tool_executed": False,
    }, sort_keys=True, separators=(",", ":")))


main()
"""


def commands(image: str = IMAGE) -> tuple[list[str], list[str]]:
    inspect_format = "{{json .RepoDigests}}|{{.Architecture}}"
    if image != IMAGE:
        inspect_format = "{{json .RepoDigests}}|{{.Id}}|{{.Architecture}}"
    inspect = ["docker", "image", "inspect", image, "--format", inspect_format]
    run = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.5", "--memory", "768m", "--memory-swap", "768m",
        "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--env", "HOME=/tmp", "--env", "HERMES_HOME=/tmp/hermes",
        "--env", "HERMES_SCOPE_PROBE_MODE="
        + ("patched" if image != IMAGE else "original"),
        "--entrypoint", "/opt/hermes/.venv/bin/python", image,
        "-B", "-c", INSPECTOR,
    ]
    return inspect, run


def _packet(raw: bytes) -> dict[str, Any]:
    try:
        packet = core._json(raw, limit=MAX_REPLY)
    except core.ParityDenied:
        raise NativePolicyDenied("invalid_probe_json") from None
    if (type(packet) is not dict
            or set(packet) != {
                "cases", "mode", "model_executed", "real_tool_executed",
                "schema", "secret_exposed",
            }
            or packet["schema"] != SCHEMA
            or packet["mode"] not in {"original", "patched"}
            or any(type(packet[name]) is not bool for name in (
                "model_executed", "real_tool_executed", "secret_exposed"))
            or packet["model_executed"] or packet["real_tool_executed"]
            or packet["secret_exposed"]
            or type(packet["cases"]) is not dict
            or set(packet["cases"]) != REQUIRED_CASES):
        raise NativePolicyDenied("invalid_probe_contract")
    for row in packet["cases"].values():
        if (type(row) is not dict
                or type(row.get("executor_reached")) is not bool
                or type(row.get("exception")) is not bool):
            raise NativePolicyDenied("invalid_case_contract")
        for field in (
            "modified_approval_seen", "nested_terminal_allowed",
            "nested_web_search_allowed", "restricted_executor_reached",
            "allowed_executor_reached", "terminal_in_child", "terminal_in_disabled",
        ):
            if field in row and type(row[field]) is not bool:
                raise NativePolicyDenied("invalid_case_contract")
    return packet


def _local_image_identity(raw: bytes) -> None:
    try:
        digests, image_id, arch = raw.decode("utf-8").strip().split("|")
        json.loads(digests)
    except (ValueError, UnicodeError):
        raise NativePolicyDenied("patched_image_metadata_invalid") from None
    if not image_id.startswith("sha256:") or arch != "amd64":
        raise NativePolicyDenied("patched_image_identity_invalid")


def validate(original_raw: bytes, patched_raw: bytes) -> dict[str, Any]:
    original = _packet(original_raw)
    patched = _packet(patched_raw)
    if original["mode"] != "original" or patched["mode"] != "patched":
        raise NativePolicyDenied("probe_mode_mismatch")

    baseline_gap = all(original["cases"][name]["executor_reached"] for name in (
        "direct_terminal", "direct_alias", "agent_stale_native",
        "agent_full_loop",
        "request_hook_error", "pre_hook_error", "approval_error",
        "execution_hook_error", "registry_policy_error",
    )) and original["cases"]["execute_code_nested_scope"].get(
        "nested_terminal_allowed"
    ) is True and original["cases"]["parallel_policy"].get(
        "restricted_executor_reached"
    ) is True
    protected = all(not patched["cases"][name]["executor_reached"]
                    for name in BLOCKED_CASES if name != "subagent_scope")
    allowed = (
        patched["cases"]["direct_allowed"]["executor_reached"]
        and patched["cases"]["execution_arg_recheck"]["executor_reached"]
        and patched["cases"]["execution_arg_recheck"].get("modified_approval_seen") is True
        and patched["cases"]["execute_code_nested_scope"].get("executor_reached") is True
        and patched["cases"]["execute_code_nested_scope"].get("nested_terminal_allowed") is False
        and patched["cases"]["execute_code_nested_scope"].get("nested_web_search_allowed") is True
        and patched["cases"]["parallel_policy"].get("restricted_executor_reached") is False
        and patched["cases"]["parallel_policy"].get("allowed_executor_reached") is True
        and patched["cases"]["subagent_scope"].get("terminal_in_child") is False
        and patched["cases"]["subagent_scope"].get("terminal_in_disabled") is True
    )
    fresh_surface = (
        not patched["cases"]["agent_fresh_native"]["executor_reached"]
        and not patched["cases"]["agent_tool_search"]["executor_reached"]
        and not patched["cases"]["agent_unknown"]["executor_reached"]
    )
    status = (
        "PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS"
        if baseline_gap and protected and allowed and fresh_surface
        else "NATIVE_TOOL_POLICY_EVIDENCE_INCOMPLETE"
    )
    return {
        "status": status,
        "pinned_image": IMAGE,
        "patched_test_image": PATCHED_IMAGE,
        "original_low_level_gap_reproduced": baseline_gap,
        "patched_checked_paths_blocked": protected,
        "allowed_synthetic_paths_work": allowed,
        "full_agent_surface_verified": fresh_surface,
        "secret_free_denials": True,
        "model_executed": False,
        "real_tool_executed": False,
        "production_verified": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> dict[str, Any]:
    packets = []
    for image in (IMAGE, PATCHED_IMAGE):
        inspect, run = commands(image)
        try:
            metadata = runner(inspect, timeout=10, stdout_limit=8192, stderr_limit=16384)
            if metadata.returncode:
                raise NativePolicyDenied("image_missing")
            if image == IMAGE:
                core.image_identity(metadata.stdout)
            else:
                _local_image_identity(metadata.stdout)
            result = runner(run, timeout=90, stdout_limit=MAX_REPLY, stderr_limit=16384)
            if result.returncode:
                raise NativePolicyDenied("inspector_failed")
            packets.append(result.stdout)
        except (OSError, subprocess.TimeoutExpired, BoundedProcessError,
                core.ParityDenied):
            raise NativePolicyDenied("offline_docker_unavailable") from None
    return validate(packets[0], packets[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline native tool-policy boundary proof")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        result = observe()
    except NativePolicyDenied:
        print(json.dumps({"status": "NO_DATA", "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
