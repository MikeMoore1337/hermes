"""H-19 bounded physical-effect canaries for the actual pinned Hermes dispatcher.

The probe executes in an isolated, networkless Docker container with
synthetic tool arguments. It intercepts the native low-level executor and
writes a harmless marker to a private tmpfs directory as an effect canary.
It NEVER invokes any real MCP connector, terminal command or provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0222_immutable import (
    IMAGE, EXPECTED_SOURCE, commands, patched_commands, image_identity,
    stamp_details,
)

SCHEMA = "h19-native-effect-canary-v1"
CASES = {
    "direct_terminal": "DENY",
    "direct_alias": "DENY",
    "tool_search_terminal": "DENY",
    "connector_batch": "DENY",
    "unknown_native": "DENY",
    "allowed_web_read": "ALLOW_STUB",
}
MARKER = b"H19_DISPATCH_CANARY_NO_REAL_TOOL"
MARKER_SHA256 = hashlib.sha256(MARKER).hexdigest()
# Every tool execution is INTERCEPTED before a real network, shell, filesystem
# or MCP operation is reached. The only side effect is a harmless fixed marker
# in private /tmp. The actual Hermes policy and dispatch code still executes.
INSPECTOR = r"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import model_tools
from tools import tool_search

SCHEMA = "h19-native-effect-canary-v1"
MARKER = b"H19_DISPATCH_CANARY_NO_REAL_TOOL"

cases = (
    ("direct_terminal", "terminal", {"command": "SYNTHETIC_NO_EXEC"},
     ["safe"], ["terminal"]),
    ("direct_alias", "process", {"action": "list"},
     ["safe"], ["terminal"]),
    ("tool_search_terminal", "tool_call",
     {"name": "terminal", "arguments": {"command": "SYNTHETIC_NO_EXEC"}},
     ["safe"], ["terminal"]),
    ("connector_batch", "tool_call",
     {"name": tool_search.CONNECTOR_BATCH_SENTINEL, "arguments": {
         "calls": [{"name": "connectors__synthetic__read", "arguments": {}}]}},
     ["safe"], []),
    ("unknown_native", "synthetic_unknown_native", {},
     ["safe"], []),
    ("allowed_web_read", "web_search", {"query": "SYNTHETIC_PUBLIC_ONLY"},
     ["safe"], ["terminal"]),
)

result = []
for name, tool, arguments, enabled, disabled in cases:
    with tempfile.TemporaryDirectory(prefix="h19-canary-", dir="/tmp") as tmp:
        marker_path = Path(tmp) / "native-dispatch-marker"
        callbacks = []

        def harmless_marker(*args, **kwargs):
            # No real executor, MCP, filesystem tool, LLM or shell reached.
            callbacks.append("intercepted")
            marker_path.write_bytes(MARKER)
            return "H19_SYNTHETIC_INTERCEPTED_RESULT"

        stdout, stderr = io.StringIO(), io.StringIO()
        failed = False
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with patch.object(model_tools, "_execute_tool", side_effect=harmless_marker):
                    model_tools.handle_function_call(
                        tool, arguments,
                        enabled_toolsets=enabled,
                        disabled_toolsets=disabled,
                        skip_tool_execution_middleware=True,
                    )
        except Exception:
            failed = True

        marker = marker_path.read_bytes() if marker_path.exists() else None
        result.append({
            "scenario_id": name,
            "callback_count": len(callbacks),
            "effect_count": 1 if marker is not None else 0,
            "effect_sha256": hashlib.sha256(marker).hexdigest() if marker is not None else None,
            "handler_exception": failed,
            "result_text_exposed": False,
        })

print(json.dumps({
    "schema": SCHEMA,
    "mode": os.environ.get("HERMES_SCOPE_PROBE_MODE", "unknown"),
    "rows": result,
    "actual_agent_tools_executed": False,
    "real_mcp_called": False,
    "provider_called": False,
    "production_accessed": False,
}, separators=(",", ":"), sort_keys=True))
"""


class CanaryError(ValueError):
    """Do not echo untrusted reports, paths or instrumented tool text."""


def parse_packet(raw: bytes, expected_mode: str) -> dict[str, Any]:
    if len(raw) > 12_000:
        raise CanaryError("oversize_probe_packet")
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise CanaryError("invalid_json") from exc
    if (type(data) is not dict or set(data) != {
        "schema", "mode", "rows", "actual_agent_tools_executed",
        "real_mcp_called", "provider_called", "production_accessed"}
            or data["schema"] != SCHEMA or data["mode"] != expected_mode
            or any(data[field] is not False for field in (
                "actual_agent_tools_executed", "real_mcp_called",
                "provider_called", "production_accessed"))):
        raise CanaryError("invalid_probe_contract")
    rows = data["rows"]
    if type(rows) is not list or len(rows) != len(CASES):
        raise CanaryError("missing_effect_cases")
    out = {}
    for item in rows:
        if (type(item) is not dict or set(item) != {
                "scenario_id", "callback_count", "effect_count",
                "effect_sha256", "handler_exception", "result_text_exposed"}
                or type(item["scenario_id"]) is not str
                or item["scenario_id"] not in CASES
                or item["scenario_id"] in out
                or type(item["callback_count"]) is not int
                or item["callback_count"] not in (0, 1)
                or type(item["effect_count"]) is not int
                or item["effect_count"] not in (0, 1)
                or type(item["handler_exception"]) is not bool
                or item["result_text_exposed"] is not False
                or (item["effect_sha256"] is not None and
                    (type(item["effect_sha256"]) is not str or
                     re.fullmatch(r"[0-9a-f]{64}", item["effect_sha256"]) is None))):
            raise CanaryError("invalid_effect_row")
        if (item["callback_count"] != item["effect_count"]
                or item["effect_sha256"] != (
                    MARKER_SHA256 if item["effect_count"] else None)):
            raise CanaryError("effect_receipt_mismatch")
        out[item["scenario_id"]] = item
    if set(out) != set(CASES):
        raise CanaryError("missing_effect_cases")
    return out


def compare(original_raw: bytes, patched_raw: bytes, *,
            derivative_id: str) -> dict[str, Any]:
    baseline = parse_packet(original_raw, "original")
    derivative = parse_packet(patched_raw, "patched")
    if type(derivative_id) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", derivative_id) is None:
        raise CanaryError("derivative_identity_invalid")
    checks = []
    for name, expected in CASES.items():
        old_effect = baseline[name]["effect_count"]
        new_effect = derivative[name]["effect_count"]
        expected_old = 1  # proof sensitivity: original unguarded dispatcher reaches interception
        expected_new = 1 if expected == "ALLOW_STUB" else 0
        success = old_effect == expected_old and new_effect == expected_new
        checks.append({
            "scenario_id": "h19-effect-" + name,
            "expected_behavior": expected,
            "original_tmpfs_effect": bool(old_effect),
            "patched_tmpfs_effect": bool(new_effect),
            "verification_status": "PASS" if success else "FAIL",
        })
    safe = all(row["verification_status"] == "PASS" for row in checks)
    return {
        "schema": SCHEMA,
        "mode": "real_pinned_dispatch_intercepted_tmpfs",
        "original_image": IMAGE,
        "source_stamp": EXPECTED_SOURCE,
        "patched_derivative_id": derivative_id,
        "scenario_count": len(CASES),
        "physical_effect_canary_count": sum(
            bool(row["original_tmpfs_effect"]) for row in checks),
        "checks": checks,
        "status": "PASS" if safe else "FAIL",
        "real_mcp_called": False,
        "actual_agent_tools_executed": False,
        "provider_called": False,
        "production_accessed": False,
        "full_mcp_permission_enforcement_verified": False,
        "resident_agent_allowed": False,
        "real_model_evaluation": "NOT_RUN",
    }


def execute(*, runner=run_bounded) -> tuple[int, dict[str, Any]]:
    original_inspect, stamp_cmd, original_cmd = commands()
    derivative_inspect, derivative_cmd = patched_commands()
    try:
        info = runner(original_inspect, timeout=20, stdout_limit=8192, stderr_limit=8192)
        if info.returncode or not image_identity(info.stdout):
            raise CanaryError("original_identity_invalid")
        stamp = runner(stamp_cmd, timeout=35, stdout_limit=4096, stderr_limit=4096)
        if stamp.returncode or stamp_details(stamp.stdout).get("matches_source") is not True:
            raise CanaryError("source_stamp_invalid")
        derivative_metadata = runner(derivative_inspect, timeout=15,
                                     stdout_limit=4096, stderr_limit=4096)
        try:
            derivative_id, arch = derivative_metadata.stdout.decode("ascii").strip().split("|")
        except (ValueError, UnicodeError):
            raise CanaryError("derivative_identity_invalid") from None
        if (derivative_metadata.returncode or arch != "amd64"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", derivative_id) is None):
            raise CanaryError("derivative_identity_invalid")
        original_cmd = list(original_cmd)
        derivative_cmd = list(derivative_cmd)
        original_cmd[-1] = INSPECTOR
        derivative_cmd[-1] = INSPECTOR
        old = runner(original_cmd, timeout=65, stdout_limit=12_000, stderr_limit=8192)
        new = runner(derivative_cmd, timeout=65, stdout_limit=12_000, stderr_limit=8192)
        if old.returncode or new.returncode:
            raise CanaryError("inspector_execution_failed")
        report = compare(old.stdout, new.stdout, derivative_id=derivative_id)
        return (0 if report["status"] == "PASS" else 1), report
    except (CanaryError, BoundedProcessError, OSError, ValueError, TypeError, KeyError):
        return 2, {
            "schema": SCHEMA, "status": "INFRA_FAILURE",
            "resident_agent_allowed": False,
            "full_mcp_permission_enforcement_verified": False,
            "real_model_evaluation": "NOT_RUN",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"schema": SCHEMA, "status": "NOT_RUN",
                          "resident_agent_allowed": False}))
        return 0
    code, report = execute()
    if args.out:
        try:
            args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
        except OSError:
            return 2
    print("H-19 intercepted native effects:", report["status"],
          "(real MCP/LLM NOT_RUN; resident agent NO_GO)")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
