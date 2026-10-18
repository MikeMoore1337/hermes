"""H-19 opt-in pinned v0.22.2 native/tool + OS sandbox evidence.

Reuses the #33 bounded inspector and its independent pair validator.
No model, terminal tool, real connectors, GitHub write, or production agent.
Run ONLY in an isolated disposable Docker host after explicit opt-in.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from scripts.bounded_subprocess import BoundedProcessError, run_bounded
from scripts.verify_v0221_native_tool_policy import (
    _packet, validate, BLOCKED_CASES, REQUIRED_CASES, NativePolicyDenied,
)
from scripts.verify_v0222_immutable import (
    IMAGE, IMAGE_DIGEST, PATCHED_IMAGE, EXPECTED_SOURCE, commands,
    patched_commands, image_identity, stamp_details,
)

SCHEMA = "h19-native-evidence-v1"
SANDBOX_CHECK = r"""
import json
import os
import socket

outside = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
outside.settimeout(1)
try:
    egress_denied = outside.connect_ex(("198.51.100.1", 443)) != 0
except OSError:
    egress_denied = True
finally:
    outside.close()

write_denied = False
test_path = "/opt/hermes/.h19-readonly-test"
try:
    with open(test_path, "x", encoding="utf-8") as test:
        test.write("test")
except OSError:
    write_denied = True
finally:
    try:
        os.unlink(test_path)
    except OSError:
        pass

print(json.dumps({
    "nonroot": os.geteuid() == 65534,
    "network_egress_probe_denied": egress_denied,
    "runtime_path_write_denied": write_denied,
    "docker_socket_absent": not os.path.exists("/var/run/docker.sock"),
    "shell_binary_present": os.path.exists("/bin/sh"),
    "credentials_injected": any(k in os.environ for k in (
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
        "GH_TOKEN", "CLOUDFLARE_API_TOKEN", "CODEX_HOME")),
}, sort_keys=True))
"""


def capture(runner=run_bounded) -> dict:
    original_inspect, stamp_cmd, original_cmd = commands()
    derivative_inspect, derivative_cmd = patched_commands()
    original_meta = runner(original_inspect, timeout=20, stdout_limit=8192,
                           stderr_limit=8192)
    if original_meta.returncode or not image_identity(original_meta.stdout):
        raise NativePolicyDenied("ORIGINAL_IMAGE_IDENTITY_DENIED")
    stamp = runner(stamp_cmd, timeout=45, stdout_limit=8192, stderr_limit=8192)
    origin = stamp_details(stamp.stdout) if stamp.returncode == 0 else {}
    if origin.get("matches_source") is not True:
        raise NativePolicyDenied("SOURCE_STAMP_NOT_MATCHED")
    patched_meta = runner(derivative_inspect, timeout=20, stdout_limit=8192,
                          stderr_limit=8192)
    try:
        iid, arch = patched_meta.stdout.decode("ascii").strip().split("|")
    except (UnicodeError, ValueError):
        raise NativePolicyDenied("DERIVATIVE_IMAGE_IDENTITY_DENIED") from None
    if (patched_meta.returncode or arch != "amd64"
            or re.fullmatch(r"sha256:[a-f0-9]{64}", iid) is None):
        raise NativePolicyDenied("DERIVATIVE_IMAGE_IDENTITY_DENIED")
    original = runner(original_cmd, timeout=95, stdout_limit=80000,
                      stderr_limit=8192)
    derivative = runner(derivative_cmd, timeout=95, stdout_limit=80000,
                        stderr_limit=8192)
    if original.returncode or derivative.returncode:
        raise NativePolicyDenied("NATIVE_INSPECTOR_FAILED")
    check = validate(original.stdout, derivative.stdout)
    raw_original = _packet(original.stdout)
    raw_patched = _packet(derivative.stdout)
    assert set(raw_patched["cases"]) == REQUIRED_CASES
    # The original may reach synthetic executors, never actual shell/model.
    os_cmd = list(original_cmd)
    os_cmd[-1] = SANDBOX_CHECK
    os_result = runner(os_cmd, timeout=45, stdout_limit=2048, stderr_limit=8192)
    try:
        os_data = json.loads(os_result.stdout) if not os_result.returncode else {}
    except (ValueError, UnicodeError):
        os_data = {}
    os_required = ("nonroot", "network_egress_probe_denied",
                   "runtime_path_write_denied", "docker_socket_absent")
    os_pass = (type(os_data) is dict and all(os_data.get(k) is True for k in os_required)
               and os_data.get("credentials_injected") is False
               and type(os_data.get("shell_binary_present")) is bool)
    runtime_pass = check["status"] == "PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS"
    case_rows = []
    for name in sorted(REQUIRED_CASES):
        first = raw_original["cases"][name]
        second = raw_patched["cases"][name]
        case_rows.append({
            "scenario_id": "h19-native-" + name,
            "source": "pinned_v0222_python_dispatch",
            "original_stub_executor_reached": first["executor_reached"],
            "patched_stub_executor_reached": second["executor_reached"],
            "expected_tool_behavior": "DENY" if name in BLOCKED_CASES else "MIXED_OR_ALLOWED",
            "verification_status": "PASS" if runtime_pass else "FAIL",
            "evidence_ref": "docker:" + iid,
        })
    return {
        "schema": SCHEMA,
        "mode": "isolated_pinned_real_code_synthetic_executors",
        "original_image": IMAGE,
        "original_source_stamp": EXPECTED_SOURCE,
        "patched_image_id": iid,
        "native_case_count": len(case_rows),
        "native_comparison_status": check["status"],
        "original_native_dispatch_gap_observed": check["original_low_level_gap_reproduced"],
        "patched_native_policy_bounded": runtime_pass,
        "checks": case_rows,
        "os_probe_status": "PASS" if os_pass else "FAIL",
        "os_probe": {k: os_data.get(k) if type(os_data) is dict else None
                     for k in (*os_required, "credentials_injected", "shell_binary_present")},
        "shell_execution_denied_by_os": False if os_data.get("shell_binary_present") else None,
        "shell_execution_denial_verified": False,
        "mcp_external_effect_denial_verified": False,
        "full_runtime_permission_enforcement_verified": False,
        "real_model_evaluation": "NOT_RUN",
        "inference_calls": 0,
        "real_tool_executed": False,
        "production_verified": False,
        "h01_service_touched": False,
        "resident_agent_allowed": False,
        "status": "PASS" if os_pass and runtime_pass else "FAIL",
    }


def run(*, runner=run_bounded) -> tuple[int, dict]:
    try:
        report = capture(runner)
        return (0 if report["status"] == "PASS" else 1), report
    except (NativePolicyDenied, BoundedProcessError, OSError, ValueError,
            TypeError, KeyError):
        return 2, {"schema": SCHEMA, "status": "INFRA_FAILURE",
                   "reason": "MISSING_OR_INVALID_SANDBOX_EVIDENCE",
                   "real_model_evaluation": "NOT_RUN", "resident_agent_allowed": False,
                   "full_runtime_permission_enforcement_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"schema": SCHEMA, "status": "NOT_RUN",
                          "resident_agent_allowed": False}))
        return 0
    code, report = run()
    if args.out:
        try:
            args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                                encoding="utf-8")
        except OSError:
            return 2
    print("H-19 pinned native: " + report["status"] +
          " (real model NOT_RUN; resident agent NO_GO)")
    return code


if __name__ == "__main__":
    sys.exit(main())
