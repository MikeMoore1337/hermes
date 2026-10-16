"""Bounded read-only v0.22.2 Docker identity + synthetic native dispatch probe.

Default is NO_EXECUTION. The explicit --execute mode runs only the pinned
offline AMD64 image, no host mounts, no credentials, no provider or real tools.
The previous v0.22.1 probe is used as a synthetic *measurement*, never as
proof that a v0.22.2 fix is applicable or deployed.
"""
from __future__ import annotations

import argparse
import json
import re

from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0221_native_tool_policy import INSPECTOR, _packet, validate as validate_patch_pair

IMAGE_DIGEST = "sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05"
IMAGE = "nousresearch/hermes-agent@" + IMAGE_DIGEST
EXPECTED_SOURCE = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
PATCHED_IMAGE = "hermes-v0222-native-policy-candidate:20261016"

STAMP_INSPECTOR = r"""
import json
import sys
from pathlib import Path
p = Path("/opt/hermes/install-stamp.json")
doc = json.loads(p.read_text(encoding="utf-8"))
if not isinstance(doc, dict):
    raise RuntimeError("invalid_stamp")
fields = {str(k): str(v) for k, v in doc.items()
          if k in ("commit", "source_commit", "git_commit", "git_sha", "version",
                   "source_sha", "revision", "tag") and isinstance(v, (str, int))}
print(json.dumps({"fields": fields, "keys": sorted(doc),
                  "python": sys.version.split()[0]}, sort_keys=True))
"""


def commands() -> tuple[list[str], list[str], list[str]]:
    inspect = ["docker", "image", "inspect", IMAGE, "--format",
               "{{json .RepoDigests}}|{{.Architecture}}"]
    sandbox = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.5", "--memory", "768m", "--memory-swap", "768m",
        "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--env", "HOME=/tmp", "--env", "HERMES_HOME=/tmp/hermes",
        "--env", "HERMES_SCOPE_PROBE_MODE=original",
        "--entrypoint", "/opt/hermes/.venv/bin/python", IMAGE,
        "-B", "-c",
    ]
    return inspect, [*sandbox, STAMP_INSPECTOR], [*sandbox, INSPECTOR]


def image_identity(raw: bytes) -> bool:
    try:
        parts = raw.decode("utf-8").strip().split("|")
        if len(parts) != 2:
            return False
        digests = json.loads(parts[0])
        return (parts[1] == "amd64" and isinstance(digests, list)
                and any(type(item) is str and item.endswith("@" + IMAGE_DIGEST)
                        for item in digests))
    except (ValueError, UnicodeError):
        return False


def stamp_details(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        return {"status": "STAMP_UNREADABLE", "matches_source": False}
    if type(payload) is not dict or set(payload) != {"fields", "keys", "python"}:
        return {"status": "STAMP_SCHEMA_INVALID", "matches_source": False}
    fields = payload["fields"]
    keys = payload["keys"]
    if (type(fields) is not dict or type(payload["python"]) is not str
            or type(keys) is not list or len(keys) > 128
            or any(type(key) is not str for key in keys)):
        return {"status": "STAMP_SCHEMA_INVALID", "matches_source": False}
    # A shared prefix, version/tag value, or malformed suffix cannot establish
    # even a stamp-level match to the exact pinned upstream source commit.
    commit_fields = ("commit", "source_commit", "git_commit", "git_sha",
                     "source_sha", "revision")
    match = any(fields.get(key) == EXPECTED_SOURCE for key in commit_fields)
    return {
        "status": "STAMP_MATCHED_IMAGE_UNATTESTED" if match else "STAMP_SOURCE_NOT_MATCHED",
        "matches_source": match,
        "stamp_field_names": sorted(fields),
        "python_version": payload["python"],
    }


def tool_details(raw: bytes) -> dict[str, object]:
    try:
        packet = _packet(raw)
        cases = packet["cases"]
        return {
            "status": "SYNTHETIC_ONLY",
            "direct_terminal_executor_reached": cases["direct_terminal"]["executor_reached"],
            "stale_agent_terminal_executor_reached": cases["agent_stale_native"]["executor_reached"],
            "full_agent_loop_terminal_executor_reached": cases["agent_full_loop"]["executor_reached"],
            "nested_terminal_allowed": cases["execute_code_nested_scope"].get(
                "nested_terminal_allowed"),
            "parallel_restricted_executor_reached": cases["parallel_policy"].get(
                "restricted_executor_reached"),
            "model_executed": False,
            "real_tool_executed": False,
        }
    except (ValueError, KeyError, TypeError):
        return {"status": "SYNTHETIC_PROBE_INCOMPATIBLE", "model_executed": False,
                "real_tool_executed": False}


def evaluate(identity: bool, stamp: dict[str, object], tools: dict[str, object]) -> dict[str, object]:
    gap = any(tools.get(key) is True for key in (
        "direct_terminal_executor_reached", "stale_agent_terminal_executor_reached",
        "full_agent_loop_terminal_executor_reached",
        "nested_terminal_allowed", "parallel_restricted_executor_reached"))
    return {
        "status": "OFFLINE_V0222_GAP_OBSERVED" if identity and gap
                  else "OFFLINE_V0222_PARTIAL_EVIDENCE",
        "exact_image_verified": identity,
        "stamp": stamp,
        "native_scope": tools,
        "upstream_image_unmodified": identity,
        "source_to_image_attested": False,
        "complete_sbom_and_cve_closed": False,
        "cloudflare_cost_verified": False,
        "production_verified": False,
        "resident_agent_allowed": False,
    }


def observe() -> dict[str, object]:
    inspect, stamp_cmd, native_cmd = commands()
    try:
        metadata = run_bounded(inspect, timeout=15, stdout_limit=8192, stderr_limit=8192)
        if metadata.returncode or not image_identity(metadata.stdout):
            return {"status": "IMAGE_IDENTITY_DENIED", "resident_agent_allowed": False}
        stamp = run_bounded(stamp_cmd, timeout=30, stdout_limit=4096, stderr_limit=16384)
        native = run_bounded(native_cmd, timeout=90, stdout_limit=80000, stderr_limit=16384)
        return evaluate(True,
                        stamp_details(stamp.stdout) if stamp.returncode == 0
                        else {"status": "STAMP_NOT_OBSERVED", "matches_source": False},
                        tool_details(native.stdout) if native.returncode == 0
                        else {"status": "SYNTHETIC_PROBE_FAILED", "model_executed": False,
                              "real_tool_executed": False})
    except (OSError, BoundedProcessError, ValueError):
        return {"status": "OFFLINE_DOCKER_UNAVAILABLE",
                "resident_agent_allowed": False}


def patched_commands() -> tuple[list[str], list[str]]:
    """Never trust the local derivative as an upstream-signed release."""
    _, _, original = commands()
    inspect = ["docker", "image", "inspect", PATCHED_IMAGE, "--format",
               "{{.Id}}|{{.Architecture}}"]
    probe = [PATCHED_IMAGE if token == IMAGE else token for token in original]
    probe = [token.replace("HERMES_SCOPE_PROBE_MODE=original",
                           "HERMES_SCOPE_PROBE_MODE=patched")
             if type(token) is str else token for token in probe]
    return inspect, probe


def compare_patched() -> dict[str, object]:
    original_inspect, _, original_run = commands()
    patched_inspect, patched_run = patched_commands()
    try:
        first = run_bounded(original_inspect, timeout=15,
                            stdout_limit=8192, stderr_limit=8192)
        if first.returncode or not image_identity(first.stdout):
            return {"status": "ORIGINAL_IMAGE_MISMATCH", "resident_agent_allowed": False}
        image = run_bounded(patched_inspect, timeout=15,
                            stdout_limit=8192, stderr_limit=8192)
        if image.returncode:
            return {"status": "DERIVATIVE_UNAVAILABLE", "resident_agent_allowed": False}
        try:
            image_id, arch = image.stdout.decode("ascii").strip().split("|")
        except (ValueError, UnicodeError):
            return {"status": "DERIVATIVE_ID_INVALID", "resident_agent_allowed": False}
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None or arch != "amd64":
            return {"status": "DERIVATIVE_ID_INVALID", "resident_agent_allowed": False}
        original = run_bounded(original_run, timeout=90,
                               stdout_limit=80000, stderr_limit=16384)
        patched = run_bounded(patched_run, timeout=90,
                              stdout_limit=80000, stderr_limit=16384)
        if original.returncode or patched.returncode:
            return {"status": "SYNTHETIC_PROBE_FAILED", "resident_agent_allowed": False}
        pair = validate_patch_pair(original.stdout, patched.stdout)
        return {
            "status": pair["status"],
            "pinned_original": IMAGE,
            "local_derivative": PATCHED_IMAGE,
            "local_derivative_id": image_id,
            "original_gap_reproduced": pair["original_low_level_gap_reproduced"],
            "patched_checked_paths_blocked": pair["patched_checked_paths_blocked"],
            "allowed_synthetic_paths_work": pair["allowed_synthetic_paths_work"],
            "model_executed": False,
            "real_tool_executed": False,
            "source_to_image_attested": False,
            "production_verified": False,
            "resident_agent_allowed": False,
        }
    except (OSError, BoundedProcessError, ValueError):
        return {"status": "OFFLINE_COMPARE_UNAVAILABLE", "resident_agent_allowed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--compare-patched", action="store_true")
    args = parser.parse_args(argv)
    result = (compare_patched() if args.compare_patched else observe()) if args.execute else {
        "status": "NOT_EXECUTED", "resident_agent_allowed": False}
    print(json.dumps(result, sort_keys=True))
    return 2 if args.execute else 0


if __name__ == "__main__":
    raise SystemExit(main())
