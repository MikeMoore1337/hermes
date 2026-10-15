"""Offline six-file Git-blob parity for a pinned Hermes v0.22.1 AMD64 image.

Not a supplier attestation, full source parity, SBOM, model run or runtime GO.
The source tree blob IDs are from exact upstream commit 297552a9d646119871391d202509822cd86330df.
No network, volumes, credentials, arbitrary paths or model execution.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Any, Callable
from .bounded_subprocess import BoundedProcessError, run_bounded

from .verify_v0221_local_image import IMAGE, SOURCE_SHA

EXPECTED = {
    "agent/auxiliary_fallback_recovery.py": "d479845e534be583477fda405325c47a92834153",
    "agent/billing_usage.py": "e3fc1ba7af077bd842ea81761d24ffbfc04b36d7",
    "agent/tool_executor.py": "4bd1bab397e5bc1432ec4f5bdda6f18a9a15e850",
    "agent/tool_guardrails.py": "258ca3ab9293e81595fee82945bcfe22e65ae7aa",
    "hermes_cli/main.py": "47aa9814a12e07e4a60b8958b0447ec4e7a72dd3",
    "providers/base.py": "9183cf3074ef0425d5af5cecc29a8a938b4cada1",
}
SHA1 = re.compile(r"[a-f0-9]{40}\Z")
INSPECTOR = r"""
import hashlib
import json
from pathlib import Path
paths = [
    "agent/auxiliary_fallback_recovery.py",
    "agent/billing_usage.py",
    "agent/tool_executor.py",
    "agent/tool_guardrails.py",
    "hermes_cli/main.py",
    "providers/base.py",
]
root = Path("/opt/hermes")
result = {}
for name in paths:
    file = root / name
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 1024 * 1024:
        raise SystemExit(4)
    raw = file.read_bytes()
    result[name] = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
print(json.dumps({"schema": "hermes-v0221-git-blobs-v1", "blobs": result}, sort_keys=True))
"""


class SampleDenied(ValueError):
    """Safe error code; raw Docker output is not exposed."""


def commands() -> tuple[list[str], list[str]]:
    first = ["docker", "image", "inspect", IMAGE, "--format",
             "{{json .RepoDigests}}|{{.Architecture}}"]
    second = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.25", "--memory", "256m", "--memory-swap", "256m",
        "--pids-limit", "25", "--tmpfs", "/tmp:rw,nosuid,nodev,size=8m",
        "--entrypoint", "/opt/hermes/.venv/bin/python",
        IMAGE, "-B", "-c", INSPECTOR,
    ]
    return first, second


def _strict_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in items:
        if key in result:
            raise SampleDenied("duplicate_json_key")
        result[key] = value
    return result


def parse(metadata: bytes, raw: bytes) -> dict[str, Any]:
    if (type(metadata) is not bytes or len(metadata) > 8192
            or type(raw) is not bytes or not 1 <= len(raw) <= 4096):
        raise SampleDenied("invalid_response_size")
    try:
        digest_json, arch = metadata.decode("utf-8").strip().split("|")
        digests = json.loads(digest_json, object_pairs_hook=_strict_pairs)
        payload = json.loads(raw, object_pairs_hook=_strict_pairs)
    except (ValueError, UnicodeError):
        raise SampleDenied("untrusted_output") from None
    if type(digests) is not list or IMAGE not in digests or arch != "amd64":
        raise SampleDenied("unexpected_image")
    if (type(payload) is not dict or set(payload) != {"schema", "blobs"}
            or payload["schema"] != "hermes-v0221-git-blobs-v1"
            or type(payload["blobs"]) is not dict
            or set(payload["blobs"]) != set(EXPECTED)):
        raise SampleDenied("invalid_blob_schema")
    received = payload["blobs"]
    if any(type(v) is not str or SHA1.fullmatch(v) is None for v in received.values()):
        raise SampleDenied("invalid_blob_digest")
    mismatched = sorted(k for k, expected in EXPECTED.items()
                        if received[k] != expected)
    return {
        "status": ("SAMPLED_GIT_BLOBS_MATCH_UNATTESTED"
                   if not mismatched else "SAMPLED_GIT_BLOBS_MISMATCH"),
        "source_commit": SOURCE_SHA,
        "image": IMAGE,
        "checked_files": len(EXPECTED),
        "mismatched_paths": mismatched,
        "sample_byte_parity_verified": not mismatched,
        "full_source_parity_verified": False,
        "supplier_attestation_verified": False,
        "complete_sbom_verified": False,
        "network_access": False,
        "model_executed": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = run_bounded) -> dict[str, Any]:
    first, second = commands()
    try:
        image = runner(first, check=False, capture_output=True, timeout=10,
                       stdout_limit=8192, stderr_limit=16384)
        if image.returncode:
            raise SampleDenied("image_not_local")
        inspector = runner(second, check=False, capture_output=True, timeout=30,
                           stdout_limit=4096, stderr_limit=16384)
        if inspector.returncode:
            raise SampleDenied("inspector_failed")
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError):
        raise SampleDenied("docker_unavailable") from None
    return parse(image.stdout, inspector.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pinned v0.22.1 six-file offline parity")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = observe()
    except SampleDenied:
        print(json.dumps({"status": "UNKNOWN", "reason": "sample_evidence_unavailable",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    # The best result remains an un-attested source sample, never runtime GO.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
