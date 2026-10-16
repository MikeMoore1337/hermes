"""Opt-in static Docker-copy parity check for FIVE pinned v0.22.2 public files.

DO NOT launch container or agent. Does not establish vendor build provenance,
security of packages, or runtime permission enforcement. Always returns NO-GO.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

IMAGE = ("nousresearch/hermes-agent@sha256:"
         "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
EXPECTED = {
    "plugins/cron_providers/chronos/verify.py": "2503f4a1a8cd21ad28bc1717c2f92494186103d6",
    "plugins/dashboard_auth/_shared.py": "e12fb5896c51096589b25172468d413ce22eef5d",
    "plugins/dashboard_auth/nous/__init__.py": "66723b5a75e481d6f5936a354245c1beef639915",
    "plugins/dashboard_auth/self_hosted/__init__.py": "f65a24ec34882687bc6558410f882c2d4479fb3e",
    "pyproject.toml": "5145f275d14a0ab119802821c715a33123b15551",
}
MAX_SOURCE_BYTES = 1_000_000
CONTAINER_RE = re.compile(r"[a-f0-9]{64}\Z")
Runner = Callable[[list[str]], bytes]


class ParityDenied(ValueError):
    """Fixed failure code without dumping Docker output or source text."""


def _blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _real_runner(argv: list[str]) -> bytes:
    # All Docker commands constructed internally as literal argv (no shell).
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, timeout=40, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ParityDenied("docker_local_unavailable") from None
    if proc.returncode != 0:
        raise ParityDenied("docker_command_failed")
    return proc.stdout


def _image_identity(runner: Runner) -> None:
    out = runner([
        "docker", "image", "inspect", IMAGE, "--format",
        "{{.Id}}|{{.Os}}|{{.Architecture}}",
    ])
    expected = IMAGE.partition("@")[2].encode() + b"|linux|amd64"
    if out.strip() != expected:
        raise ParityDenied("unexpected_image_identity")


def audit(runner: Runner = _real_runner) -> dict:
    """Docker-create, never start; Docker-copy exact allowlisted paths, then rm."""
    _image_identity(runner)
    container_id: str | None = None
    cleanup_ok = False
    findings: list[dict[str, str | bool]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="hermes-h18-static-") as temp:
            raw_id = runner([
                "docker", "create", "--pull", "never", "--platform", "linux/amd64",
                "--network", "none", "--read-only", "--user", "65534:65534",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "32", "--memory", "256m", "--memory-swap", "256m",
                "--entrypoint", "/bin/true", IMAGE,
            ])
            candidate = raw_id.decode("ascii", "strict").strip()
            if not CONTAINER_RE.fullmatch(candidate):
                raise ParityDenied("invalid_container_id")
            container_id = candidate

            for index, (name, expected_blob) in enumerate(sorted(EXPECTED.items())):
                target = Path(temp) / f"file-{index}.py"
                runner(["docker", "cp", f"{container_id}:/opt/hermes/{name}",
                        str(target)])
                if target.is_symlink() or not target.is_file():
                    raise ParityDenied("missing_extracted_source")
                data = target.read_bytes()
                if len(data) > MAX_SOURCE_BYTES:
                    raise ParityDenied("oversized_extracted_source")
                actual_blob = _blob_hash(data)
                findings.append({
                    "path": name, "git_blob_sha1": actual_blob,
                    "matches_exact_upstream_git_blob": actual_blob == expected_blob,
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
    except (OSError, ValueError, UnicodeError) as exc:
        if isinstance(exc, ParityDenied):
            raise
        raise ParityDenied("static_copy_or_hash_failed") from None
    finally:
        if container_id is not None:
            try:
                runner(["docker", "rm", container_id])
                cleanup_ok = True
            except (ParityDenied, OSError, ValueError):
                # Cleanup failure must not produce an unconditional PASS.
                cleanup_ok = False
    if not cleanup_ok:
        raise ParityDenied("temporary_container_cleanup_unverified")
    matched = sum(item["matches_exact_upstream_git_blob"] for item in findings)
    return {
        "status": "AUTH_SUBSET_PARITY_OBSERVED" if matched == len(EXPECTED)
                  else "AUTH_SUBSET_MISMATCH",
        "image": IMAGE,
        "platform": "linux/amd64",
        "source_files_checked": len(findings),
        "source_files_matching_upstream": matched,
        "source_files": findings,
        "docker_container_started": False,
        "temporary_container_removed": True,
        "complete_image_parity_verified": False,
        "signed_source_to_image_provenance_verified": False,
        "all_cve_remediated": False,
        "native_tool_enforcement_verified": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pinned image 5-file static JWT parity")
    parser.add_argument("--execute", action="store_true", help="Opt in to local Docker create/cp/rm")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        report = audit()
    except ParityDenied:
        report = {"status": "INCONCLUSIVE", "resident_agent_allowed": False}
    print(json.dumps(report, sort_keys=True))
    # Always P0 NO-GO, including matched subsets.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
