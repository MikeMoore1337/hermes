"""Observed, partial CycloneDX 1.5 BOM for pinned v0.22.1.

No network, pulling, model calls, mounts, credentials or production operations.
This is neither a complete SBOM nor signed supplier provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from . import verify_v0221_local_image as image
from .bounded_subprocess import BoundedProcessError, run_bounded

EXPECTED_OS = 274
EXPECTED_PYTHON = 146


class SbomDenied(ValueError):
    """Fail closed without disclosing raw inspector output."""


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SbomDenied("duplicate_json_key")
        result[key] = value
    return result


def build(metadata: bytes, inspector: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        check = image.parse(metadata, inspector)
        if (not check["embedded_stamp_matches_release_commit"]
                or check["os_package_entries"] != EXPECTED_OS
                or check["python_package_entries"] != EXPECTED_PYTHON):
            raise SbomDenied("unexpected_image_scope")
        payload = json.loads(inspector, object_pairs_hook=unique_pairs)
    except (image.ImageEvidenceDenied, ValueError, UnicodeError, TypeError):
        raise SbomDenied("invalid_pinned_image_evidence") from None

    packages: dict[tuple[str, str], str] = {}
    duplicates = 0
    for ecosystem, field in (("dpkg", "os_packages"), ("python-venv", "python_packages")):
        for row in payload[field]:
            name, version = row["name"], row["version"]
            canonical = (re.sub(r"[-_.]+", "-", name).lower()
                         if ecosystem == "python-venv" else name.lower())
            key = ecosystem, canonical
            if key in packages:
                if packages[key] != version:
                    raise SbomDenied("conflicting_versions")
                duplicates += 1
            else:
                packages[key] = version

    components = []
    for (ecosystem, name), version in sorted(packages.items()):
        raw = (ecosystem + "\0" + name + "\0" + version).encode("utf-8")
        components.append({
            "type": "library",
            "bom-ref": "urn:hermes:observed:" + hashlib.sha256(raw).hexdigest(),
            "name": name,
            "version": version,
            "properties": [
                {"name": "hermes:observed-ecosystem", "value": ecosystem},
                {"name": "hermes:verified-supplier-provenance", "value": "false"},
            ],
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {
            "type": "container",
            "name": "nousresearch/hermes-agent",
            "version": "v0.22.1",
            "properties": [
                {"name": "hermes:immutable-image", "value": image.IMAGE},
                {"name": "hermes:embedded-source-commit", "value": image.SOURCE_SHA},
                {"name": "hermes:scope", "value": "dpkg-and-primary-python-venv-only"},
                {"name": "hermes:complete-sbom-verified", "value": "false"},
            ],
        }},
        "components": components,
    }
    serialized = json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    summary = {
        "status": "OBSERVED_PARTIAL_CYCLONEDX_NO_GO",
        "image": image.IMAGE,
        "raw_dpkg_entries": EXPECTED_OS,
        "raw_python_entries": EXPECTED_PYTHON,
        "duplicate_metadata_rows": duplicates,
        "unique_components": len(components),
        "bom_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "vendor_runtimes_covered": False,
        "dependency_relationships_covered": False,
        "licenses_verified": False,
        "vulnerabilities_scanned": False,
        "supplier_attestation_verified": False,
        "complete_sbom_verified": False,
        "model_executed": False,
        "resident_agent_allowed": False,
    }
    return bom, summary


def collect(runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> tuple[dict[str, Any], dict[str, Any]]:
    inspect, run = image.commands()
    try:
        first = runner(inspect, check=False, capture_output=True, timeout=10,
                       stdout_limit=8192, stderr_limit=16384)
        if first.returncode:
            raise SbomDenied("pinned_image_unavailable")
        second = runner(run, check=False, capture_output=True, timeout=30,
                        stdout_limit=image.MAX_BYTES, stderr_limit=16384)
        if second.returncode:
            raise SbomDenied("isolated_inspector_failed")
        return build(first.stdout, second.stdout)
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError):
        raise SbomDenied("local_docker_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observed partial BOM, never production GO")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if args.output is None:
        print(json.dumps({"status": "NOT_RUN", "reason": "output_required",
                          "resident_agent_allowed": False}))
        return 2
    try:
        bom, summary = collect()
        with args.output.open("x", encoding="utf-8", newline="\n") as file:
            json.dump(bom, file, ensure_ascii=False, indent=2, sort_keys=True)
            file.write("\n")
    except (SbomDenied, OSError):
        print(json.dumps({"status": "NO_DATA", "reason": "partial_sbom_unavailable",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
