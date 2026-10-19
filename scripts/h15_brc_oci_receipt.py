#!/usr/bin/env python3
"""Fail-closed, secret-free H-15 OCI build provenance receipt (CI only).

This is NOT a runtime installation, publishing or authorization utility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"
BASE_DIGEST = "sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5"
IMAGE_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
BASE_REF = "node:24-bookworm-slim@" + BASE_DIGEST
UNSAFE_IMAGE_ENV = ("BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET", "BRC_TOKEN",
                    "BRC_DEVICE_ID", "GITHUB_TOKEN", "GH_TOKEN")


class ReceiptDenied(ValueError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_receipt(
    *, dockerfile: Path, inspect_json: Path, sbom_file: Path,
    source_audit: Path, git_sha: str,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise ReceiptDenied("bad_hermes_commit")
    docker_source = dockerfile.read_text(encoding="utf-8")
    if docker_source.count("FROM " + BASE_REF + " AS ") != 2:
        raise ReceiptDenied("unapproved_or_unpinned_oci_base")
    image = json.loads(inspect_json.read_text(encoding="utf-8"))
    if not isinstance(image, list) or len(image) != 1:
        raise ReceiptDenied("unexpected_docker_inspect")
    image = image[0]
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not IMAGE_PATTERN.fullmatch(image_id):
        raise ReceiptDenied("image_id_missing")
    config = image.get("Config") or {}
    if config.get("User") != "65534:65534":
        raise ReceiptDenied("oci_runtime_principal_not_nonroot")
    labels = config.get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != UPSTREAM_SHA:
        raise ReceiptDenied("unreviewed_upstream_revision")
    if labels.get("org.opencontainers.image.licenses") != "MIT":
        raise ReceiptDenied("license_not_preserved")
    env = config.get("Env") or []
    if not isinstance(env, list) or any(
        e.split("=", 1)[0].upper() in UNSAFE_IMAGE_ENV for e in env
        if isinstance(e, str)
    ):
        raise ReceiptDenied("secret_bearing_image_environment")
    if any(not isinstance(e, str) or "=" not in e for e in env):
        raise ReceiptDenied("invalid_image_environment")
    if config.get("Cmd") != ["node", "packages/relay/dist/cli.js"]:
        raise ReceiptDenied("unexpected_runtime_command")

    sbom = json.loads(sbom_file.read_text(encoding="utf-8"))
    components = sbom.get("components")
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or not str(sbom.get("specVersion", "")).startswith("1.")
        or not isinstance(components, list)
        or len(components) < 10
    ):
        raise ReceiptDenied("invalid_or_empty_dependency_sbom")
    audit = json.loads(source_audit.read_text(encoding="utf-8"))
    if (
        audit.get("status") != "SOURCE_PIN_VERIFIED"
        or audit.get("sha") != UPSTREAM_SHA
        or audit.get("production_ready") is not False
        or audit.get("live_execution") != "DENIED"
    ):
        raise ReceiptDenied("upstream_provenance_unverified")

    return {
        "schema": 1,
        "status": "CI_IMAGE_VERIFIED_NOT_DEPLOYABLE",
        "hermes_commit": git_sha,
        "upstream_sha": UPSTREAM_SHA,
        "node_base_ref": BASE_REF,
        "image_id": image_id,
        "image_user": config["User"],
        "application_license": "MIT",
        "sbom_format": "CycloneDX",
        "sbom_component_count": len(components),
        "cyclonedx_sha256": sha256(sbom_file),
        "source_audit_sha256": sha256(source_audit),
        "dockerfile_sha256": sha256(dockerfile),
        "production_deployment": "NOT_AUTHORIZED",
        "external_mcp_listener": "NOT_EXPOSED",
        "owner_device_execution": "NOT_ENABLED",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dockerfile", type=Path, required=True)
    p.add_argument("--image-inspect", type=Path, required=True)
    p.add_argument("--sbom", type=Path, required=True)
    p.add_argument("--source-audit", type=Path, required=True)
    p.add_argument("--git-sha", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    try:
        receipt = build_receipt(
            dockerfile=args.dockerfile, inspect_json=args.image_inspect,
            sbom_file=args.sbom, source_audit=args.source_audit,
            git_sha=args.git_sha,
        )
    except (ReceiptDenied, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": type(exc).__name__}))
        return 2
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("HERMES_BRC_OCI_PROVENANCE=" + receipt["status"])
    print("HERMES_BRC_SBOM_COMPONENTS=" + str(receipt["sbom_component_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
