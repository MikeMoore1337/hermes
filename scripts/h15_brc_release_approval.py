#!/usr/bin/env python3
"""H-15: require a separate, root-controlled release decision for one OCI ID.

This is a local authorization gate, NOT cryptographic build attestation or
automatic CVE clearance. The owner verifies the referenced CI evidence before
creating this file. Nothing in CI or source delivery writes the approval.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat

UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
FIELDS = {
    "schema", "decision", "scope", "image_id", "upstream_sha",
    "hermes_commit", "oci_archive_sha256", "trivy_report_sha256",
    "cve_triage_sha256", "reviewed_residual_cve_ids",
}
DECISION = "OWNER_ACCEPTED_RESIDUAL_CVE_RISK"
SCOPE = "INTERNAL_OAUTH_ONLY_NO_AGENTS_NO_PUBLIC_MCP"


class ApprovalDenied(ValueError):
    pass


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalDenied("duplicate_json_key")
        result[key] = value
    return result


def validate_decision(doc: dict, image_id: str) -> None:
    if not isinstance(doc, dict) or set(doc) != FIELDS:
        raise ApprovalDenied("unexpected_decision_schema")
    if not IMAGE_RE.fullmatch(image_id):
        raise ApprovalDenied("invalid_requested_image")
    if (type(doc["schema"]) is not int or doc["schema"] != 1
            or doc["decision"] != DECISION
            or doc["scope"] != SCOPE
            or doc["image_id"] != image_id
            or doc["upstream_sha"] != UPSTREAM_SHA):
        raise ApprovalDenied("unapproved_image_or_scope")
    if not isinstance(doc["hermes_commit"], str) or not COMMIT_RE.fullmatch(doc["hermes_commit"]):
        raise ApprovalDenied("missing_verified_hermes_revision")
    for key in ("oci_archive_sha256", "trivy_report_sha256", "cve_triage_sha256"):
        if not isinstance(doc[key], str) or not HEX_RE.fullmatch(doc[key]):
            raise ApprovalDenied("missing_evidence_pin")
    cves = doc["reviewed_residual_cve_ids"]
    if (not isinstance(cves, list) or len(cves) > 200
            or any(not isinstance(cve, str) or not CVE_RE.fullmatch(cve) for cve in cves)
            or cves != sorted(set(cves))):
        raise ApprovalDenied("invalid_residual_cve_review")


def validate_private_file(path: Path, *, owner_uid: int = 0, owner_gid: int = 0) -> None:
    # lstat rejects symlinks instead of following them. The fixed production
    # parent is root:root 0700; the receipt is root:root 0600.
    parent = path.parent.lstat()
    file = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner_uid
            or parent.st_gid != owner_gid or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ApprovalDenied("unsafe_approval_directory")
    if (not stat.S_ISREG(file.st_mode) or file.st_uid != owner_uid
            or file.st_gid != owner_gid or stat.S_IMODE(file.st_mode) != 0o600
            or not 1 <= file.st_size <= 8192):
        raise ApprovalDenied("unsafe_approval_file")


def check_release_approval(path: Path, image_id: str) -> None:
    validate_private_file(path)
    # Refuse duplicate keys so an owner-reviewed ID cannot differ from the
    # one a permissive JSON parser would read later.
    doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
    validate_decision(doc, image_id)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--file", type=Path, required=True)
    p.add_argument("--image-id", required=True)
    args = p.parse_args()
    try:
        check_release_approval(args.file, args.image_id)
    except (ApprovalDenied, OSError, UnicodeError, ValueError, TypeError, RecursionError):
        print("H15_OWNER_IMAGE_APPROVAL=REFUSED")
        return 2
    print("H15_OWNER_IMAGE_APPROVAL=PASS")
    print("H15_OWNER_APPROVAL_SCOPE=" + SCOPE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
