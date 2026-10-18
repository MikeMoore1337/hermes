"""Private-only Skill Evals evidence index: verified hashes, never raw agent logs.

Hermes #349 / ADT #11. No upload, networking, provider calls or file writes.
A human must still review raw evidence independently before publication.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .protocol import AdmissionDenied, CASES, validate_job

SHA256 = re.compile(r"^[a-f0-9]{64}$")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
FILES = ("prompt.txt", "source.diff", "agent.stdout.txt",
         "agent.stderr.txt", "oracle.stdout.txt", "oracle.stderr.txt")
MAX_MANIFEST = 2_000_000
MAX_FILE = 2_000_000


def _private_root(root: Path) -> None:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise AdmissionDenied("private_evidence_root_required")
    if root.stat().st_mode & 0o077:
        raise AdmissionDenied("evidence_root_must_be_0700")
    if hasattr(os, "getuid") and root.stat().st_uid != os.getuid():
        raise AdmissionDenied("evidence_owner_mismatch")
    for ancestor in [root, *root.parents]:
        if ancestor.is_symlink():
            raise AdmissionDenied("linked_evidence_ancestor")


def _sha256_file(path: Path, *, root: Path, maximum: int) -> tuple[str, bytes]:
    if (path.is_symlink() or not path.is_file() or
            not path.resolve().is_relative_to(root.resolve())):
        raise AdmissionDenied("unsafe_evidence_file")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum or
            info.st_nlink != 1):
        raise AdmissionDenied("unbounded_or_hardlinked_evidence")
    if info.st_mode & 0o077:
        raise AdmissionDenied("public_or_group_readable_evidence")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise AdmissionDenied("evidence_changed_or_too_large")
    return hashlib.sha256(content).hexdigest(), content


def _verdict(value: object, name: str) -> bool:
    if type(value) is not dict or type(value.get("timed_out")) is not bool:
        raise AdmissionDenied("invalid_" + name + "_result")
    exit_code = value.get("returncode")
    if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
        raise AdmissionDenied("invalid_" + name + "_exit_code")
    return exit_code == 0 and not value["timed_out"]


def make_private_hash_manifest(root: Path, job: dict, *, expected_sha256: str,
                               clock: float | None = None) -> dict:
    """Generate metadata from private, SHA-bound ADT report, without exporting it.

    Caller must supply trusted job and SHA from the sealed one-shot receipt.
    This is not an approval verifier and cannot enable inference.
    """
    if type(expected_sha256) is not str or not SHA256.fullmatch(expected_sha256):
        raise AdmissionDenied("expected_receipt_digest_required")
    checked = validate_job(job, clock=clock)
    _private_root(root)
    digest, raw = _sha256_file(root / "observations.json", root=root,
                               maximum=MAX_MANIFEST)
    if digest != expected_sha256:
        raise AdmissionDenied("observations_digest_mismatch")
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise AdmissionDenied("malformed_observations") from exc
    if (type(report) is not dict or report.get("schema_version") != 1 or
            report.get("dataset") != "adt-controlled-pilot-v1" or
            report.get("provider") != checked["provider"] or
            report.get("model") != checked["model"] or
            report.get("executed") is not True):
        raise AdmissionDenied("observations_context_mismatch")
    records = report.get("records")
    if type(records) is not list or len(records) != 2 * checked["trials"] * len(checked["case_ids"]):
        raise AdmissionDenied("incomplete_paired_observations")
    all_expected = {(case, trial, variant)
                    for case in checked["case_ids"]
                    for trial in range(1, checked["trials"] + 1)
                    for variant in ("baseline", "candidate")}
    seen = set()
    safe_records = []
    for run in records:
        if type(run) is not dict:
            raise AdmissionDenied("invalid_observation_record")
        case, trial, variant = (run.get("case_id"), run.get("trial"), run.get("variant"))
        key = (case, trial, variant)
        if (type(case) is not str or case not in CASES or
                type(trial) is not int or type(variant) is not str or
                key not in all_expected or key in seen):
            raise AdmissionDenied("unexpected_or_duplicate_evidence_run")
        seen.add(key)
        fixture = run.get("fixture_commit_sha")
        if type(fixture) is not str or not SHA40.fullmatch(fixture):
            raise AdmissionDenied("fixture_sha_missing")
        cli_ok = _verdict(run.get("cli"), "cli")
        oracle_ok = _verdict(run.get("oracle"), "oracle")
        run_id = f"{case}-t{trial}-{variant}"
        folder = root / run_id
        if folder.is_symlink() or not folder.is_dir() or not folder.resolve().is_relative_to(root.resolve()):
            raise AdmissionDenied("unsafe_evidence_directory")
        expected_paths = [f"{run_id}/{name}" for name in FILES]
        observed_paths = run.get("evidence")
        claimed_hashes = run.get("evidence_sha256")
        if (type(observed_paths) is not list or observed_paths != expected_paths or
                type(claimed_hashes) is not dict or set(claimed_hashes) != set(expected_paths)):
            raise AdmissionDenied("evidence_inventory_mismatch")
        hashes = {}
        for name in FILES:
            rel = f"{run_id}/{name}"
            claimed = claimed_hashes[rel]
            if type(claimed) is not str or not SHA256.fullmatch(claimed):
                raise AdmissionDenied("invalid_evidence_hash")
            actual, _ = _sha256_file(folder / name, root=root, maximum=MAX_FILE)
            if actual != claimed:
                raise AdmissionDenied("evidence_tampering_detected")
            hashes[name] = actual
        safe_records.append({
            "case_id": case, "trial": trial, "variant": variant,
            "fixture_commit_sha": fixture,
            "cli_exit_success": cli_ok, "oracle_passed": oracle_ok,
            "evidence_sha256": hashes,
        })
    if seen != all_expected:
        raise AdmissionDenied("incomplete_pair_set")
    safe_records.sort(key=lambda x: (x["case_id"], x["trial"], x["variant"]))
    return {
        "schema_version": 1, "type": "PRIVATE_HASH_ONLY_NOT_REVIEWED",
        "job_id": checked["job_id"], "toolkit_sha": checked["toolkit_sha"],
        "provider": checked["provider"], "model": checked["model"],
        "observations_sha256": digest, "paired_attempts": len(safe_records),
        "records": safe_records, "independent_review": "NOT_PERFORMED",
        "safe_to_publish": False, "provider_cost_verified": False,
        "note": "Hash-only index; raw private evidence requires independent review.",
    }
