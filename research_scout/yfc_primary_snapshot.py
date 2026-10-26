"""I4 #599: operator-only, immutable JATS body snapshots for source review.

The official Europe PMC full-text preflight validates identity before extraction.
No claims, licences, reviewer status or permission to publish are inferred.
A one-shot write requires a dedicated protected directory and explicit action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

from . import yfc_fulltext_gate as gate
from . import yfc_draft_handoff as handoff

SOURCE_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
MAX_SNAPSHOT = 524_288
MAX_PARAGRAPHS = 350
MIN_PARAGRAPH = 20
DIRECTORY = handoff.SOURCE_DIR


class SnapshotHold(ValueError):
    """Only fixed machine reason codes, no source text."""


def require(value: bool, reason: str) -> None:
    if not value:
        raise SnapshotHold(reason)


def extracted_text(raw: bytes) -> bytes:
    """Extract bounded JATS body paragraphs; discard markup, not claim content."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise SnapshotHold("JATS_XML_INVALID") from None
    bodies = [element for element in root.iter()
              if element.tag.rsplit("}", 1)[-1] == "body"]
    require(len(bodies) == 1, "JATS_BODY_INVALID")
    paragraphs = []
    for element in bodies[0].iter():
        if element.tag.rsplit("}", 1)[-1] != "p":
            continue
        content = " ".join("".join(element.itertext()).split())
        if len(content) < MIN_PARAGRAPH:
            continue
        paragraphs.append(content)
        require(len(paragraphs) <= MAX_PARAGRAPHS, "JATS_PARAGRAPH_LIMIT")
    require(len(paragraphs) >= 1, "JATS_BODY_EMPTY")
    payload = ("\n\n".join(paragraphs) + "\n").encode("utf-8")
    require(len(payload) <= MAX_SNAPSHOT, "JATS_SNAPSHOT_TOO_LARGE")
    return payload


def _write_immutable(directory: Path, filename: str, raw: bytes) -> None:
    """Use an ownership-verified directory fd and O_EXCL/O_NOFOLLOW."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(directory, flags)
    except OSError:
        raise SnapshotHold("SOURCE_DIRECTORY_UNAVAILABLE") from None
    try:
        info = os.fstat(dir_fd)
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "SOURCE_DIRECTORY_UNTRUSTED")
        try:
            fd = os.open(filename,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0),
                         0o600, dir_fd=dir_fd)
        except FileExistsError:
            raise SnapshotHold("SOURCE_ALREADY_STAGED") from None
        except OSError:
            raise SnapshotHold("SOURCE_CREATE_FAILED") from None
        success = False
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                require(written > 0, "SOURCE_WRITE_FAILED")
                view = view[written:]
            os.fsync(fd)
            os.fsync(dir_fd)
            success = True
        except OSError:
            raise SnapshotHold("SOURCE_WRITE_FAILED") from None
        finally:
            os.close(fd)
            if not success:
                os.unlink(filename, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def stage(pmcid: str, source_id: str, xml: bytes, *,
          expected_doi: str | None = None,
          directory: Path = DIRECTORY) -> dict:
    """Fail closed on identity, then stage a private, immutable review copy."""
    require(type(source_id) is str and SOURCE_ID.fullmatch(source_id) is not None,
            "SOURCE_ID_INVALID")
    try:
        meta = gate.inspect(pmcid, xml, expected_doi=expected_doi)
    except gate.FulltextHold:
        raise SnapshotHold("FULLTEXT_IDENTITY_OR_STRUCTURE_HOLD") from None
    body = extracted_text(xml)
    digest = hashlib.sha256(body).hexdigest()
    _write_immutable(directory, source_id + ".txt", body)
    # The source URLs are deterministic; never accept arbitrary user URLs here.
    return {
        "status": "STAGED_NEEDS_EDITORIAL_REVIEW",
        "source_id": source_id,
        "pmcid": pmcid,
        "url": "https://pmc.ncbi.nlm.nih.gov/articles/" + pmcid + "/",
        "full_text_sha256": digest,
        "raw_xml_sha256": meta["sha256"],
        "license_reuse_verified": False,
        "primary_claims_verified": False,
        "correction_notice_verified": False,
        "hmac_submission_allowed": False,
        "automatic_publication": False,
        "network_calls": 0,
        "model_calls": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="I4 explicit OA source staging, no publishing")
    parser.add_argument("--pmcid", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--expected-doi")
    parser.add_argument("--fetch-and-stage", action="store_true")
    args = parser.parse_args(argv)
    if not args.fetch_and_stage:
        print(json.dumps({"status": "HOLD", "reason": "OPERATOR_OPT_IN_REQUIRED",
                          "automatic_publication": False}))
        return 2
    try:
        # One pinned official GET. No retry, redirect, credential or model call.
        raw = gate.fetch(args.pmcid)
        result = stage(args.pmcid, args.source_id, raw,
                       expected_doi=args.expected_doi)
    except (gate.FulltextHold, SnapshotHold):
        print(json.dumps({"status": "HOLD", "reason": "SOURCE_GATE_HOLD",
                          "automatic_publication": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
