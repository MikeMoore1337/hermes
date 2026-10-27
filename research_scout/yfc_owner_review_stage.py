"""I4 #599: one-shot, offline staging of a pending-review YFC article packet.

No scientific or publisher-rights attestation is created by this program.
The packet is a draft proposal only, with all five claims still pending.
Never use model/network/HMAC/Root credentials and never publish. Existing
reviewed documents cannot be overwritten, replayed or deleted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from . import yfc_draft_handoff as handoff

CANDIDATE = Path(__file__).resolve().parent / "reviews/i4-lifting-load-candidate-2026-10-27.json"
DESTINATION = handoff.REVIEWED_FILE
SOURCE_DIR = handoff.SOURCE_DIR
EXPECTED_SOURCES = {
    "fink2016": (
        "https://pmc.ncbi.nlm.nih.gov/articles/PMC4899398/",
        "c96a1e48f963b4914d41519f12ea7a4e6e440d218bd10fdd43197eb23b3febe8",
    ),
    "vann2022": (
        "https://pmc.ncbi.nlm.nih.gov/articles/PMC8962955/",
        "089d000f1f561d5898b978618897dd9453663e0b6895c7320189286a701e7f88",
    ),
}


class StageHold(ValueError):
    """Stable failure codes, never display source/article bytes."""


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, obj in pairs:
        if key in value:
            raise StageHold("DUPLICATE_JSON_KEY")
        value[key] = obj
    return value


def prepare(candidate: Path = CANDIDATE, *, source_dir: Path = SOURCE_DIR) -> bytes:
    """Build candidate from pinned original source hashes; no disk writes."""
    try:
        meta = candidate.lstat()
        if (not stat.S_ISREG(meta.st_mode) or candidate.is_symlink()
                or not 0 < meta.st_size <= handoff.MAX_REQUEST):
            raise StageHold("CANDIDATE_UNTRUSTED")
        document = json.loads(candidate.read_bytes(), object_pairs_hook=_unique)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, StageHold):
            raise
        raise StageHold("CANDIDATE_UNAVAILABLE") from None
    if type(document) is not dict or document.get("source_receipts") != []:
        raise StageHold("CANDIDATE_CHANGED")
    article = document.get("article")
    if (type(article) is not dict or article.get("domain_reviewer") is not None
            or article.get("article_kind") != "evidence_review"
            or article.get("risk_level") != "low"
            or article.get("evidence_level") != "limited"
            or type(article.get("claims")) is not list
            or len(article["claims"]) != 5
            or type(article.get("claim_source_matrix")) is not list
            or len(article["claim_source_matrix"]) != 5
            or any(row.get("review_status") != "pending"
                   or row.get("support_level") != "unclear"
                   for row in article["claim_source_matrix"])):
        raise StageHold("EDITORIAL_APPROVAL_NOT_ATTESTED")
    sources = article.get("sources")
    if (type(sources) is not list or len(sources) != len(EXPECTED_SOURCES)
            or any(type(item) is not dict or
                   item.get("source_id") not in EXPECTED_SOURCES or
                   item.get("url") != EXPECTED_SOURCES[item["source_id"]][0]
                   for item in sources)
            or {item["source_id"] for item in sources} != set(EXPECTED_SOURCES)):
        raise StageHold("SOURCE_BINDING_CHANGED")
    document["source_receipts"] = [
        {"source_id": item["source_id"], "url": item["url"],
         "full_text_sha256": EXPECTED_SOURCES[item["source_id"]][1]}
        for item in sources
    ]
    # Ensures exact protected private source byte hashes match the receipts;
    # enforces complete article, bounded payload, pending claim matrix.
    try:
        payload = handoff.build_payload(document, source_dir=source_dir)
        handoff._encode(payload)
    except handoff.HandoffHold as exc:
        raise StageHold(str(exc)) from None
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    if not 0 < len(raw) <= handoff.MAX_REQUEST:
        raise StageHold("REVIEW_PACKET_SIZE")
    return raw


def stage(raw: bytes, *, destination: Path = DESTINATION) -> str:
    """Immutable 0600 local file, strictly owner-only, never overwrite."""
    if type(raw) is not bytes or not 0 < len(raw) <= handoff.MAX_REQUEST:
        raise StageHold("REVIEW_PACKET_SIZE")
    parent = destination.parent
    try:
        p = parent.lstat()
        if (not stat.S_ISDIR(p.st_mode) or parent.is_symlink()
                or p.st_uid != os.geteuid()
                or stat.S_IMODE(p.st_mode) != 0o700):
            raise StageHold("DESTINATION_UNTRUSTED")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # An ambiguous partial write remains quarantined; never overwrite.
            raise
        observed = handoff._protected_bytes(destination, max_size=handoff.MAX_REQUEST)
        if observed != raw:
            raise StageHold("STAGED_PACKET_MISMATCH")
        return hashlib.sha256(observed).hexdigest()
    except FileExistsError:
        raise StageHold("REVIEW_PACKET_ALREADY_EXISTS") from None
    except (OSError, handoff.HandoffHold) as exc:
        raise StageHold("REVIEW_PACKET_UNAVAILABLE") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One-shot protected I4 draft packet")
    parser.add_argument("--stage", action="store_true",
                        help="Explicit local write only; never transmit")
    args = parser.parse_args(argv)
    if not args.stage:
        print(json.dumps({"status": "NOT_EXECUTED", "file_writes": 0,
                          "hmac_submission": False, "automatic_publication": False}))
        return 0
    try:
        raw = prepare()
        digest = stage(raw)
    except StageHold as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc),
                          "hmac_submission": False, "automatic_publication": False}))
        return 2
    print(json.dumps({"status": "PENDING_EDITORIAL_REVIEW", "packet_sha256": digest,
                      "claims_pending": 5, "independent_science_review": False,
                      "publisher_clearance_attested": False,
                      "hmac_submission": False, "automatic_publication": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
