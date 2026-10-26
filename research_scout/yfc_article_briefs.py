"""I4 / #599: fail-closed metadata briefs from the existing Research Scout digest.

This is NOT an article generator, HMAC client, YFC candidate publisher or
scientific reviewer. The digests contain only bibliographic metadata. Each
proposed item is therefore either HOLD or NEEDS_CONTENT and CANNOT be posted
as HermesWebArticleProposal. No LLM, subscriptions, HTTP or publication.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
import tempfile
from pathlib import Path
import stat

from .core import PROMPT_INJECTION
from .daily_digest import (
    DIRECTORY, FILENAME, MAX_OUTPUT, SCHEMA as DIGEST_SCHEMA,
    TOPIC_IDS,
)
from .europe_pmc import MAX_AGE_DAYS
from .review_draft import ReviewDraftError, build_daily_item_draft

SCHEMA = "hermes-i4-source-gated-briefs-v1"
POLICY = "AUTO_DRAFT_ONLY"
MAX_BRIEFS = 6
MAX_INPUT_AGE = timedelta(hours=48)
_REASONS = frozenset({
    "metadata_only", "suspicious_title", "stale_publication_date",
    "date_unverified", "invalid_publication_date", "future_publication_date",
    "duplicate_doi", "doi_missing", "duplicate_across_topics",
    "integrity_hold", "integrity_unknown", "doi_enriched_review_required",
})
_NOTICE = frozenset({
    "NOT_CHECKED", "NOT_REPORTED_IN_THIS_METADATA", "REVIEW_REQUIRED",
    "UNAVAILABLE",
})


class BriefHold(ValueError):
    """Stable machine reason only; untrusted source text is never logged."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BriefHold(reason)


def _observed(value: object, *, now: datetime) -> datetime:
    _require(type(value) is str and len(value) <= 40, "DIGEST_TIMESTAMP_INVALID")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise BriefHold("DIGEST_TIMESTAMP_INVALID") from None
    _require(moment.tzinfo is not None and moment.utcoffset() == timedelta(0),
             "DIGEST_TIMESTAMP_INVALID")
    _require(-timedelta(minutes=5) <= now - moment <= MAX_INPUT_AGE,
             "DIGEST_STALE_OR_FUTURE")
    return moment


def _source_key(item: dict) -> str:
    # Opaque stable digest, not YFC candidate_id nor submission idempotency key.
    unique = (item["doi"].casefold() if item["doi"] else
              "europe-pmc:" + item["identifier"])
    return hashlib.sha256(unique.encode("utf-8")).hexdigest()[:32]


def build_briefs(record: object, *, now: datetime) -> dict:
    """Project validated bibliographic records; NEVER return a YFC article."""
    _require(isinstance(now, datetime) and now.tzinfo is not None,
             "NOW_TIMEZONE_REQUIRED")
    now = now.astimezone(UTC)
    fields = {"schema", "observed_at", "status", "requests_attempted",
              "topics", "items", "errors", "scientific_claims_verified",
              "automatic_publication", "report_requires_manual_review"}
    _require(type(record) is dict and set(record) == fields
             and record["schema"] == DIGEST_SCHEMA
             and record["topics"] == list(TOPIC_IDS)
             and record["scientific_claims_verified"] is False
             and record["automatic_publication"] is False
             and record["report_requires_manual_review"] is True,
             "DIGEST_CONTRACT_INVALID")
    observed = _observed(record["observed_at"], now=now)
    items, errors = record["items"], record["errors"]
    _require(type(items) is list and len(items) <= MAX_BRIEFS
             and type(errors) is list and len(errors) <= 4
             and type(record["requests_attempted"]) is int
             and 3 <= record["requests_attempted"] <= 5,
             "DIGEST_BOUNDS_INVALID")
    _require(all(type(error) is dict and
                 error.get("reason") in {"source_unknown", "doi_registry_unknown",
                                         "integrity_unavailable"} and
                 error.get("topic") in (*TOPIC_IDS, "crossref", "article-integrity")
                 and set(error) == {"reason", "topic"} for error in errors),
             "DIGEST_ERROR_INVALID")
    briefs = []
    seen = set()
    for item in items:
        _require(type(item) is dict and
                 item.get("topic") in TOPIC_IDS
                 and item.get("reason") in _REASONS
                 and item.get("article_notice_state") in _NOTICE
                 and item.get("scientific_claims_verified") is False,
                 "SOURCE_CONTRACT_INVALID")
        try:
            draft = build_daily_item_draft(item)
        except (ReviewDraftError, TypeError, ValueError, KeyError):
            raise BriefHold("SOURCE_CONTRACT_INVALID") from None
        # This is untrusted index metadata; prompt injections are never
        # interpreted as editorial instructions, even for HOLD entries.
        _require(not PROMPT_INJECTION.search(draft["title"]),
                 "SOURCE_INSTRUCTION_DETECTED")
        source_key = _source_key(item)
        duplicate = source_key in seen
        seen.add(source_key)
        published = item["publication_date"]
        fresh = False
        if type(published) is str:
            from datetime import date
            try:
                day = date.fromisoformat(published)
            except ValueError:
                raise BriefHold("SOURCE_PUBLICATION_DATE_INVALID") from None
            delta = observed.date() - day
            fresh = -1 <= delta.days <= MAX_AGE_DAYS
        notice = item["article_notice_state"]
        held = (item["status"] != "MANUAL_REVIEW"
                or item["reason"] != "metadata_only"
                or notice != "NOT_REPORTED_IN_THIS_METADATA"
                or bool(item["article_notice_codes"])
                or not fresh or duplicate or bool(errors))
        reasons = ["primary_full_text_and_claim_matrix_missing",
                   "publisher_license_and_notice_clearance_unverified",
                   "qualified_scientific_review_not_attested"]
        if not fresh:
            reasons.append("publication_date_unverified_or_stale")
        if notice in {"REVIEW_REQUIRED", "UNAVAILABLE"}:
            reasons.append("publisher_notice_requires_review")
        if duplicate:
            reasons.append("duplicate_source_reference")
        if errors:
            reasons.append("source_collection_incomplete")
        if item["status"] == "HOLD":
            reasons.append("source_previously_held")
        briefs.append({
            "source_key": source_key,
            "topic": item["topic"],
            "bibliographic_title": draft["title"],
            "identifier": item["identifier"],
            "doi": item["doi"],
            "source_url": draft["source_link"],
            "publication_date": published,
            "status": "HOLD" if held else "NEEDS_CONTENT",
            "reason_codes": reasons,
            "claim_source_matrix": [],
            "scientific_claims_verified": False,
            "expert_approval": False,
            "full_text_verified": False,
            "candidate_provisioning_allowed": False,
            "yfc_intake_payload": None,
            "publication_allowed": False,
        })
    expected_status = ("HOLD" if errors or
                       any(item["status"] == "HOLD" for item in items)
                       else "MANUAL_REVIEW" if items else "NO_DATA")
    _require(record["status"] == expected_status, "DIGEST_VERDICT_CONFLICT")
    # A confirmed duplicate in the source inputs may not appear twice as two
    # pending candidates. Never create a fake YFC candidate identifier.
    return {
        "schema": SCHEMA,
        "policy": POLICY,
        "source_digest_schema": DIGEST_SCHEMA,
        "source_observed_at": observed.isoformat(),
        "status": ("HOLD" if record["status"] == "HOLD"
                   else "NEEDS_CONTENT" if briefs else "NO_DATA"),
        "briefs": briefs,
        "brief_count": len(briefs),
        "scientific_claims_verified": False,
        "generation_provider": "none",
        "model_calls": 0,
        "network_calls": 0,
        "yfc_intake_payload": None,
        "hmac_transmission_allowed": False,
        "automatic_publication": False,
        "next_gate": "VERIFIED_PRIMARY_TEXT_AND_CLAIM_SOURCE_MATRIX",
    }


def read_source(path: Path = DIRECTORY / FILENAME) -> dict:
    """Read *only* the pinned private Research Scout digest, no arbitrary paths."""
    _require(path == DIRECTORY / FILENAME, "SOURCE_PATH_NOT_ALLOWLISTED")
    try:
        parent, meta = path.parent.lstat(), path.lstat()
        _require(stat.S_ISDIR(parent.st_mode) and
                 stat.S_IMODE(parent.st_mode) == 0o700
                 and parent.st_uid == os.geteuid(), "SOURCE_DIRECTORY_UNTRUSTED")
        _require(stat.S_ISREG(meta.st_mode) and
                 stat.S_IMODE(meta.st_mode) == 0o600
                 and meta.st_uid == os.geteuid()
                 and meta.st_nlink == 1
                 and 0 < meta.st_size <= MAX_OUTPUT, "SOURCE_FILE_UNTRUSTED")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            inside = os.fstat(fd)
            _require((inside.st_dev, inside.st_ino, inside.st_size) ==
                     (meta.st_dev, meta.st_ino, meta.st_size),
                     "SOURCE_FILE_CHANGED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                content = stream.read(MAX_OUTPUT + 1)
        finally:
            os.close(fd)
        _require(len(content) == meta.st_size, "SOURCE_FILE_CHANGED")
        return json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise BriefHold("SOURCE_READ_UNAVAILABLE") from None



BRIEFS_FILENAME = "latest-yfc-article-briefs.json"
MAX_BRIEFS_BYTES = 64 * 1024


def save_briefs(result: object, directory: Path = DIRECTORY) -> None:
    """Atomic 0600 source-only brief snapshot; no scripts/services/network.

    A validated digest plan is informational, not YFC intake or permission.
    Failed writes must never remove a valid citation digest.
    """
    require_shape = (type(result) is dict and result.get("schema") == SCHEMA
                     and result.get("policy") == POLICY
                     and result.get("hmac_transmission_allowed") is False
                     and result.get("automatic_publication") is False
                     and result.get("model_calls") == 0
                     and result.get("network_calls") == 0
                     and result.get("yfc_intake_payload") is None
                     and type(result.get("brief_count")) is int
                     and type(result.get("briefs")) is list
                     and len(result["briefs"]) == result["brief_count"] <= MAX_BRIEFS
                     and all(type(row) is dict
                             and row.get("status") in ("HOLD", "NEEDS_CONTENT")
                             and row.get("yfc_intake_payload") is None
                             and row.get("candidate_provisioning_allowed") is False
                             and row.get("publication_allowed") is False
                             for row in result["briefs"]))
    _require(require_shape, "BRIEFS_CONTRACT_UNTRUSTED")
    try:
        info = directory.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700,
                 "BRIEFS_DIRECTORY_UNTRUSTED")
        target = directory / BRIEFS_FILENAME
        if target.is_symlink():
            raise BriefHold("BRIEFS_SYMLINK_DENIED")
        if target.exists():
            existing = target.stat()
            _require(stat.S_ISREG(existing.st_mode)
                     and stat.S_IMODE(existing.st_mode) == 0o600
                     and existing.st_uid == os.geteuid() and existing.st_nlink == 1,
                     "BRIEFS_EXISTING_FILE_UNTRUSTED")
        raw = json.dumps(result, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
        _require(0 < len(raw) <= MAX_BRIEFS_BYTES, "BRIEFS_CAPACITY")
        fd, name = tempfile.mkstemp(dir=directory, prefix=".i4-briefs-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
            root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        finally:
            Path(name).unlink(missing_ok=True)
    except OSError:
        raise BriefHold("BRIEFS_WRITE_UNAVAILABLE") from None


def main() -> int:
    try:
        result = build_briefs(read_source(), now=datetime.now(UTC))
    except BriefHold as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc),
                          "policy": POLICY, "auto_publish": False}))
        return 2
    # Never dump arbitrary source titles/contents into service logs.
    print(json.dumps({
        "status": result["status"], "policy": POLICY,
        "brief_count": result["brief_count"],
        "held": sum(b["status"] == "HOLD" for b in result["briefs"]),
        "needs_content": sum(b["status"] == "NEEDS_CONTENT" for b in result["briefs"]),
        "yfc_intake_payload": None, "auto_publish": False,
        "model_calls": 0, "network_calls": 0,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
