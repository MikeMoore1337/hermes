"""H-03: standalone bounded scientific metadata packet, not article publication.

Three exact Europe PMC public queries and at most one Crossref DOI lookup.
No LLM, subscriptions, external messages, YFC/Second Brain data or SSH.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .crossref import CrossrefError, review_candidate
from .europe_pmc import EuropePMCError, ID, run as search

DIRECTORY = Path("/var/lib/hermes-research-scout")
FILENAME = "latest-citations.json"
SCHEMA = "hermes-research-metadata-v1"
MAX_OUTPUT = 32_768
TOPIC_IDS = ("resistance-training", "muscle-hypertrophy", "exercise-recovery")


class DigestError(ValueError):
    """Fixed-code refusal, no untrusted article contents or secrets."""


def _review_item(candidate: object, topic: str) -> dict[str, object]:
    if type(candidate) is not dict or candidate.get("source") != "EUROPE_PMC":
        raise DigestError("candidate_origin_invalid")
    source_url, title = candidate.get("source_url"), candidate.get("title")
    if (type(source_url) is not str or len(source_url) > 130
            or not source_url.startswith((
                "https://europepmc.org/articles/PMC",
                "https://europepmc.org/article/MED/",
            )) or type(title) is not str or not 1 <= len(title) <= 300
            or any(ord(c) < 32 or ord(c) == 127 for c in title)):
        raise DigestError("candidate_metadata_invalid")
    status = candidate.get("status")
    if status not in ("MANUAL_REVIEW", "HOLD"):
        raise DigestError("candidate_status_invalid")
    reason = candidate.get("reason")
    if type(reason) is not str or reason not in {
        "metadata_only", "suspicious_title", "stale_publication_date",
        "date_unverified", "invalid_publication_date",
        "future_publication_date", "duplicate_doi",
    }:
        raise DigestError("candidate_reason_invalid")
    identifier = candidate.get("id")
    if type(identifier) is not str or ID.fullmatch(identifier) is None:
        raise DigestError("candidate_id_invalid")
    expected_url = (
        "https://europepmc.org/articles/" if identifier.startswith("PMC")
        else "https://europepmc.org/article/MED/"
    ) + identifier
    if source_url != expected_url:
        raise DigestError("candidate_url_invalid")
    date = candidate.get("first_publication_date")
    if date is not None and (
        type(date) is not str or len(date) != 10 or
        any(ch not in "0123456789-" for ch in date)
    ):
        raise DigestError("candidate_date_invalid")
    doi = candidate.get("doi")
    if doi is not None and (type(doi) is not str or len(doi) > 256):
        raise DigestError("candidate_doi_invalid")
    return {
        "topic": topic, "title": title, "identifier": identifier,
        "source_url": source_url, "doi": doi, "status": status,
        "reason": reason,
        "publication_date": date,
        "crossref_doi_status": "NOT_CHECKED",
        "scientific_claims_verified": False,
    }


def prepare(
    *,
    now: datetime,
    searcher: Callable[..., dict[str, Any]] = search,
    doi_verifier: Callable[..., dict[str, object]] = review_candidate,
) -> dict[str, object]:
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise DigestError("timezone_required")
    items: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    calls = 0
    selected_crossref: dict[str, object] | None = None
    for topic in TOPIC_IDS:
        calls += 1
        try:
            report = searcher(topic, now=now)
            if report["topic"] != topic or report["status"] not in (
                "MANUAL_REVIEW", "HOLD", "NO_DATA",
            ):
                raise DigestError("topic_response_invalid")
            candidates = report.get("candidates")
            if type(candidates) is not list or len(candidates) > 2:
                raise DigestError("topic_candidates_invalid")
            for candidate in candidates:
                reviewed = _review_item(candidate, topic)
                items.append(reviewed)
                if (selected_crossref is None and
                        reviewed["status"] == "MANUAL_REVIEW" and reviewed["doi"]):
                    selected_crossref = candidate
        except (EuropePMCError, DigestError):
            errors.append({"topic": topic, "reason": "source_unknown"})
    if selected_crossref is not None:
        calls += 1
        try:
            checked = doi_verifier(selected_crossref)
            if (type(checked) is not dict
                    or checked.get("status") != "MANUAL_REVIEW"
                    or checked.get("doi") != selected_crossref["doi"]):
                raise DigestError("crossref_result_invalid")
            for item in items:
                if (item["identifier"] == selected_crossref["id"]
                        and item["doi"] == checked["doi"]):
                    item["crossref_doi_status"] = "MATCHED_METADATA_ONLY"
                    break
        except (CrossrefError, DigestError):
            errors.append({"topic": "crossref", "reason": "doi_registry_unknown"})
    if len(items) > 6 or calls > 4:
        raise DigestError("resource_budget_exceeded")
    # One DOI across multiple topics remains a single article, not two
    # independent scientific corroborations.
    seen_dois: set[str] = set()
    for item in items:
        doi = item["doi"]
        if doi is not None:
            name = doi.casefold()
            if name in seen_dois:
                item["status"], item["reason"] = "HOLD", "duplicate_across_topics"
            seen_dois.add(name)
    status = ("HOLD" if errors else
              "MANUAL_REVIEW" if any(x["status"] == "MANUAL_REVIEW" for x in items)
              else "HOLD" if items else "NO_DATA")
    return {
        "schema": SCHEMA,
        "observed_at": now.astimezone(UTC).isoformat(),
        "status": status,
        "requests_attempted": calls,
        "topics": list(TOPIC_IDS),
        "items": items,
        "errors": errors,
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "report_requires_manual_review": True,
    }


def save(record: dict[str, object], directory: Path = DIRECTORY) -> None:
    if (type(record) is not dict or record.get("schema") != SCHEMA
            or record.get("automatic_publication") is not False
            or record.get("scientific_claims_verified") is not False):
        raise DigestError("report_schema_invalid")
    if directory.is_symlink() or not directory.is_dir():
        raise DigestError("directory_missing_or_symlinked")
    info = directory.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise DigestError("directory_permissions_invalid")
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_OUTPUT:
        raise DigestError("report_oversize")
    destination = directory / FILENAME
    if destination.is_symlink():
        raise DigestError("report_symlink_denied")
    if destination.exists():
        old = destination.stat()
        if (not stat.S_ISREG(old.st_mode) or
                old.st_uid != os.geteuid() or
                stat.S_IMODE(old.st_mode) != 0o600 or old.st_nlink != 1):
            raise DigestError("report_file_unsafe")
    fd, tmpname = tempfile.mkstemp(prefix=".citation-digest-", dir=directory)
    temporary = Path(tmpname)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as sink:
            sink.write(raw)
            sink.flush()
            os.fsync(sink.fileno())
        os.replace(temporary, destination)
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One daily bounded scientific metadata packet")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        report = prepare(now=datetime.now(UTC))
        save(report)
    except (DigestError, OSError):
        print(json.dumps({"status": "UNKNOWN", "reason": "metadata_report_unavailable"}))
        return 2
    print(json.dumps({
        "status": report["status"],
        "topics": len(TOPIC_IDS),
        "candidate_count": len(report["items"]),
        "errors": len(report["errors"]),
        "requests_attempted": report["requests_attempted"],
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }, sort_keys=True))
    return 0 if not report["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
