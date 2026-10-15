"""H-03: standalone bounded scientific metadata packet, not article publication.

Three exact Europe PMC searches, one Crossref DOI, and at most one article-integrity lookup.
No LLM, subscriptions, external messages, YFC/Second Brain data or SSH.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from datetime import UTC, date as date_module, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .crossref import CrossrefError, review_candidate
from .article_integrity import ArticleIntegrityError, inspect as inspect_article
from .europe_pmc import EuropePMCError, ID, MAX_AGE_DAYS, run as search
from .pubmed_fetch import DOI

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
        "future_publication_date", "duplicate_doi", "doi_missing",
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
    # A syntactically plausible date (e.g. 2026-02-30) is not evidence
    # of an actual publication. Validate the calendar even for HOLD items.
    if date is not None:
        try:
            date_module.fromisoformat(date)
        except ValueError:
            raise DigestError("candidate_date_invalid") from None
    doi = candidate.get("doi")
    if doi is not None and (type(doi) is not str or len(doi) > 256
                            or DOI.fullmatch(doi) is None):
        raise DigestError("candidate_doi_invalid")
    # A missing DOI in the lite row cannot be treated as publication-ready:
    # the same PMCID may still have a DOI in a separate PubMed record.
    if doi is None and status == "MANUAL_REVIEW":
        status, reason = "HOLD", "doi_missing"
    return {
        "topic": topic, "title": title, "identifier": identifier,
        "source_url": source_url, "doi": doi, "status": status,
        "reason": reason,
        "publication_date": date,
        "crossref_doi_status": "NOT_CHECKED",
        "article_notice_state": "NOT_CHECKED",
        "article_notice_codes": [],
        "scientific_claims_verified": False,
    }


def prepare(
    *,
    now: datetime,
    searcher: Callable[..., dict[str, Any]] = search,
    doi_verifier: Callable[..., dict[str, object]] = review_candidate,
    integrity_verifier: Callable[[str, str], dict[str, object]] | None = None,
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
    # Optional single official Europe PMC integrity check for the SAME item
    # selected for DOI verification. No extra requests for the other items.
    # The production entrypoint opts in; older pure offline callers stay offline.
    if selected_crossref is not None and integrity_verifier is not None:
        calls += 1
        identifier = selected_crossref["id"]
        source = "PMC" if identifier.startswith("PMC") else "MED"
        current = next((x for x in items if x["identifier"] == identifier), None)
        if current is None:
            raise DigestError("integrity_candidate_missing")
        try:
            article = integrity_verifier(source, identifier)
            if (type(article) is not dict
                    or article.get("article_source") != source
                    or article.get("article_identifier") != identifier
                    or article.get("status") not in ("HOLD", "MANUAL_REVIEW")
                    or article.get("notice_state") not in (
                        "REVIEW_REQUIRED", "NOT_REPORTED_IN_THIS_METADATA",
                    ) or article.get("scientific_claims_verified") is not False
                    or article.get("automatic_publication") is not False):
                raise DigestError("integrity_response_invalid")
            codes = article.get("notice_codes")
            if (type(codes) is not list or len(codes) > 4 or
                    len(set(map(str, codes))) != len(codes) or
                    not all(type(code) is str and code in (
                        "CORRECTION_NOTICE", "RETRACTION_OR_WITHDRAWAL_NOTICE",
                        "EXPRESSION_OF_CONCERN", "OTHER_OR_UNKNOWN_NOTICE",
                    ) for code in codes)):
                raise DigestError("integrity_notice_invalid")
            if article["notice_state"] == "REVIEW_REQUIRED" and not codes:
                raise DigestError("integrity_notice_invalid")
            if article["notice_state"] != "REVIEW_REQUIRED" and codes:
                raise DigestError("integrity_notice_invalid")
            current["article_notice_state"] = article["notice_state"]
            current["article_notice_codes"] = codes
            if (article.get("doi") != selected_crossref["doi"] or
                    article["status"] == "HOLD" or
                    article["notice_state"] == "REVIEW_REQUIRED"):
                current["status"] = "HOLD"
                current["reason"] = "integrity_hold"
        except (ArticleIntegrityError, DigestError):
            current["status"] = "HOLD"
            current["reason"] = "integrity_unknown"
            current["article_notice_state"] = "UNAVAILABLE"
            errors.append({"topic": "article-integrity",
                           "reason": "integrity_unavailable"})
    if len(items) > 6 or calls > 5:
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
    # A single unsafe/uncertain citation holds the whole packet. Consumers
    # must never interpret a mixed report as universally reviewable.
    status = ("HOLD" if errors or any(x["status"] == "HOLD" for x in items) else
              "MANUAL_REVIEW" if items else "NO_DATA")
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
    if (type(record) is not dict or set(record) != {
            "schema", "observed_at", "status", "requests_attempted",
            "topics", "items", "errors", "scientific_claims_verified",
            "automatic_publication", "report_requires_manual_review",
        } or record["schema"] != SCHEMA
            or record["automatic_publication"] is not False
            or record["scientific_claims_verified"] is not False
            or record["report_requires_manual_review"] is not True):
        raise DigestError("report_schema_invalid")
    if record["status"] not in ("NO_DATA", "MANUAL_REVIEW", "HOLD"):
        raise DigestError("report_status_invalid")
    if (record["topics"] != list(TOPIC_IDS)
            or type(record["requests_attempted"]) is not int
            or not 3 <= record["requests_attempted"] <= 5):
        raise DigestError("report_budget_invalid")
    items, errors = record["items"], record["errors"]
    if type(items) is not list or len(items) > 6 or type(errors) is not list or len(errors) > 4:
        raise DigestError("report_entries_invalid")
    if (type(record["observed_at"]) is not str or
            len(record["observed_at"]) > 40):
        raise DigestError("report_time_invalid")
    try:
        moment = datetime.fromisoformat(record["observed_at"])
    except ValueError:
        raise DigestError("report_time_invalid") from None
    if moment.tzinfo is None or moment.utcoffset().total_seconds() != 0:
        raise DigestError("report_time_invalid")
    for item in items:
        if type(item) is not dict or set(item) != {
            "topic", "title", "identifier", "source_url", "doi", "status",
            "reason", "publication_date", "crossref_doi_status",
            "article_notice_state", "article_notice_codes",
            "scientific_claims_verified",
        } or item["topic"] not in TOPIC_IDS or item["scientific_claims_verified"] is not False:
            raise DigestError("report_item_schema_invalid")
        original = {
            "source": "EUROPE_PMC", "id": item["identifier"],
            "source_url": item["source_url"], "title": item["title"],
            "doi": item["doi"], "status": item["status"],
            "reason": item["reason"],
            "first_publication_date": item["publication_date"],
        }
        if item["reason"] == "duplicate_across_topics":
            original["reason"] = "duplicate_doi"
        if item["reason"] in ("integrity_hold", "integrity_unknown"):
            original["reason"] = "metadata_only"
        _review_item(original, item["topic"])
        if item["crossref_doi_status"] not in ("NOT_CHECKED", "MATCHED_METADATA_ONLY"):
            raise DigestError("report_crossref_state_invalid")
        state, codes = item["article_notice_state"], item["article_notice_codes"]
        if (state not in ("NOT_CHECKED", "NOT_REPORTED_IN_THIS_METADATA",
                          "REVIEW_REQUIRED", "UNAVAILABLE")
                or type(codes) is not list or len(codes) > 4
                or any(type(code) is not str or code not in (
                    "CORRECTION_NOTICE", "RETRACTION_OR_WITHDRAWAL_NOTICE",
                    "EXPRESSION_OF_CONCERN", "OTHER_OR_UNKNOWN_NOTICE",
                ) for code in codes)
                or (state == "REVIEW_REQUIRED") != bool(codes)):
            raise DigestError("report_article_notice_invalid")
        if state in ("REVIEW_REQUIRED", "UNAVAILABLE") and item["status"] != "HOLD":
            raise DigestError("report_article_not_on_hold")
        normalized = _review_item(original, item["topic"])
        # Checking only the schema is insufficient: untrusted or accidentally
        # mutated reports must not promote absent DOI / stale / suspicious
        # citations to MANUAL_REVIEW, or relabel metadata-only HOLD as healthy.
        # Integrity and cross-topic HOLD reasons are derived by prepare() after
        # the original Europe PMC check; these are the only special cases.
        derived_reason = item["reason"]
        if derived_reason in (
            "duplicate_across_topics", "integrity_hold", "integrity_unknown",
        ):
            if item["status"] != "HOLD":
                raise DigestError("report_item_status_reason_conflict")
        elif (item["status"] != normalized["status"]
              or item["reason"] != normalized["reason"]):
            raise DigestError("report_item_status_reason_conflict")
        if item["status"] not in ("HOLD", "MANUAL_REVIEW"):
            raise DigestError("report_item_status_reason_conflict")
        if item["reason"] == "duplicate_across_topics" and item["doi"] is None:
            raise DigestError("report_item_status_reason_conflict")
        if item["status"] == "MANUAL_REVIEW" and (
            item["reason"] != "metadata_only" or item["doi"] is None
        ):
            raise DigestError("report_item_status_reason_conflict")
        # The producer's Europe PMC window is 30 days, with a one-day
        # future tolerance. Re-enforce this at the storage boundary so
        # tampered metadata cannot promote stale or future papers.
        if item["status"] == "MANUAL_REVIEW":
            published = item["publication_date"]
            if published is None:
                raise DigestError("report_publication_date_unreviewable")
            published_day = date_module.fromisoformat(published)
            observed_day = moment.date()
            if (published_day > observed_day + timedelta(days=1)
                    or observed_day - published_day > timedelta(days=MAX_AGE_DAYS)):
                raise DigestError("report_publication_date_unreviewable")
    for error in errors:
        if (type(error) is not dict or set(error) != {"topic", "reason"}
                or error["topic"] not in (*TOPIC_IDS, "crossref", "article-integrity")
                or error["reason"] not in ("source_unknown", "doi_registry_unknown",
                                           "integrity_unavailable")):
            raise DigestError("report_error_schema_invalid")
    # Reconstruct the packet verdict from the validated constituent records.
    # Any HOLD or source/registry error must hold the *entire* packet; neither
    # an empty result nor a mixed one can be presented as MANUAL_REVIEW.
    actual_status = (
        "HOLD" if errors or any(item["status"] == "HOLD" for item in items)
        else "MANUAL_REVIEW" if items else "NO_DATA"
    )
    if record["status"] != actual_status:
        raise DigestError("report_aggregate_status_conflict")
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
        report = prepare(now=datetime.now(UTC), integrity_verifier=inspect_article)
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
        "integrity_holds": sum(x["reason"] in ("integrity_hold", "integrity_unknown")
                               for x in report["items"]),
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }, sort_keys=True))
    return 0 if not report["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
