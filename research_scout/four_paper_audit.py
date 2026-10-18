"""H-03: a single explicit, bounded four-paper Crossref update audit.

Operator-triggered only. Each preselected public DOI gets at most one GET via
crossref_updates.inspect; no retry, scheduler, publication, model or file I/O.
The result keeps Crossref metadata separate from publisher-only notices and
independent scientific review. Never upgrades a bibliographic candidate.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, date
import json
import re
from collections.abc import Callable
from typing import Any

from .crossref_updates import UpdateLookupError, checked_doi, inspect
from .report_view import curated_reports

SCHEMA = "hermes-research-four-paper-integrity-v1"
PUBLISHER_CORRECTION = {
    "42771055": "10.1007/s00520-026-11294-6",
}
MAX_REQUESTS = 4
EXPECTED_PMIDS = frozenset({"42840492", "42771055", "42797032", "42733310"})


def review(
    *,
    now: datetime,
    inspector: Callable[[str], dict[str, object]] = inspect,
) -> dict[str, object]:
    """Run 4 strictly fixed Crossref lookups and conservatively project status.

    The 4-request ceiling is independent of (and never added to) the daily
    digest's 5-request budget. This is NOT scheduled or automatically invoked.
    """
    if (type(now) is not datetime or now.tzinfo is None
            or now.utcoffset().total_seconds() != 0):
        raise ValueError("audit_time_must_be_utc")
    records = curated_reports()
    if (len(records) != MAX_REQUESTS
            or {r["pmid"] for r in records} != EXPECTED_PMIDS
            or len({r["doi"].casefold() for r in records}) != MAX_REQUESTS):
        raise ValueError("audit_fixed_sources_invalid")
    items: list[dict[str, object]] = []
    for record in records:
        pmid, doi = record["pmid"], record["doi"]
        publisher_notice = PUBLISHER_CORRECTION.get(pmid)
        item: dict[str, object] = {
            "pmid": pmid,
            "doi": doi,
            "source": "CROSSREF_REVERSE_UPDATES",
            "audit_state": "UNKNOWN",
            "crossref_coverage": "UNKNOWN",
            "crossref_notice_dois": [],
            "crossref_notice_codes": [],
            "publisher_notice_doi": publisher_notice,
            "publisher_notice_state": ("KNOWN_CORRECTION_REVIEW_REQUIRED"
                                      if publisher_notice else "NOT_INDEPENDENTLY_CLEARED"),
            "status": "HOLD" if publisher_notice else "MANUAL_REVIEW",
            "scientific_claims_verified": False,
            "publisher_correction_clearance_verified": False,
            "automatic_publication": False,
            "manual_review_required": True,
        }
        try:
            result = inspector(doi)
            _check(result, doi)
            found = [x["doi"] for x in result["notices"]]
            item["crossref_notice_dois"] = found
            item["crossref_notice_codes"] = result["notice_codes"]
            item["crossref_coverage"] = result["coverage"]
            item["audit_state"] = (
                "CROSSREF_REVIEW_REQUIRED"
                if result["status"] == "REVIEW_REQUIRED"
                else "NO_CROSSREF_UPDATE_FOUND_NOT_PUBLISHER_CLEARANCE"
            )
            if publisher_notice and publisher_notice.casefold() not in {
                x.casefold() for x in found
            }:
                item["audit_state"] = "CROSSREF_PUBLISHER_DISAGREEMENT_REVIEW_REQUIRED"
        except (UpdateLookupError, ValueError, TypeError, KeyError):
            # No raw upstream strings or third-party content in the report.
            item["audit_state"] = "UNKNOWN"
            item["crossref_coverage"] = "LOOKUP_UNAVAILABLE_OR_INVALID"
        items.append(item)
    return {
        "schema": SCHEMA,
        "observed_at": now.isoformat(),
        "requests_attempted": MAX_REQUESTS,
        "results": items,
        "report_status": "HOLD_FOR_EXPERT_REVIEW",
        "source_scope": "FOUR_FIXED_CROSSREF_REVERSE_UPDATE_METADATA_LOOKUPS_ONLY",
        "authoritative_publisher_clearance": False,
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "manual_review_required": True,
    }


def _check(result: object, doi: str) -> None:
    """Reject impossible or false-clearance results before owner presentation."""
    if type(result) is not dict:
        raise ValueError("audit_untrusted_result")
    if (result.get("doi") != doi or result.get("source") != "CROSSREF"
            or result.get("scientific_claims_verified") is not False
            or result.get("automatic_publication") is not False
            or result.get("authoritative_notice_clearance") is not False
            or result.get("manual_review_required") is not True):
        raise ValueError("audit_untrusted_result")
    notices, codes = result.get("notices"), result.get("notice_codes")
    if (type(notices) is not list or type(codes) is not list
            or len(notices) > 5 or len(codes) > 4 or
            len(codes) != len(set(codes)) or
            any(c not in {
                "CORRECTION_NOTICE", "RETRACTION_OR_WITHDRAWAL_NOTICE",
                "EXPRESSION_OF_CONCERN", "OTHER_OR_UNKNOWN_NOTICE"
            } for c in codes)):
        raise ValueError("audit_untrusted_notices")
    valid_notices: list[str] = []
    derived_codes: set[str] = set()
    for notice in notices:
        if (type(notice) is not dict
                or set(notice) != {"doi", "notice_type", "published", "source"}
                or notice["source"] != "CROSSREF_REVERSE_UPDATE_METADATA"
                or notice["notice_type"] not in {
                    "CORRECTION_NOTICE", "RETRACTION_OR_WITHDRAWAL_NOTICE",
                    "EXPRESSION_OF_CONCERN", "OTHER_OR_UNKNOWN_NOTICE"
                }):
            raise ValueError("audit_untrusted_notice")
        # Revalidate even injected/in-memory inspector responses, not just
        # live Crossref JSON parsed by the lower-level component.
        checked_doi(notice["doi"])
        published = notice["published"]
        if (type(published) is not str
                or re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}){0,2}", published) is None):
            raise ValueError("audit_untrusted_date")
        parts = [int(part) for part in published.split("-")]
        try:
            date(parts[0], parts[1] if len(parts) > 1 else 1,
                 parts[2] if len(parts) > 2 else 1)
        except ValueError:
            raise ValueError("audit_untrusted_date") from None
        valid_notices.append(notice["doi"].casefold())
        derived_codes.add(notice["notice_type"])
    if len(valid_notices) != len(set(valid_notices)) or set(codes) != derived_codes:
        raise ValueError("audit_notice_conflict")
    if result.get("coverage") not in (
        "CROSSREF_FILTER_TRUNCATED", "CROSSREF_REVERSE_UPDATES_ONLY"
    ):
        raise ValueError("audit_coverage_invalid")
    status = result.get("status")
    if status not in ("REVIEW_REQUIRED", "NOT_FOUND_WITH_COVERAGE"):
        raise ValueError("audit_status_invalid")
    if ((status == "NOT_FOUND_WITH_COVERAGE" and (
            notices or result["coverage"] != "CROSSREF_REVERSE_UPDATES_ONLY"))
            or (status == "REVIEW_REQUIRED" and not notices
                and result["coverage"] != "CROSSREF_FILTER_TRUNCATED")):
        raise ValueError("audit_status_conflict")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit four-publication metadata audit")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "requests_attempted": 0}))
        return 0
    result = review(now=datetime.now(UTC))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 2 if any(i["audit_state"] == "UNKNOWN" for i in result["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
