"""Opt-in three-call NCBI discovery -> citation review, no publishing.

Only a manually chosen fixed topic and the owner's contact are accepted.
Never performs an autonomous search or asks a model to interpret research.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from time import sleep
from typing import Any, Callable

from .citation_review import CitationInputError, review_batch
from .ncbi_esearch import NCBIError, TOPICS, find_candidates
from .ncbi_esummary import _contact, get_citation

MAX_CITATIONS = 2
INTER_REQUEST_GAP_SECONDS = 1.0


def review_topic(
    topic: str, *, contact: str,
    search: Callable[..., dict[str, Any]] = find_candidates,
    citation: Callable[..., dict[str, Any]] = get_citation,
    pause: Callable[[float], None] = sleep,
    now: datetime | None = None,
) -> dict[str, Any]:
    """At most one ESearch plus two ESummary GETs with a one-second gap."""
    if type(topic) is not str or topic not in TOPICS:
        raise NCBIError("ncbi_topic_denied")
    _contact(contact)
    stamp = now if now is not None else datetime.now(UTC)
    if not isinstance(stamp, datetime) or stamp.tzinfo is None:
        raise CitationInputError("now_timezone_required")
    discovery = search(topic, contact=contact)
    if discovery.get("status") == "NO_DATA":
        if discovery.get("pmids") != []:
            raise NCBIError("ncbi_discovery_inconsistent")
        return {
            "status": "NO_DATA", "topic": topic, "candidates": 0,
            "review": review_batch([], now=stamp),
            "scientific_claims_verified": False,
        }
    if discovery.get("status") != "UNVERIFIED_PMID_CANDIDATES":
        raise NCBIError("ncbi_discovery_unverified")
    pmids = discovery.get("pmids")
    if not isinstance(pmids, list) or len(pmids) > 5:
        raise NCBIError("ncbi_discovery_invalid_ids")
    # Always validate all discovered IDs, even those beyond the two-read cap.
    from .pubmed_fetch import validate_pmid, PubmedFetchError
    seen = set()
    for pmid in pmids:
        try:
            validate_pmid(pmid)
        except PubmedFetchError as exc:
            raise NCBIError("ncbi_discovery_invalid_ids") from exc
        if pmid in seen:
            raise NCBIError("ncbi_discovery_duplicate_ids")
        seen.add(pmid)
    results: list[dict[str, Any]] = []
    for pmid in pmids[:MAX_CITATIONS]:
        pause(INTER_REQUEST_GAP_SECONDS)
        entry = citation(pmid, contact=contact)
        if (not isinstance(entry, dict)
                or entry.get("status") not in ("UNVERIFIED_METADATA", "QUARANTINE")
                or entry.get("pmid") != pmid):
            raise NCBIError("ncbi_citation_inconsistent")
        # Quarantine is not submitted as a regular citation to human review.
        if entry["status"] == "QUARANTINE":
            return {
                "status": "HOLD", "topic": topic, "candidates": len(pmids),
                "reason": "quarantined_citation",
                "scientific_claims_verified": False,
            }
        results.append(entry)
    outcome = review_batch(results, now=stamp)
    # No extra source text, secrets, or unsupported truth/proof confidence.
    return {
        "status": outcome["status"], "topic": topic,
        "candidates": len(pmids), "review": outcome,
        "scientific_claims_verified": False,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--topic", required=True, choices=sorted(TOPICS))
    args = parser.parse_args()
    if not args.execute:
        data = {"status": "REJECTED", "reason": "explicit_execute_required"}
    else:
        try:
            data = review_topic(
                args.topic, contact=os.environ.get("HERMES_NCBI_CONTACT_EMAIL", "")
            )
        except (NCBIError, CitationInputError, OSError) as exc:
            reason = str(exc) if isinstance(exc, (NCBIError, CitationInputError)) else "local_run_failed"
            data = {"status": "UNKNOWN", "reason": reason}
    print(json.dumps(data, ensure_ascii=False, sort_keys=True))
    return 0 if data["status"] in ("MANUAL_REVIEW", "HOLD", "NO_DATA") else 2


if __name__ == "__main__":
    raise SystemExit(main())
