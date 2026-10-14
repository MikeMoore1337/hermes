"""One explicitly requested ESearch query for fixed PubMed research topics."""
from __future__ import annotations

import http.client
import json
import os
from typing import Any, Callable
from urllib.parse import urlencode

from .ncbi_esummary import (
    HOST, MAX_BODY, NCBIError, TOOL, _PinnedNCBI, _contact, _resolve,
    _unique_json_object,
)
from .pubmed_fetch import validate_pmid

TOPICS = {
    "resistance-training": (
        '("resistance training"[Title/Abstract] OR "strength training"[Title/Abstract])'
        ' AND (meta-analysis[Publication Type] OR randomized controlled trial[Publication Type])'
    ),
    "muscle-hypertrophy": (
        '"muscle hypertrophy"[Title/Abstract]'
        ' AND (meta-analysis[Publication Type] OR randomized controlled trial[Publication Type])'
    ),
    "exercise-recovery": (
        '("exercise recovery"[Title/Abstract] OR "muscle recovery"[Title/Abstract])'
        ' AND (systematic review[Publication Type] OR randomized controlled trial[Publication Type])'
    ),
}
MAX_IDS = 5


def _fetch(topic: str, contact: str) -> bytes:
    if type(topic) is not str or topic not in TOPICS:
        raise NCBIError("ncbi_topic_denied")
    _contact(contact)
    connection = _PinnedNCBI(_resolve())
    query = urlencode({
        "db": "pubmed", "term": TOPICS[topic], "retmode": "json",
        "retmax": str(MAX_IDS), "retstart": "0",
        "reldate": "30", "datetype": "edat", "sort": "pub date",
        "tool": TOOL, "email": contact,
    })
    try:
        connection.request(
            "GET", "/entrez/eutils/esearch.fcgi?" + query,
            headers={
                "Host": HOST, "Accept": "application/json",
                "Accept-Encoding": "identity", "Connection": "close",
                "User-Agent": "HermesResearchScout/0.1",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise NCBIError("ncbi_esearch_http_refused")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise NCBIError("ncbi_esearch_compression_denied")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise NCBIError("ncbi_esearch_content_denied")
        length = response.getheader("Content-Length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or int(length) > MAX_BODY
        ):
            raise NCBIError("ncbi_esearch_too_large")
        result = response.read(MAX_BODY + 1)
        if len(result) > MAX_BODY:
            raise NCBIError("ncbi_esearch_too_large")
        return result
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise NCBIError("ncbi_esearch_network_failed") from exc
    finally:
        connection.close()


def _number(value: Any) -> int:
    if (type(value) is not str or not value.isascii() or not value.isdigit()
            or len(value) > 9):
        raise NCBIError("ncbi_esearch_count_invalid")
    return int(value)


def parse_candidates(payload: bytes, topic: str) -> dict[str, Any]:
    if type(topic) is not str or topic not in TOPICS:
        raise NCBIError("ncbi_topic_denied")
    if type(payload) is not bytes or len(payload) > MAX_BODY:
        raise NCBIError("ncbi_esearch_response_invalid")
    try:
        root = json.loads(payload, object_pairs_hook=_unique_json_object)
    except NCBIError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise NCBIError("ncbi_esearch_response_invalid") from exc
    if not isinstance(root, dict) or not isinstance(root.get("esearchresult"), dict):
        raise NCBIError("ncbi_esearch_schema_invalid")
    result = root["esearchresult"]
    for section in (root, result):
        if any(type(key) is str and key.lower() in (
            "error", "errors", "warninglist", "errorlist"
        ) for key in section):
            raise NCBIError("ncbi_esearch_api_error")
    total = _number(result.get("count"))
    maximum = _number(result.get("retmax"))
    offset = _number(result.get("retstart"))
    ids = result.get("idlist")
    if (maximum != MAX_IDS or offset != 0 or not isinstance(ids, list)
            or len(ids) > MAX_IDS or len(ids) > total):
        raise NCBIError("ncbi_esearch_result_mismatch")
    seen: set[str] = set()
    for pmid in ids:
        try:
            validate_pmid(pmid)
        except ValueError as exc:
            raise NCBIError("ncbi_esearch_pmid_invalid") from exc
        if pmid in seen:
            raise NCBIError("ncbi_esearch_duplicate_pmid")
        seen.add(pmid)
    return {
        "status": "UNVERIFIED_PMID_CANDIDATES" if ids else "NO_DATA",
        "topic": topic, "window": "30_days_entrez_entry",
        "reported_total": total, "pmids": ids, "source_api": "NCBI_ESEARCH",
    }


def find_candidates(
    topic: str, *, contact: str,
    fetch: Callable[[str, str], bytes] = _fetch,
) -> dict[str, Any]:
    if type(topic) is not str or topic not in TOPICS:
        raise NCBIError("ncbi_topic_denied")
    _contact(contact)
    return parse_candidates(fetch(topic, contact), topic)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--topic", required=True, choices=sorted(TOPICS))
    arguments = parser.parse_args()
    try:
        result = find_candidates(
            arguments.topic, contact=os.environ.get("HERMES_NCBI_CONTACT_EMAIL", "")
        )
    except NCBIError as exc:
        result = {"status": "UNKNOWN", "reason": str(exc)}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] in ("UNVERIFIED_PMID_CANDIDATES", "NO_DATA") else 1


if __name__ == "__main__":
    raise SystemExit(main())
