"""Import the exact owner-provided 2026 YFC Wordstat semantic CSV, offline only.

YFC repeats the SAME Wordstat volume for Google and Yandex SERP rows.
Deduplicate the original Yandex source instead of counting them twice.
No provider calls, credential access, generated metrics, or YFC writes.
"""
from __future__ import annotations

import csv
import hashlib
import io
from datetime import date
from typing import Any

from marketing.seo_research import SeoResearchDenied, normalize_observations

SCHEMA = "hermes-h12-yfc-wordstat-import-v1"
SOURCE_PATH = "docs/seo/semantic-core-ru-cis.csv"
SOURCE_REPOSITORY = "MikeMoore1337/your-fitness-coach"
SOURCE_BLOB_SHA1 = "da88488e780b187afcfc5f70cb001ef4f4eb3a72"
SOURCE_OBSERVED_AT = "2026-09-16"
SOURCE_PERIOD = "2026-08-15..2026-09-15"
MAX_CSV_BYTES = 64 * 1024
MAX_ROWS = 100
FIELDS = frozenset({
    "keyword", "country", "region", "language", "search_engine", "intent",
    "demand_source", "demand_status", "wordstat_period", "wordstat_geography",
    "wordstat_device_scope", "wordstat_operator", "demand_broad_frequency",
    "demand_quoted_frequency",
})
INTENT_MAP = {
    "tool/calculator": "transactional",
    "program/template": "informational",
    "informational": "informational",
    "commercial investigation": "commercial",
    "transactional/product": "transactional",
}
VALID_STATUSES = frozenset({
    "observed_broad_and_quoted", "observed_broad_only", "no_export_available",
})


def _count(raw: str) -> int | None:
    if raw == "NO_DATA":
        return None
    if not raw.isascii() or not raw.isdigit() or len(raw) > 12:
        raise SeoResearchDenied("wordstat_frequency_invalid")
    return int(raw)


def import_yfc_wordstat(content: bytes, *, selected_query: str, as_of: str) -> dict[str, Any]:
    """Admit only a pinned YFC Git blob and return typed H-12 input observations."""
    if type(content) is not bytes or not 0 < len(content) <= MAX_CSV_BYTES:
        raise SeoResearchDenied("wordstat_csv_size_invalid")
    blob = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
    if blob != SOURCE_BLOB_SHA1:
        raise SeoResearchDenied("wordstat_source_snapshot_mismatch")
    try:
        day = date.fromisoformat(as_of)
        if day < date.fromisoformat(SOURCE_OBSERVED_AT):
            raise ValueError
        decoded = content.decode("utf-8")
    except (ValueError, UnicodeDecodeError, TypeError):
        raise SeoResearchDenied("wordstat_as_of_invalid") from None
    if (type(selected_query) is not str or not 1 <= len(selected_query) <= 120
            or any(ord(c) < 32 or c in "<>{}|" or c == chr(96) for c in selected_query)):
        raise SeoResearchDenied("wordstat_query_invalid")
    try:
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        if reader.fieldnames is None or not FIELDS.issubset(reader.fieldnames):
            raise SeoResearchDenied("wordstat_header_invalid")
        rows = list(reader)
    except csv.Error:
        raise SeoResearchDenied("wordstat_csv_invalid") from None
    if len(rows) > MAX_ROWS or any(None in row for row in rows):
        raise SeoResearchDenied("wordstat_row_invalid")
    digest = hashlib.sha256(content).hexdigest()
    unique: dict[str, tuple[int | None, int | None, str]] = {}
    for row in rows:
        if (row["demand_source"] != "Yandex Wordstat"
                or row["search_engine"] not in {"Google", "Yandex"}
                or row["country"] != "RU" or row["region"] != "RU"
                or row["language"] != "ru"
                or row["wordstat_geography"] != "Russia"
                or row["wordstat_device_scope"] != "all"
                or row["wordstat_period"] != SOURCE_PERIOD
                or row["wordstat_operator"] != "broad + quoted/fixed-word-count"
                or row["intent"] not in INTENT_MAP
                or row["demand_status"] not in VALID_STATUSES):
            raise SeoResearchDenied("wordstat_row_context_invalid")
        broad = _count(row["demand_broad_frequency"])
        quoted = _count(row["demand_quoted_frequency"])
        if ((row["demand_status"] == "observed_broad_and_quoted"
             and (broad is None or quoted is None))
            or (row["demand_status"] == "observed_broad_only"
                and (broad is None or quoted is not None))
            or (row["demand_status"] == "no_export_available"
                and (broad is not None or quoted is not None))):
            raise SeoResearchDenied("wordstat_status_conflict")
        keyword = row["keyword"]
        if keyword.casefold() != selected_query.casefold():
            continue
        entry = (broad, quoted, INTENT_MAP[row["intent"]])
        prev = unique.get(keyword.casefold())
        if prev is not None and prev != entry:
            raise SeoResearchDenied("wordstat_engine_duplicate_conflict")
        unique[keyword.casefold()] = entry

    observations: list[dict[str, Any]] = []
    for keyword, (broad, quoted, intent) in unique.items():
        for operator, value in (("broad", broad), ("quoted_fixed_word_count", quoted)):
            if value is None:
                continue
            observations.append({
                "source": "yandex_wordstat", "source_type": "owner_export",
                "observed_at": SOURCE_OBSERVED_AT,
                "period_start": "2026-08-15", "period_end": "2026-09-15",
                "query": keyword, "search_intent": intent,
                "country": "RU", "language": "ru",
                "wordstat_region": "Russia", "wordstat_device": "all",
                "wordstat_operator": operator, "search_volume": value,
                "limitations": ("Historical owner Wordstat Regions export; "
                                "not Google demand, ranking or live API verification"),
                "evidence_sha256": digest, "owner_attested": True,
            })
    normalize_observations(observations, as_of=day)
    return {
        "schema": SCHEMA, "selected_query": selected_query,
        "source_repo": SOURCE_REPOSITORY, "source_path": SOURCE_PATH,
        "source_git_blob_sha1": blob, "evidence_sha256": digest,
        "period_start": "2026-08-15", "period_end": "2026-09-15",
        "as_of": str(day), "observations": observations,
        "source_quality": "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED",
        "publication_allowed": False, "yfc_write_allowed": False,
        "live_api_used": False, "paid_api_used": False,
    }
