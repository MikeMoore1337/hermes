"""H-24/#191: bounded, transport-neutral GSC evidence normalization (offline).

The caller supplies an already-authorized snapshot. There is deliberately no
OAuth, network, persistence, schedule, or publisher in this module.
A content digest is NOT a cryptographic attestation from Google or Windsor.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date
from typing import Any
from urllib.parse import urlsplit

SCHEMA = "hermes-h24-gsc-evidence-v1"
PROPERTY = "sc-domain:your-fitness-coach.ru"
TRANSPORTS = frozenset({"windsor_ai", "owner_export", "google_api"})
DIMENSIONS = frozenset({"date", "page", "query", "country", "device"})
SEARCH_TYPES = frozenset({"web", "image", "video", "news", "discover", "googleNews"})
MAX_ROWS = 1000
MAX_DAYS = 370
MAX_BYTES = 256 * 1024
METRICS = ("clicks", "impressions", "ctr", "position")
SAFE_TEXT = re.compile(r"^[^<>\x00-\x1f\x7f]{1,300}$")
COUNTRY = re.compile(r"^[A-Za-z][A-Za-z -]{1,79}$")


class GscEvidenceError(ValueError):
    """Stable error codes only. Never include a provider row or secret."""


def _day(raw: object) -> date:
    if type(raw) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        raise GscEvidenceError("date_invalid")
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise GscEvidenceError("date_invalid") from None


def _text(raw: object, limit: int = 300) -> str:
    if type(raw) is not str or len(raw) > limit or not SAFE_TEXT.fullmatch(raw):
        raise GscEvidenceError("text_invalid")
    return raw


def _page(raw: object) -> str:
    value = _text(raw)
    try:
        p = urlsplit(value)
        if (p.scheme != "https" or p.hostname != "your-fitness-coach.ru"
                or p.username is not None or p.password is not None
                or p.port not in (None, 443) or p.fragment):
            raise GscEvidenceError("page_invalid")
    except ValueError:
        raise GscEvidenceError("page_invalid") from None
    return value


def _count(raw: object) -> int:
    if type(raw) is not int or raw < 0:
        raise GscEvidenceError("metric_invalid")
    return raw


def _positive_float(raw: object, *, allow_zero: bool = True) -> float:
    if type(raw) not in (int, float) or not math.isfinite(raw):
        raise GscEvidenceError("metric_invalid")
    if raw < 0 or (not allow_zero and raw == 0):
        raise GscEvidenceError("metric_invalid")
    return float(raw)


def _snapshot_header(raw: object) -> tuple[dict[str, Any], date, date, date]:
    if type(raw) is not dict or set(raw) != {
        "property", "transport", "period_start", "period_end", "observed_at",
        "data_latest_date", "search_type", "dimensions", "ctr_unit", "rows"
    }:
        raise GscEvidenceError("snapshot_schema_invalid")
    if raw["property"] != PROPERTY:
        raise GscEvidenceError("property_mismatch")
    if raw["transport"] not in TRANSPORTS:
        raise GscEvidenceError("transport_invalid")
    start, end, observed = (_day(raw[k]) for k in
                             ("period_start", "period_end", "observed_at"))
    if not start <= end <= observed or (end - start).days > MAX_DAYS:
        raise GscEvidenceError("period_invalid")
    latest_raw = raw["data_latest_date"]
    latest = _day(latest_raw) if latest_raw is not None else None
    if latest is not None and (latest > observed or latest > end):
        raise GscEvidenceError("latest_date_invalid")
    if raw["search_type"] not in SEARCH_TYPES:
        raise GscEvidenceError("search_type_invalid")
    dims = raw["dimensions"]
    if (type(dims) is not list or len(dims) > 3
            or any(type(v) is not str or v not in DIMENSIONS for v in dims)
            or len(dims) != len(set(dims))):
        raise GscEvidenceError("dimensions_invalid")
    if raw["ctr_unit"] not in {"fraction", "percent"}:
        raise GscEvidenceError("ctr_unit_required")
    rows = raw["rows"]
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise GscEvidenceError("rows_invalid")
    try:
        source_bytes = json.dumps(raw, sort_keys=True, ensure_ascii=False,
                                  allow_nan=False, separators=(",", ":")).encode()
    except (TypeError, ValueError, OverflowError):
        raise GscEvidenceError("snapshot_invalid") from None
    if len(source_bytes) > MAX_BYTES:
        raise GscEvidenceError("snapshot_too_large")
    digest = hashlib.sha256(source_bytes).hexdigest()
    header = {
        "schema_version": SCHEMA,
        "search_engine": "google",
        "source": "google_search_console",
        "provider": raw["transport"],
        "source_kind": "operator_supplied_snapshot",
        "property": PROPERTY,
        "observed_at": str(observed),
        "period_start": str(start),
        "period_end": str(end),
        "data_latest_date": str(latest) if latest else None,
        "search_type": raw["search_type"],
        "dimensions": list(dims),
        "evidence_sha256": digest,
        "provider_attested": False,
        "hermes_runtime_source_verified": False,
        "live_api_used_by_hermes": False,
        "publication_allowed": False,
        "yfc_write_allowed": False,
    }
    return header, start, end, observed


def normalize_analytics(snapshot: object) -> dict[str, Any]:
    """Normalize one *single-dimension-context* GSC report; never sum reports.

    Null metrics are absent, not zeros. CTR units must be declared explicitly.
    Query rows are never assumed complete. Missing dates are not zero days.
    """
    result, start, end, observed = _snapshot_header(snapshot)
    dims = result["dimensions"]
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for raw in snapshot["rows"]:
        if type(raw) is not dict or set(raw) - set(dims) - set(METRICS):
            raise GscEvidenceError("row_fields_invalid")
        if any(d not in raw or raw[d] is None for d in dims):
            raise GscEvidenceError("dimension_missing")
        row: dict[str, Any] = {}
        for d in dims:
            value = raw[d]
            if d == "date":
                day = _day(value)
                if not start <= day <= end:
                    raise GscEvidenceError("row_date_invalid")
                row[d] = str(day)
            elif d == "page":
                row[d] = _page(value)
            elif d == "query":
                row[d] = _text(value, 120)
            elif d == "device":
                if value not in ("DESKTOP", "MOBILE", "TABLET"):
                    raise GscEvidenceError("device_invalid")
                row[d] = value
            else:
                if (type(value) is not str or not COUNTRY.fullmatch(value)):
                    raise GscEvidenceError("country_invalid")
                row[d] = value
        key = tuple(row[d] for d in dims)
        if key in seen:
            raise GscEvidenceError("duplicate_row")
        seen.add(key)
        metrics: dict[str, int | float] = {}
        for field in ("clicks", "impressions"):
            if field in raw and raw[field] is not None:
                metrics[field] = _count(raw[field])
        if ("clicks" in metrics and "impressions" in metrics
                and metrics["clicks"] > metrics["impressions"]):
            raise GscEvidenceError("metric_inconsistent")
        if "ctr" in raw and raw["ctr"] is not None:
            ctr = _positive_float(raw["ctr"])
            if snapshot["ctr_unit"] == "percent":
                if ctr > 100:
                    raise GscEvidenceError("metric_invalid")
                ctr /= 100
            elif ctr > 1:
                raise GscEvidenceError("metric_invalid")
            metrics["ctr"] = ctr
        if ("ctr" in metrics and "clicks" in metrics and "impressions" in metrics
                and metrics["impressions"] > 0 and
                abs(metrics["ctr"] - metrics["clicks"] / metrics["impressions"]) > 0.01):
            raise GscEvidenceError("metric_inconsistent")
        if "position" in raw and raw["position"] is not None:
            position = _positive_float(raw["position"])
            # Windsor sometimes returns position=0 on zero-impression dates.
            # This is missing position, never a ranking of zero.
            if position == 0:
                if metrics.get("impressions", 0) != 0:
                    raise GscEvidenceError("metric_invalid")
            else:
                if metrics.get("impressions") == 0:
                    raise GscEvidenceError("metric_inconsistent")
                metrics["average_position"] = position
        if not metrics:
            raise GscEvidenceError("metric_missing")
        row["metrics"] = metrics
        row["quality_status"] = ("NO_IMPRESSIONS" if metrics.get("impressions") == 0
                                 else "PARTIAL_METRICS" if
                                 {"clicks", "impressions"} - metrics.keys()
                                 else "OBSERVED")
        rows.append(row)
    if not dims and len(rows) > 1:
        raise GscEvidenceError("site_aggregate_ambiguous")
    latest_raw = result["data_latest_date"]
    latest = _day(latest_raw) if latest_raw else None
    status = ("NO_DATA" if not rows else
              "LATEST_DATE_UNKNOWN" if latest is None else
              "STALE" if (observed - latest).days > 10 else
              "PARTIAL" if latest < end else "AVAILABLE")
    result.update({
        "kind": "search_analytics",
        "rows": rows,
        "quality_status": status,
        "completeness": ("QUERY_ROWS_NOT_EXHAUSTIVE" if "query" in dims else
                         "PAGE_AGGREGATED_NOT_SITE_TOTAL" if "page" in dims else
                         "DIMENSION_SPECIFIC" if dims else "PROPERTY_AGGREGATE"),
        "limitations": [
            "Google Search Console: Pacific Time date boundaries; recent dates may be preliminary",
            "Search Analytics may omit anonymized low-frequency queries and low-ranked rows",
            "Metrics from different dimensions must not be summed or treated as equal site totals",
            "Snapshot digest identifies bytes, not Google authentication or Hermes runtime access",
        ],
    })
    return result


def normalize_sitemaps(snapshot: object) -> dict[str, Any]:
    """Keep sitemap diagnostics; never infer index coverage from 'indexed'."""
    result, _start, _end, _observed = _snapshot_header(snapshot)
    if result["dimensions"] != ["sitemap"]:
        # Sitemaps are a separate report, not Search Analytics dimensions.
        raise GscEvidenceError("sitemap_dimensions_invalid")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in snapshot["rows"]:
        if type(raw) is not dict or set(raw) - {
            "path", "submitted", "errors", "warnings", "last_downloaded",
            "last_submitted", "indexed"
        }:
            raise GscEvidenceError("sitemap_row_invalid")
        if raw.get("path") is None:
            # Windsor.ai returns a null-path aggregation placeholder.
            if any(raw.get(k) not in (None, 0) for k in ("submitted", "errors", "warnings")):
                raise GscEvidenceError("sitemap_placeholder_invalid")
            continue
        path = _page(raw["path"])
        if path in seen:
            raise GscEvidenceError("duplicate_row")
        seen.add(path)
        row: dict[str, Any] = {"sitemap_url": path}
        for k in ("submitted", "errors", "warnings"):
            if raw.get(k) is not None:
                row[{"submitted": "submitted_url_count"}.get(k, k)] = _count(raw[k])
        for k in ("last_downloaded", "last_submitted"):
            if raw.get(k) is not None:
                val = _text(raw[k], 40)
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", val):
                    raise GscEvidenceError("sitemap_timestamp_invalid")
                row[k] = val
        out.append(row)
    result.update({
        "kind": "sitemaps",
        "rows": out,
        "quality_status": "AVAILABLE" if out else "NO_DATA",
        "completeness": "SITEMAP_DIAGNOSTICS_ONLY",
        "limitations": [
            "Sitemaps API contents[].indexed is deprecated and deliberately ignored",
            "Successful sitemap download does not prove discovery, crawl or indexing",
            "URL Inspection is a separate API and is not supplied by Windsor.ai here",
        ],
    })
    return result


def to_h12_observations(report: dict[str, Any], *,
                        query: str, intent: str, as_of: str) -> list[dict[str, Any]]:
    """Fail-closed bridge to #64. Never mark a connector snapshot owner-attested.

    H-12 requires a selected query and search intent supplied by an editor;
    a site/page/country aggregate is NOT a search-query observation.
    """
    from marketing.seo_research import normalize_observations

    if report.get("schema_version") != SCHEMA or report.get("kind") != "search_analytics":
        raise GscEvidenceError("normalized_report_required")
    if ("query" not in report.get("dimensions", [])
            or report.get("provider_attested") is not False
            or report.get("source") != "google_search_console"
            or report.get("property") != PROPERTY):
        raise GscEvidenceError("report_not_admitted")
    query = _text(query, 120)
    rows = [r for r in report["rows"] if r.get("query", "").casefold() == query.casefold()]
    if len(rows) > 50:
        raise GscEvidenceError("handoff_too_many_rows")
    evidence: list[dict[str, Any]] = []
    for row in rows:
        obj: dict[str, Any] = {
            "source": "google_search_console", "source_type": "owner_export",
            "observed_at": report["observed_at"],
            "period_start": report["period_start"],
            "period_end": report["period_end"],
            "query": row["query"], "search_intent": intent,
            "evidence_sha256": report["evidence_sha256"],
            "owner_attested": False,
            "limitations": ("Operator-supplied " + report["provider"] +
                            " GSC snapshot; API provenance not independently verified by Hermes"),
        }
        if "page" in row:
            obj["page"] = row["page"]
        for k in ("clicks", "impressions", "ctr", "average_position"):
            if k in row["metrics"]:
                obj[k] = row["metrics"][k]
        if any(k in obj for k in ("clicks", "impressions", "ctr", "average_position")):
            evidence.append(obj)
    return normalize_observations(evidence, as_of=_day(as_of))
