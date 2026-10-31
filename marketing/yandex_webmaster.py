"""H-24 #397: bounded, offline-only Yandex Webmaster v4 GET/evidence contract.

Official response shapes are untrusted owner exports until an independently
authenticated read exists. There are no HTTP calls, credentials, file writes,
Wordstat, Metrika, GSC or publication actions in this module.
"""
from __future__ import annotations

from datetime import date, datetime
import hashlib
import json
import math
import re
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from marketing.seo_research import normalize_observations, SeoResearchDenied

INPUT_SCHEMA = "hermes-h24-yandex-webmaster-offline-input-v1"
OUTPUT_SCHEMA = "hermes-h24-yandex-webmaster-offline-report-v1"
MAX_QUERY_ROWS = 50
MAX_DAYS = 32
MAX_SITEMAPS = 20
MAX_INPUT_BYTES = 65536
DEVICES = frozenset({"ALL", "DESKTOP", "MOBILE_AND_TABLET", "MOBILE", "TABLET"})
INDICATORS = {
    "TOTAL_SHOWS": "impressions",
    "TOTAL_CLICKS": "clicks",
    "AVG_SHOW_POSITION": "average_position",
    "AVG_CLICK_POSITION": "average_click_position",
}
HTTP_CODES = frozenset({"HTTP_2XX", "HTTP_3XX", "HTTP_4XX", "HTTP_5XX", "OTHER"})
INTENTS = frozenset({"informational", "navigational", "commercial", "transactional"})
HOST = "https:your-fitness-coach.ru:443"
BASE = "https://api.webmaster.yandex.net/v4"


class WebmasterDenied(ValueError):
    """Public fixed error codes; do not echo tokens or source text."""


class WebmasterContractDiagnosticDenied(WebmasterDenied):
    """Safe section and fixed error code, never a source value or query text."""

    def __init__(self, section: str, reason: str) -> None:
        super().__init__(reason)
        self.section = section


# Only repository-owned literal error codes are eligible for a diagnostic
# receipt. Provider/user-controlled strings must never pass through.
CONTRACT_DIAGNOSTIC_CODES = frozenset({
    "date_invalid", "counter_invalid", "position_invalid",
    "series_schema_invalid", "series_size_invalid",
    "series_point_invalid", "series_date_invalid",
    "popular_schema_invalid", "popular_period_invalid",
    "popular_rows_invalid", "popular_row_invalid",
    "metric_inconsistent", "sitemaps_invalid", "sitemap_row_invalid",
    "sitemap_url_invalid", "sitemap_date_invalid",
    "export_schema_invalid", "export_context_invalid",
    "export_period_invalid", "export_hash_invalid",
    "export_size_limit", "seo_packet_denied",
})


def _diagnostic_reason(exc: WebmasterDenied) -> str:
    code = exc.args[0] if len(exc.args) == 1 else None
    return (code if type(code) is str and code in CONTRACT_DIAGNOSTIC_CODES
            else "YANDEX_RESPONSE_CONTRACT_CHANGED")


def _day(value: Any) -> date:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise WebmasterDenied("date_invalid")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise WebmasterDenied("date_invalid") from None


# The API documents popular date_from/date_to as datetime, although
# some official examples show YYYY-MM-DD. Keep owner input dates strict.
_PROVIDER_DATETIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:\d{2}|[+-]\d{4})"
)


def _provider_day(value: Any) -> date:
    if type(value) is not str or len(value) > 40:
        raise WebmasterDenied("popular_period_invalid")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise WebmasterDenied("popular_period_invalid") from None
    if not _PROVIDER_DATETIME.fullmatch(value):
        raise WebmasterDenied("popular_period_invalid")
    try:
        instant = datetime.fromisoformat(
            value.replace(",", ".").replace("Z", "+00:00"),
        )
    except ValueError:
        raise WebmasterDenied("popular_period_invalid") from None
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise WebmasterDenied("popular_period_invalid")
    return instant.date()


def _count(value: Any) -> int:
    # Yandex sometimes serializes counters as JSON double or decimal text.
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        value = int(value)
    if type(value) in (int, float) and 0 <= value <= 2_147_483_647 and math.isfinite(value) and float(value).is_integer():
        return int(value)
    raise WebmasterDenied("counter_invalid")


def _positive(value: Any) -> float:
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 < value <= 1000:
        raise WebmasterDenied("position_invalid")
    return float(value)


def _position_value_class(value: Any) -> str:
    """Fixed, non-reversible category; never return a provider value."""
    if value is None:
        return "NULL"
    if type(value) is bool:
        return "BOOLEAN"
    if type(value) in (int, float):
        if not math.isfinite(value):
            return "NONFINITE"
        if value == 0:
            return "ZERO"
        if value < 0:
            return "NEGATIVE"
        if value > 1000:
            return "ABOVE_LIMIT"
        return "VALID"
    if type(value) is str:
        return ("NUMERIC_STRING" if re.fullmatch(
            r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)", value,
        ) else "STRING")
    return "OTHER_TYPE"


def classify_popular_position_problem(
    source: Any, *, start: date, end: date,
) -> dict[str, str]:
    """Classify one invalid position without returning queries or raw values.

    The existing full parser must first reject specifically a position,
    otherwise we do not infer that its other fields are correct.
    """
    try:
        _popular(source, start=start, end=end)
    except WebmasterDenied as exc:
        if exc.args != ("position_invalid",):
            raise
        for item in source["queries"]:
            indicators = item["indicators"]
            for name in ("AVG_SHOW_POSITION", "AVG_CLICK_POSITION"):
                if name in indicators:
                    category = _position_value_class(indicators[name])
                    if category != "VALID":
                        return {"indicator": name, "value_class": category}
        raise WebmasterDenied("position_invalid") from None
    return {"indicator": "NONE", "value_class": "NO_INVALID_POSITION"}


def _series(container: Any, *, allowed: frozenset[str], as_of: date) -> dict[str, list[dict[str, Any]]]:
    if type(container) is not dict or set(container) != {"indicators"}:
        raise WebmasterDenied("series_schema_invalid")
    data = container["indicators"]
    if type(data) is not dict or set(data) - allowed or len(data) > len(allowed):
        raise WebmasterDenied("series_schema_invalid")
    output: dict[str, list[dict[str, Any]]] = {}
    for indicator, points in data.items():
        if type(points) is not list or len(points) > MAX_DAYS:
            raise WebmasterDenied("series_size_invalid")
        rows, seen = [], set()
        for point in points:
            if type(point) is not dict or set(point) != {"date", "value"}:
                raise WebmasterDenied("series_point_invalid")
            stamp = point["date"]
            if type(stamp) is not str or len(stamp) > 40:
                raise WebmasterDenied("series_point_invalid")
            try:
                instant = datetime.fromisoformat(stamp.replace(",", "."))
            except ValueError:
                raise WebmasterDenied("series_date_invalid") from None
            if instant.tzinfo is None or instant.date() > as_of or instant.date() in seen:
                raise WebmasterDenied("series_date_invalid")
            seen.add(instant.date())
            rows.append({"date": str(instant.date()),
                         "value": _count(point["value"]) if indicator.startswith("HTTP_") or indicator == "OTHER" or indicator in {"TOTAL_SHOWS", "TOTAL_CLICKS"} else _positive(point["value"])})
        output[indicator] = sorted(rows, key=lambda row: row["date"])
    return output


def read_plan(*, user_id: int, host_id: str, start: str, end: str, device: str = "ALL") -> dict[str, Any]:
    """Review-only allowlist. No HTTP client or bearer token in the module."""
    a, b = _day(start), _day(end)
    if (type(user_id) is not int or not 1 <= user_id <= 2**63 - 1 or host_id != HOST
            or type(device) is not str or device not in DEVICES
            or not a <= b or (b - a).days >= MAX_DAYS):
        raise WebmasterDenied("read_plan_invalid")
    h = f"/user/{user_id}/hosts/{quote(host_id, safe='')}"
    window = {"date_from": start, "date_to": end}
    query_fields = ("TOTAL_SHOWS", "TOTAL_CLICKS", "AVG_SHOW_POSITION", "AVG_CLICK_POSITION")
    return {
        "schema": "hermes-h24-yandex-webmaster-get-plan-v1",
        "status": "PLAN_ONLY_NO_REQUESTS", "authorization": "NOT_GRANTED",
        "required_oauth_scope": "webmaster:hostinfo",
        "requests": [
            {"method": "GET", "url": BASE + "/user"},
            {"method": "GET", "url": BASE + f"/user/{user_id}/hosts"},
            {"method": "GET", "url": BASE + h + "/search-queries/popular?" + urlencode({
                **window, "order_by": "TOTAL_SHOWS", "device_type_indicator": device,
                "query_indicator": query_fields, "limit": 50}, doseq=True)},
            {"method": "GET", "url": BASE + h + "/search-queries/all/history?" + urlencode({
                **window, "device_type_indicator": device, "query_indicator": query_fields},
                doseq=True)},
            {"method": "GET", "url": BASE + h + "/indexing/history?" + urlencode(window)},
            {"method": "GET", "url": BASE + h + "/sitemaps?" + urlencode({"limit": 20})},
        ],
        "max_requests": 6, "retries": 0, "network_calls": 0,
        "paid_api_allowed": False, "mutations_allowed": False,
    }


def classify_http_status(code: Any) -> dict[str, Any]:
    """No retries, fallback, credential disclosure or inferred data."""
    if type(code) is not int or not 100 <= code <= 599:
        raise WebmasterDenied("http_status_invalid")
    state = (
        "RESPONSE_REQUIRES_VALIDATION" if code == 200 else
        "AUTH_REQUIRED" if code == 401 else
        "ACCESS_DENIED" if code == 403 else
        "HOST_NOT_VERIFIED_OR_UNAVAILABLE" if code == 404 else
        "RATE_LIMITED" if code == 429 else
        "UPSTREAM_UNAVAILABLE" if code >= 500 else
        "UNSUPPORTED_HTTP_STATUS"
    )
    return {"status": state, "http_status": code, "retries": 0,
            "live_api_verified": False, "fallback_paid": False,
            "network_calls": 0}


def _popular(source: Any, *, start: date, end: date) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if type(source) is not dict or set(source) != {"queries", "date_from", "date_to", "count"}:
        raise WebmasterDenied("popular_schema_invalid")
    a, b = _provider_day(source["date_from"]), _provider_day(source["date_to"])
    if not start <= a <= b <= end:
        raise WebmasterDenied("popular_period_invalid")
    count = _count(source["count"])
    rows = source["queries"]
    if type(rows) is not list or len(rows) > MAX_QUERY_ROWS or count < len(rows):
        raise WebmasterDenied("popular_rows_invalid")
    out, seen = [], set()
    for item in rows:
        if type(item) is not dict or set(item) != {"query_id", "query_text", "indicators"}:
            raise WebmasterDenied("popular_row_invalid")
        qid, query, metrics = item["query_id"], item["query_text"], item["indicators"]
        if (type(qid) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", qid)
                or type(query) is not str or not 1 <= len(query) <= 120
                or type(metrics) is not dict or set(metrics) - INDICATORS.keys()
                or not metrics or qid in seen):
            raise WebmasterDenied("popular_row_invalid")
        seen.add(qid)
        parsed: dict[str, int | float] = {}
        for key, value in metrics.items():
            if key in {"TOTAL_SHOWS", "TOTAL_CLICKS"}:
                parsed[INDICATORS[key]] = _count(value)
            else:
                parsed[INDICATORS[key]] = _positive(value)
        if "impressions" in parsed and "clicks" in parsed:
            if parsed["clicks"] > parsed["impressions"]:
                raise WebmasterDenied("metric_inconsistent")
            if parsed["impressions"] > 0:
                parsed["ctr"] = parsed["clicks"] / parsed["impressions"]
        out.append({"query": query, "metrics": parsed})
    return out, {"period_start": str(a), "period_end": str(b),
                 "available_query_count": count, "returned_rows": len(rows),
                 "truncated": count > len(rows)}


def _sitemaps(source: Any, *, as_of: date) -> list[dict[str, Any]]:
    if type(source) is not dict or set(source) != {"sitemaps"} or type(source["sitemaps"]) is not list or len(source["sitemaps"]) > MAX_SITEMAPS:
        raise WebmasterDenied("sitemaps_invalid")
    result, seen = [], set()
    for row in source["sitemaps"]:
        required = {"sitemap_id", "sitemap_url", "errors_count",
                    "urls_count", "children_count", "sources", "sitemap_type"}
        # Official Webmaster v4 schema marks last_access_date optional.
        # Missing or explicit null remains unknown, never an invented date.
        allowed = required | {"last_access_date"}
        if (type(row) is not dict or not required.issubset(row)
                or not set(row).issubset(allowed)):
            raise WebmasterDenied("sitemap_row_invalid")
        uri = row["sitemap_url"]
        if type(uri) is not str or len(uri) > 300:
            raise WebmasterDenied("sitemap_row_invalid")
        try:
            address = urlsplit(uri)
            if (address.scheme != "https" or address.hostname != "your-fitness-coach.ru"
                    or address.username is not None or address.password is not None
                    or address.port not in (None, 443) or address.query or address.fragment):
                raise WebmasterDenied("sitemap_url_invalid")
        except ValueError:
            raise WebmasterDenied("sitemap_url_invalid") from None
        accessed = row.get("last_access_date")
        if accessed is not None:
            if type(accessed) is not str or len(accessed) > 40:
                raise WebmasterDenied("sitemap_date_invalid")
            try:
                stamp = datetime.fromisoformat(accessed.replace(",", "."))
            except ValueError:
                raise WebmasterDenied("sitemap_date_invalid") from None
            if stamp.tzinfo is None or stamp.date() > as_of:
                raise WebmasterDenied("sitemap_date_invalid")
        sid = row["sitemap_id"]
        if type(sid) is not str or not re.fullmatch(r"[A-Za-z0-9:_-]{1,80}", sid) or sid in seen:
            raise WebmasterDenied("sitemap_row_invalid")
        seen.add(sid)
        if (type(row["sources"]) is not list or len(row["sources"]) > 6
                or any(type(v) is not str or v not in {"ROBOTS_TXT", "WEBMASTER", "INDEX_SITEMAP"} for v in row["sources"])
                or type(row["sitemap_type"]) is not str or row["sitemap_type"] not in {"SITEMAP", "INDEX_SITEMAP"}):
            raise WebmasterDenied("sitemap_row_invalid")
        result.append({"sitemap_id": sid, "url": uri,
                       "last_access_date": str(stamp.date()) if accessed is not None else None,
                       "errors": _count(row["errors_count"]),
                       "urls": _count(row["urls_count"]),
                       "children": _count(row["children_count"]),
                       "sitemap_type": row["sitemap_type"]})
    return result


def normalize_export(
    payload: Any, *, as_of: date, diagnostic: bool = False,
) -> dict[str, Any]:
    """Convert supplied official-shape JSON to separate SEO + technical evidence.

    Diagnostics are opt-in and identify only a fixed section/error code.
    """
    def checked(section: str, action: Any) -> Any:
        try:
            return action()
        except WebmasterDenied as exc:
            if diagnostic:
                raise WebmasterContractDiagnosticDenied(
                    section, _diagnostic_reason(exc),
                ) from None
            raise

    if type(payload) is not dict or set(payload) != {
        "schema", "source_type", "owner_attested", "host_id", "observed_at",
        "period_start", "period_end", "device", "search_intent",
        "popular", "all_history", "index_history", "sitemaps",
    } or payload["schema"] != INPUT_SCHEMA or payload["host_id"] != HOST:
        raise WebmasterDenied("export_schema_invalid")
    kind = payload["source_type"]
    attested = payload["owner_attested"]
    if (kind not in ("owner_export", "synthetic_fixture")
            or type(kind) is not str or type(attested) is not bool
            or (kind == "synthetic_fixture" and attested)
            or type(payload["device"]) is not str or payload["device"] not in DEVICES
            or type(payload["search_intent"]) is not str
            or payload["search_intent"] not in INTENTS or type(as_of) is not date):
        raise WebmasterDenied("export_context_invalid")
    observed, start, end = (_day(payload[key]) for key in ("observed_at", "period_start", "period_end"))
    if not start <= end <= observed <= as_of or (end - start).days >= MAX_DAYS:
        raise WebmasterDenied("export_period_invalid")
    source = payload["popular"]
    parsed, coverage = checked(
        "POPULAR_DATA", lambda: _popular(source, start=start, end=end),
    ) if source is not None else ([], None)
    observations = []
    for item in parsed:
        metrics = {key: val for key, val in item["metrics"].items()
                   if key in {"impressions", "clicks", "ctr", "average_position"}}
        if not metrics or ("clicks" in metrics and "impressions" not in metrics):
            continue  # Never treat missing impressions as zero in existing #64.
        row = {"source": "yandex_webmaster", "source_type": kind,
               "observed_at": str(observed),
               "period_start": coverage["period_start"],
               "period_end": coverage["period_end"],
               "query": item["query"], "search_intent": payload["search_intent"],
               "limitations": "Yandex Webmaster popular query export, capped 50 rows; not full site demand, no page/region dimension",
               **metrics}
        if kind == "owner_export":
            row["owner_attested"] = attested
        observations.append(row)
    general = (checked(
        "ALL_HISTORY_DATA",
        lambda: _series(
            payload["all_history"], allowed=frozenset(INDICATORS), as_of=as_of,
        ),
    ) if payload["all_history"] is not None else None)
    indexing = (checked(
        "INDEXING_DATA",
        lambda: _series(payload["index_history"], allowed=HTTP_CODES, as_of=as_of),
    ) if payload["index_history"] is not None else None)
    sitemaps = (checked(
        "SITEMAPS_DATA",
        lambda: _sitemaps(payload["sitemaps"], as_of=as_of),
    ) if payload["sitemaps"] is not None else None)
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise WebmasterDenied("export_hash_invalid") from None
    if len(encoded) > MAX_INPUT_BYTES:
        raise WebmasterDenied("export_size_limit")
    digest = hashlib.sha256(encoded).hexdigest()
    for row in observations:
        if kind == "owner_export":
            row["evidence_sha256"] = digest
    try:
        normalized = normalize_observations(observations, as_of=as_of)
    except SeoResearchDenied:
        if diagnostic:
            raise WebmasterContractDiagnosticDenied(
                "SEO_PACKET", "seo_packet_denied",
            ) from None
        raise WebmasterDenied("seo_packet_denied") from None
    return {
        "schema": OUTPUT_SCHEMA, "status": "OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED",
        "source": "yandex_webmaster", "source_type": kind,
        "owner_attested": attested, "evidence_sha256": digest,
        "observed_at": str(observed), "requested_period": [str(start), str(end)],
        "device": payload["device"], "popular_coverage": coverage,
        "seo_research_input_observations": observations,
        "seo_research_observations": normalized,
        "site_history": general, "indexing_http_status_history": indexing,
        "sitemaps": sitemaps, "page_metrics_available": False,
        "region_metrics_available": False, "indexing_is_search_visibility": False,
        "search_metrics_combined": False, "publication_allowed": False,
        "live_api_used": False, "network_calls": 0, "paid_api_used": False,
        "authorization_verified": False, "mutations_allowed": False,
    }
