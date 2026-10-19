"""Autonomous GSC read-only collector for H-24/#191.

Exactly six Search Analytics queries plus one Sitemaps list request per run.
Nothing is scheduled or authorized by importing this module. Credentials are
loaded only in live_run(), from an operator-provisioned private JSON file.
"""
from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from zoneinfo import ZoneInfo

from marketing.gsc_analytics import (
    GscEvidenceError, PROPERTY, normalize_analytics, normalize_sitemaps,
)

SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
API_ORIGIN = "https://www.googleapis.com"
SITE_PATH = quote(PROPERTY, safe="")
BASE_URL = API_ORIGIN + "/webmasters/v3/sites/" + SITE_PATH
DIMENSION_REPORTS = ((), ("date",), ("page",), ("query",), ("country",), ("device",))
PER_REPORT_ROWS = 250
MAX_RESPONSE_BYTES = 384 * 1024
API_TIMEOUT = 8
REPORT_WINDOW_DAYS = 28


class GscRuntimeError(RuntimeError):
    """No URLs, response payloads or credentials in exception text."""


def request_plan(*, as_of: date) -> tuple[str, str, list[tuple[str, str, dict[str, Any] | None]]]:
    """Use Search Console's America/Los_Angeles report-date timezone.

    Query final data through yesterday; Google can omit recent days even then.
    Every response is explicitly tagged with the requested date window.
    """
    if type(as_of) is not date:
        raise GscRuntimeError("date_invalid")
    end = as_of - timedelta(days=1)
    start = end - timedelta(days=REPORT_WINDOW_DAYS - 1)
    calls = []
    for dims in DIMENSION_REPORTS:
        body = {
            "startDate": start.isoformat(), "endDate": end.isoformat(),
            "dimensions": list(dims), "type": "web", "dataState": "final",
            "rowLimit": PER_REPORT_ROWS, "startRow": 0,
        }
        calls.append(("POST", BASE_URL + "/searchAnalytics/query", body))
    calls.append(("GET", BASE_URL + "/sitemaps", None))
    return start.isoformat(), end.isoformat(), calls


def _google_rows(payload: object, dims: tuple[str, ...]) -> list[dict[str, Any]]:
    if type(payload) is not dict or type(payload.get("rows", [])) is not list:
        raise GscRuntimeError("analytics_response_invalid")
    rows = payload.get("rows", [])
    if len(rows) > PER_REPORT_ROWS:
        raise GscRuntimeError("rows_exceeded")
    result = []
    for item in rows:
        if type(item) is not dict or set(item) - {"keys", "clicks", "impressions", "ctr", "position"}:
            raise GscRuntimeError("analytics_row_invalid")
        keys = item.get("keys", [])
        if type(keys) is not list or len(keys) != len(dims):
            raise GscRuntimeError("dimension_values_invalid")
        row = dict(zip(dims, keys))
        for k in ("clicks", "impressions", "ctr", "position"):
            if k in item:
                value = item[k]
                if k in ("clicks", "impressions"):
                    # Google's Search Analytics schema calls these doubles.
                    # Preserve exact counts when the wire format is 4.0.
                    if (type(value) is float and math.isfinite(value)
                            and value >= 0 and value.is_integer()
                            and value <= 2 ** 53):
                        value = int(value)
                    elif type(value) is not int or value < 0 or value > 2 ** 53:
                        raise GscRuntimeError("analytics_count_invalid")
                row[k] = value
        result.append(row)
    return result


def _gsc_long(value: object) -> int:
    """Google JSON int64 fields can be encoded as decimal strings."""
    if type(value) is int and 0 <= value <= 2 ** 63 - 1:
        return value
    if (type(value) is str and re.fullmatch(r"(?:0|[1-9][0-9]{0,18})", value)
            and int(value) <= 2 ** 63 - 1):
        return int(value)
    raise GscRuntimeError("sitemap_count_invalid")


def _gsc_timestamp(value: object) -> str:
    """Canonicalize RFC3339 datetimes (including explicit UTC offsets) to UTC Z."""
    if (type(value) is not str or len(value) > 48 or
            not re.fullmatch(
                r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}"
                r"(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})", value)):
        raise GscRuntimeError("sitemap_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timezone missing")
        utc = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except ValueError:
        raise GscRuntimeError("sitemap_timestamp_invalid") from None
    return utc.replace("+00:00", "Z")


def _sitemap_rows(payload: object) -> list[dict[str, Any]]:
    if type(payload) is not dict or type(payload.get("sitemap", [])) is not list:
        raise GscRuntimeError("sitemap_response_invalid")
    items = payload.get("sitemap", [])
    if len(items) > 50:
        raise GscRuntimeError("sitemap_rows_exceeded")
    results = []
    for item in items:
        if type(item) is not dict:
            raise GscRuntimeError("sitemap_row_invalid")
        contents = item.get("contents", [])
        if type(contents) is not list or len(contents) > 10:
            raise GscRuntimeError("sitemap_contents_invalid")
        submitted = 0
        for c in contents:
            if type(c) is not dict:
                raise GscRuntimeError("sitemap_contents_invalid")
            try:
                submitted += _gsc_long(c.get("submitted"))
            except GscRuntimeError:
                raise GscRuntimeError("sitemap_submitted_invalid") from None
            if submitted > 2 ** 63 - 1:
                raise GscRuntimeError("sitemap_submitted_invalid")
        row = {"path": item.get("path")}
        if contents:
            row["submitted"] = submitted
        for native, normalized in (("errors", "errors"), ("warnings", "warnings"),
                                   ("lastSubmitted", "last_submitted"),
                                   ("lastDownloaded", "last_downloaded")):
            if native in item:
                if native in ("errors", "warnings"):
                    row[normalized] = _gsc_long(item[native])
                else:
                    row[normalized] = _gsc_timestamp(item[native])
        # 'contents[].indexed' is deprecated and never copied to evidence.
        results.append(row)
    return results


def collect(fetch: Callable[[str, str, dict[str, Any] | None], object],
            *, as_of: date) -> dict[str, Any]:
    """Transport-neutral 7-call collector, deterministic and safe for offline tests.

    Supplied fetch is NOT a provenance claim: all normalized reports remain
    unverified until live_run actually authenticates and executes the calls.
    """
    start, end, calls = request_plan(as_of=as_of)
    day = as_of.isoformat()
    raw = []
    for method, url, body in calls:
        try:
            response = fetch(method, url, body)
        except GscRuntimeError:
            raise
        except Exception:
            raise GscRuntimeError("provider_unavailable") from None
        raw.append(response)
    if len(raw) != len(DIMENSION_REPORTS) + 1:
        raise GscRuntimeError("request_count_invalid")
    dates = _google_rows(raw[1], ("date",))
    available_dates = [x["date"] for x in dates]
    latest = max(available_dates, default=None)
    reports = {}
    for i, dims in enumerate(DIMENSION_REPORTS):
        snap = {
            "property": PROPERTY, "transport": "google_api",
            "period_start": start, "period_end": end, "observed_at": day,
            "data_latest_date": latest, "search_type": "web",
            "dimensions": list(dims), "ctr_unit": "fraction",
            "rows": _google_rows(raw[i], dims),
        }
        name = "site" if not dims else dims[0]
        try:
            reports[name] = normalize_analytics(snap)
        except GscEvidenceError:
            raise GscRuntimeError("normalization_invalid") from None
        reports[name]["limitations"].append(
            "data_latest_date is the last observed date row, not proof of full final-date coverage")
        reports[name]["limitations"].append(
            "Exactly one page of top rows requested; full query/page coverage is not claimed")
    snap_sitemap = {
        "property": PROPERTY, "transport": "google_api",
        "period_start": start, "period_end": end, "observed_at": day,
        "data_latest_date": latest, "search_type": "web",
        "dimensions": ["sitemap"], "ctr_unit": "fraction",
        "rows": _sitemap_rows(raw[-1]),
    }
    try:
        reports["sitemaps"] = normalize_sitemaps(snap_sitemap)
    except GscEvidenceError:
        raise GscRuntimeError("sitemap_normalization_invalid") from None
    return {
        "schema": "hermes-h24-gsc-live-collection-v1",
        "property": PROPERTY, "observed_at": day, "period_start": start,
        "period_end": end, "search_type": "web",
        "source": "google_search_console", "transport": "google_api",
        "provider_verified": False, "live_api_used_by_hermes": False,
        "data_latest_observed_date": latest, "report_count": len(reports),
        "request_count": len(calls), "reports": reports,
        "quality_status": ("NO_DATA" if not any(
            x["rows"] for k, x in reports.items() if k != "sitemaps") else
            "LATEST_OBSERVED_DATE_UNKNOWN" if latest is None else "OBSERVED"),
        "limitations": [
            "Google Search Console dates use America/Los_Angeles; final data may lag",
            "Query totals are not site totals; no inferred zeros or indexed URL counts",
            "No calls to URL Inspection or write endpoints",
        ],
        "publication_allowed": False, "yfc_write_allowed": False,
    }


def _verify_credential_file(path: Path) -> None:
    if not path.is_absolute():
        raise GscRuntimeError("credential_path_not_absolute")
    try:
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or
                meta.st_size > 32 * 1024 or meta.st_size < 64):
            raise GscRuntimeError("credential_file_unsafe")
        # Validation before google-auth parses the private credential file.
        body = json.loads(path.read_text(encoding="utf-8"))
        if (type(body) is not dict or body.get("type") != "service_account"
                or body.get("token_uri") != "https://oauth2.googleapis.com/token"
                or not re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com",
                                    body.get("client_email", ""))
                or type(body.get("private_key")) is not str):
            raise GscRuntimeError("credential_type_invalid")
    except GscRuntimeError:
        raise
    except (OSError, ValueError, TypeError):
        raise GscRuntimeError("credential_unavailable") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _authorized_fetch(access_token: str) -> Callable[[str, str, dict[str, Any] | None], object]:
    if type(access_token) is not str or not access_token:
        raise GscRuntimeError("token_invalid")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    allowed = {BASE_URL + "/searchAnalytics/query", BASE_URL + "/sitemaps"}
    def fetch(method: str, url: str, body: dict[str, Any] | None) -> object:
        if ((method, url) not in {("POST", BASE_URL + "/searchAnalytics/query"),
                                  ("GET", BASE_URL + "/sitemaps")}
                or url not in allowed):
            raise GscRuntimeError("endpoint_not_allowed")
        payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        req = Request(url, data=payload, method=method, headers={
            "Authorization": "Bearer " + access_token, "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Hermes-GSC-readonly/1",
        })
        try:
            with opener.open(req, timeout=API_TIMEOUT) as res:
                if res.status != 200:
                    raise GscRuntimeError("provider_http_unexpected")
                raw = res.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise GscRuntimeError("provider_response_too_large")
        except HTTPError as exc:
            code = exc.code
            raise GscRuntimeError(
                "provider_http_" + str(code) if code in {400, 401, 403, 404, 429, 500, 502, 503}
                else "provider_http_other") from None
        except (URLError, TimeoutError, OSError):
            raise GscRuntimeError("provider_network_error") from None
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise GscRuntimeError("provider_json_invalid") from None
        if type(result) is not dict:
            raise GscRuntimeError("provider_json_invalid")
        return result
    return fetch


def _write_private_json(path: Path, data: dict[str, Any]) -> None:
    if not path.is_absolute() or path.suffix != ".json":
        raise GscRuntimeError("output_path_invalid")
    parent = path.parent
    try:
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o022:
            raise GscRuntimeError("output_directory_unsafe")
        if path.is_symlink():
            raise GscRuntimeError("output_symlink_denied")
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True,
                         allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > 512 * 1024:
            raise GscRuntimeError("output_too_large")
        fd, name = tempfile.mkstemp(prefix=".gsc-", dir=str(parent))
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    except GscRuntimeError:
        raise
    except (OSError, TypeError, ValueError):
        raise GscRuntimeError("output_write_failed") from None


def live_run(*, credentials_path: Path, output_path: Path,
             now_utc: datetime | None = None) -> dict[str, Any]:
    """One permissioned live run; no scheduling or service activation here."""
    _verify_credential_file(credentials_path)
    try:
        from google.auth.transport.requests import Request as AuthRequest
        from google.oauth2 import service_account
    except ImportError:
        raise GscRuntimeError("google_auth_dependency_missing") from None
    try:
        credentials = service_account.Credentials.from_service_account_file(
            str(credentials_path), scopes=[SCOPE])
        credentials.refresh(AuthRequest())
        token = credentials.token
    except Exception:
        raise GscRuntimeError("google_auth_failed") from None
    utc = now_utc or datetime.now(tz=ZoneInfo("UTC"))
    if utc.tzinfo is None:
        raise GscRuntimeError("timezone_required")
    as_of = utc.astimezone(ZoneInfo("America/Los_Angeles")).date()
    report = collect(_authorized_fetch(token), as_of=as_of)
    # This attestation is set exclusively after a successful actual authorized
    # HTTPS fetch; mocked collect() can never set provider_verified=True.
    report["provider_verified"] = True
    report["live_api_used_by_hermes"] = True
    for sub in report["reports"].values():
        sub["provider_attested"] = True
        sub["hermes_runtime_source_verified"] = True
        sub["live_api_used_by_hermes"] = True
        sub["source_kind"] = "gsc_api_live"
    _write_private_json(output_path, report)
    return {"status": "LIVE_GSC_SNAPSHOT_SAVED",
            "period_end": report["period_end"],
            "quality_status": report["quality_status"],
            "request_count": report["request_count"],
            "report_count": report["report_count"]}
