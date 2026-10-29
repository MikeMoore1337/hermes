"""Hermes #397: explicit owner-invoked, bounded HTTPS/OAuth GET-only Yandex probe.

Does NOT install or schedule a worker, mutate Webmaster, infer provider billing,
promote owner evidence to YFC READY, or create a token. Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import stat
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener,
)

from marketing.yandex_webmaster import (
    BASE, HOST, INPUT_SCHEMA, WebmasterDenied, normalize_export, read_plan,
)

RESPONSE_LIMIT = 64 * 1024
TOTAL_RESPONSE_LIMIT = 256 * 1024
TIMEOUT_SECONDS = 8
MAX_REQUESTS = 6
SCOPE = "webmaster:hostinfo"
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~+-]{20,4096}$")


class YandexLiveDenied(ValueError):
    """Stable public refusal codes only; never include URLs, token or raw API text."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_private_token(path: str) -> str:
    """Private POSIX token file: owned by caller, mode 0600, no symlink."""
    if type(path) is not str or not path.startswith("/") or "\x00" in path:
        raise YandexLiveDenied("TOKEN_PATH_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                    or st.st_mode & 0o077 or st.st_size > 4097):
                raise YandexLiveDenied("TOKEN_FILE_UNSAFE")
            raw = os.read(fd, 4098)
        finally:
            os.close(fd)
    except OSError:
        raise YandexLiveDenied("TOKEN_FILE_UNAVAILABLE") from None
    try:
        token = raw.decode("ascii").strip("\r\n")
    except UnicodeError:
        raise YandexLiveDenied("TOKEN_INVALID") from None
    if not TOKEN_PATTERN.fullmatch(token):
        raise YandexLiveDenied("TOKEN_INVALID")
    return token


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise YandexLiveDenied("RESPONSE_DUPLICATE_KEY")
        obj[key] = value
    return obj


def _parse_response(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > RESPONSE_LIMIT or not raw:
        raise YandexLiveDenied("RESPONSE_SIZE_INVALID")
    try:
        doc = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_json_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                YandexLiveDenied("RESPONSE_NUMBER_INVALID")),
        )
    except (ValueError, UnicodeError, OverflowError):
        raise YandexLiveDenied("RESPONSE_JSON_INVALID") from None
    if type(doc) is not dict:
        raise YandexLiveDenied("RESPONSE_SCHEMA_INVALID")
    return doc


def _safe_url(url: str) -> None:
    if type(url) is not str or len(url) > 1200:
        raise YandexLiveDenied("URL_NOT_ALLOWED")
    try:
        value = urlsplit(url)
    except ValueError:
        raise YandexLiveDenied("URL_NOT_ALLOWED") from None
    if (value.scheme != "https" or value.netloc != "api.webmaster.yandex.net"
            or value.username or value.password or value.port is not None
            or not value.path.startswith("/v4/") or value.fragment):
        raise YandexLiveDenied("URL_NOT_ALLOWED")


def _transport(url: str, token: str) -> bytes:
    _safe_url(url)
    context = ssl.create_default_context()
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
    request = Request(
        url, headers={"Authorization": "OAuth " + token,
                      "Accept": "application/json"}, method="GET",
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise YandexLiveDenied("RESPONSE_NOT_OK")
            data = response.read(RESPONSE_LIMIT + 1)
    except HTTPError as exc:
        code = exc.code
        if code == 401:
            raise YandexLiveDenied("AUTH_REQUIRED") from None
        if code == 403:
            raise YandexLiveDenied("ACCESS_DENIED") from None
        if code == 404:
            raise YandexLiveDenied("HOST_NOT_VERIFIED_OR_UNAVAILABLE") from None
        if code == 429:
            raise YandexLiveDenied("RATE_LIMITED") from None
        if code >= 500:
            raise YandexLiveDenied("UPSTREAM_UNAVAILABLE") from None
        raise YandexLiveDenied("HTTP_REQUEST_REFUSED") from None
    except (URLError, OSError, TimeoutError, ssl.SSLError):
        raise YandexLiveDenied("NETWORK_UNAVAILABLE") from None
    if len(data) > RESPONSE_LIMIT:
        raise YandexLiveDenied("RESPONSE_SIZE_INVALID")
    return data


def _uid(response: dict[str, Any]) -> int:
    number = response.get("user_id")
    if type(number) is not int or not 1 <= number <= 2**63 - 1:
        raise YandexLiveDenied("USER_ID_INVALID")
    return number


def _verify_host(response: dict[str, Any]) -> None:
    hosts = response.get("hosts")
    if type(hosts) is not list or len(hosts) > 100:
        raise YandexLiveDenied("HOST_LIST_INVALID")
    target = [x for x in hosts if type(x) is dict and x.get("host_id") == HOST]
    if len(target) != 1 or target[0].get("verified") is not True:
        raise YandexLiveDenied("TARGET_HOST_NOT_VERIFIED")
    # Yandex /v4/user/{uid}/hosts exposes a required ASCII host URL.
    # Matching an ID alone must not accept a mismatched canonical origin.
    if target[0].get("ascii_host_url") != "https://your-fitness-coach.ru/":
        raise YandexLiveDenied("TARGET_HOST_URL_MISMATCH")
    mirror = target[0].get("main_mirror")
    if mirror is not None and (
        type(mirror) is not dict or mirror.get("host_id") != HOST
    ):
        raise YandexLiveDenied("PRIMARY_MIRROR_MISMATCH")
    if target[0].get("host_data_status") in ("NOT_INDEXED", "NOT_LOADED"):
        raise YandexLiveDenied("TARGET_SITE_DATA_UNAVAILABLE")


def collect(
    *, as_of: date, token: str, transport: Callable[[str, str], bytes] | None = None,
    device: str = "ALL",
) -> dict[str, Any]:
    """Only six GETs in fixed order, gate user and verified primary host first.

    An injected transport is for synthetic tests; this API cannot attest such
    a transport's real-network identity. Returned evidence stays unverified.
    """
    if (type(as_of) is not date or type(token) is not str or
            not TOKEN_PATTERN.fullmatch(token)):
        raise YandexLiveDenied("INPUT_INVALID")
    endpoint = transport if transport is not None else _transport
    total_bytes, request_count = 0, 0

    def read(url: str) -> dict[str, Any]:
        nonlocal total_bytes, request_count
        _safe_url(url)
        if request_count >= MAX_REQUESTS:
            raise YandexLiveDenied("REQUEST_BUDGET_EXCEEDED")
        request_count += 1
        try:
            raw = endpoint(url, token)
        except YandexLiveDenied:
            raise
        except Exception:
            # Third-party transports may leak response/token in exception text.
            raise YandexLiveDenied("REQUEST_FAILED") from None
        if type(raw) is not bytes:
            raise YandexLiveDenied("RESPONSE_SIZE_INVALID")
        total_bytes += len(raw)
        if total_bytes > TOTAL_RESPONSE_LIMIT:
            raise YandexLiveDenied("RESPONSE_BUDGET_EXCEEDED")
        return _parse_response(raw)

    account = read(BASE + "/user")
    uid = _uid(account)
    hosts = read(BASE + f"/user/{uid}/hosts")
    _verify_host(hosts)
    end = as_of - timedelta(days=2)
    start = end - timedelta(days=27)
    plan = read_plan(user_id=uid, host_id=HOST, start=str(start),
                     end=str(end), device=device)
    if plan["max_requests"] != MAX_REQUESTS or len(plan["requests"]) != MAX_REQUESTS:
        raise YandexLiveDenied("PLAN_INVALID")
    payloads = [read(row["url"]) for row in plan["requests"][2:]]
    envelope = {
        "schema": INPUT_SCHEMA, "source_type": "owner_export",
        "owner_attested": False, "host_id": HOST,
        "observed_at": str(as_of),
        "period_start": str(start), "period_end": str(end),
        "device": device, "search_intent": "informational",
        "popular": payloads[0], "all_history": payloads[1],
        "index_history": payloads[2], "sitemaps": payloads[3],
    }
    try:
        report = normalize_export(envelope, as_of=as_of)
    except WebmasterDenied:
        raise YandexLiveDenied("Yandex_RESPONSE_CONTRACT_CHANGED") from None
    # The nested report explicitly remains owner-export / NOT provider-attested.
    # A synthetic or caller-injected transport cannot manufacture VERIFIED.
    return {
        "schema": "hermes-h24-yandex-read-probe-v1",
        "status": "SYNTHETIC_TRANSPORT_CHECK" if transport is not None
                  else "LIVE_GET_RESPONSE_UNATTESTED",
        "source": "yandex_webmaster", "host_id": HOST,
        "period_start": str(start), "period_end": str(end),
        "requests": request_count, "retries": 0,
        "external_publication_allowed": False,
        "seo_changes_applied": 0, "sitemap_mutations": 0,
        "paid_api_allowed": False, "data": report,
    }


def summarized_receipt(report: dict[str, Any]) -> dict[str, Any]:
    """Safe operator output, deliberately omits query strings and credentials."""
    data = report["data"]
    return {
        "status": report["status"], "site": report["host_id"],
        "period_start": report["period_start"], "period_end": report["period_end"],
        "request_count": report["requests"],
        "query_rows": len(data["seo_research_observations"]),
        "sitemaps": len(data["sitemaps"] or []),
        "indexing_available": data["indexing_http_status_history"] is not None,
        "source_provenance": data["status"],
        "publication_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Owner-invoked bounded Yandex GET probe")
    parser.add_argument("--date", required=True)
    parser.add_argument("--token-file")
    parser.add_argument("--execute-read", action="store_true")
    args = parser.parse_args(argv)
    try:
        as_of = date.fromisoformat(args.date)
        if not args.execute_read:
            result = {"status": "NOT_EXECUTED", "scope": SCOPE, "max_gets": 6}
        else:
            if args.token_file is None:
                raise YandexLiveDenied("TOKEN_FILE_REQUIRED")
            result = summarized_receipt(collect(
                as_of=as_of, token=read_private_token(args.token_file)))
        code = 0
    except (YandexLiveDenied, ValueError):
        result = {"status": "REFUSED", "reason": "AUTH_OR_RESPONSE_NOT_VERIFIED"}
        code = 2
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
