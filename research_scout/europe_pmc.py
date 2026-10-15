"""One-shot Europe PMC metadata search without registration, keys or publishing.

Only fixed topics and one bounded pinned-IP HTTPS GET, no retries, redirects,
LLM, local user data, chat message or untrusted custom query.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
from datetime import UTC, date, datetime, timedelta
from typing import Any, Callable
from urllib.parse import urlencode

from .core import PROMPT_INJECTION
from .pubmed_fetch import DOI

HOST = "www.ebi.ac.uk"
ENDPOINT = "/europepmc/webservices/rest/search"
MAX_BODY = 32000
MAX_ITEMS = 2
MAX_AGE_DAYS = 45
TOPICS = {
    "resistance-training": 'TITLE_ABS:"resistance training"',
    "muscle-hypertrophy": 'TITLE_ABS:"muscle hypertrophy"',
    "exercise-recovery": 'TITLE_ABS:"exercise recovery"',
}
ID = re.compile(r"(?:[1-9][0-9]{1,11}|PMC[1-9][0-9]{1,11})\Z")
DAY = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}\Z")


class EuropePMCError(ValueError):
    """Fixed codes, no raw network input, source text or secrets."""


def resolve_public() -> str:
    try:
        records = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise EuropePMCError("pmc_dns_unavailable") from None
    ips = sorted({row[4][0] for row in records
                  if row[0] in (socket.AF_INET, socket.AF_INET6)})
    try:
        parsed = [ipaddress.ip_address(value) for value in ips]
    except ValueError:
        raise EuropePMCError("pmc_dns_invalid") from None
    if not parsed or not all(ip.is_global for ip in parsed):
        raise EuropePMCError("pmc_private_dns_denied")
    v4 = [ip for ip in parsed if ip.version == 4]
    return str(sorted(v4 or parsed, key=int)[0])


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, ip: str):
        super().__init__(HOST, timeout=8, context=ssl.create_default_context())
        self.pinned_ip = ip

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def fetch(topic: str, start: date, end: date) -> bytes:
    if topic not in TOPICS or type(topic) is not str:
        raise EuropePMCError("topic_not_allowlisted")
    if not isinstance(start, date) or not isinstance(end, date) or start > end:
        raise EuropePMCError("dates_invalid")
    parameters = urlencode({
        "query": TOPICS[topic] + " AND FIRST_PDATE:[" + start.isoformat() +
                 " TO " + end.isoformat() + "]",
        "format": "json", "resultType": "lite", "pageSize": str(MAX_ITEMS),
    })
    connection = PinnedHTTPS(resolve_public())
    try:
        connection.request(
            "GET", ENDPOINT + "?" + parameters,
            headers={"Host": HOST, "Accept": "application/json",
                     "Accept-Encoding": "identity", "Connection": "close",
                     "User-Agent": "HermesResearchScout/0.2"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise EuropePMCError("pmc_http_refused")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise EuropePMCError("pmc_encoding_denied")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise EuropePMCError("pmc_content_type_denied")
        length = response.getheader("Content-Length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or int(length) > MAX_BODY
        ):
            raise EuropePMCError("pmc_body_too_large")
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise EuropePMCError("pmc_body_too_large")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException):
        raise EuropePMCError("pmc_network_or_tls_failed") from None
    finally:
        connection.close()


def unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EuropePMCError("duplicate_json_key")
        result[key] = value
    return result


def parse(raw: bytes, topic: str, *, now: datetime) -> dict[str, Any]:
    if type(topic) is not str or topic not in TOPICS or not isinstance(now, datetime) or now.tzinfo is None:
        raise EuropePMCError("input_invalid")
    if type(raw) is not bytes or len(raw) > MAX_BODY:
        raise EuropePMCError("pmc_response_invalid")
    try:
        root = json.loads(raw, object_pairs_hook=unique_json)
    except EuropePMCError:
        raise
    except (ValueError, UnicodeError):
        raise EuropePMCError("pmc_json_invalid") from None
    if type(root) is not dict or type(root.get("hitCount")) is not int or root["hitCount"] < 0:
        raise EuropePMCError("pmc_schema_invalid")
    block = root.get("resultList")
    rows = block.get("result") if type(block) is dict else None
    if type(rows) is not list or len(rows) > MAX_ITEMS or len(rows) > root["hitCount"]:
        raise EuropePMCError("pmc_rows_invalid")
    if root["hitCount"] > 0 and not rows:
        raise EuropePMCError("pmc_rows_invalid")
    today = now.astimezone(UTC).date()
    results, rejections, seen = [], [], set()
    for index, row in enumerate(rows):
        if type(row) is not dict:
            rejections.append({"index": index, "reason": "row_invalid"})
            continue
        source, ident = row.get("source"), row.get("id")
        if (source not in ("MED", "PMC") or type(ident) is not str
                or ID.fullmatch(ident) is None
                or (source == "PMC") != ident.startswith("PMC")):
            rejections.append({"index": index, "reason": "source_or_id_invalid"})
            continue
        key = (source, ident)
        if key in seen:
            rejections.append({"index": index, "reason": "duplicate_record"})
            continue
        seen.add(key)
        title, doi, raw_date = row.get("title"), row.get("doi"), row.get("firstPublicationDate")
        if (type(title) is not str or not 1 <= len(title.strip()) <= 300
                or any(ord(c) < 32 or ord(c) == 127 for c in title)):
            rejections.append({"index": index, "reason": "title_invalid"})
            continue
        if doi is not None and (type(doi) is not str or DOI.fullmatch(doi) is None):
            rejections.append({"index": index, "reason": "doi_invalid"})
            continue
        item = {
            "source": "EUROPE_PMC", "id": ident,
            "source_url": ("https://europepmc.org/articles/" if source == "PMC"
                           else "https://europepmc.org/article/MED/") + ident,
            "title": title.strip(), "doi": doi, "status": "HOLD",
            "reason": "date_unverified", "scientific_claims_verified": False,
        }
        if PROMPT_INJECTION.search(title):
            item["title"] = "[quarantined]"
            item["reason"] = "suspicious_title"
        elif type(raw_date) is str and DAY.fullmatch(raw_date) is not None:
            try:
                published = date.fromisoformat(raw_date)
            except ValueError:
                item["reason"] = "invalid_publication_date"
            else:
                item["first_publication_date"] = published.isoformat()
                if published > today + timedelta(days=1):
                    item["reason"] = "future_publication_date"
                elif today - published > timedelta(days=MAX_AGE_DAYS):
                    item["reason"] = "stale_publication_date"
                else:
                    item["status"], item["reason"] = "MANUAL_REVIEW", "metadata_only"
        results.append(item)
    status = ("NO_DATA" if root["hitCount"] == 0 else
              "MANUAL_REVIEW" if any(x["status"] == "MANUAL_REVIEW" for x in results)
              else "HOLD")
    return {
        "status": status, "topic": topic, "reported_total": root["hitCount"],
        "candidates": results, "rejections": rejections,
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }


def run(topic: str, *, now: datetime | None = None,
        transport: Callable[[str, date, date], bytes] = fetch) -> dict[str, Any]:
    if type(topic) is not str or topic not in TOPICS:
        raise EuropePMCError("topic_not_allowlisted")
    observed = now if now is not None else datetime.now(UTC)
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        raise EuropePMCError("now_timezone_required")
    end = observed.astimezone(UTC).date()
    return parse(transport(topic, end - timedelta(days=30), end), topic, now=observed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One bounded Europe PMC public metadata search")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--topic", choices=sorted(TOPICS), required=True)
    arguments = parser.parse_args(argv)
    if not arguments.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = run(arguments.topic)
    except EuropePMCError as exc:
        print(json.dumps({"status": "UNKNOWN", "reason": str(exc)}))
        return 2
    # Avoid automatically posting arbitrary untrusted article text to journald.
    print(json.dumps({
        "status": result["status"], "topic": result["topic"],
        "candidates_count": len(result["candidates"]),
        "rejections_count": len(result["rejections"]),
        "scientific_claims_verified": False,
        "automatic_publication": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
