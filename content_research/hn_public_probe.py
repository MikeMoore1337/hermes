"""Issue #542: explicit, bounded, unauthenticated HN search snapshot.

Not a scheduler, resident agent, scientific claim verifier or general web fetcher.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlencode

from .discussion_digest import build_digest

HOST = "hn.algolia.com"
ENDPOINT = "/api/v1/search_by_date"
TOPICS = {
    "ai-agents": "AI agents",
    "python-qa": "Python testing",
    "fitness-tech": "fitness app",
}
MAX_BYTES = 96 * 1024
MAX_HITS = 12
MIN_POINTS = 10


class PublicSearchError(ValueError):
    """Fixed-code refusal; never echo untrusted remote response."""


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, ip: str) -> None:
        super().__init__(HOST, timeout=6, context=ssl.create_default_context())
        self.ip = ip

    def connect(self) -> None:
        raw = socket.create_connection((self.ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=HOST)


def _global_ip() -> str:
    try:
        addresses = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
        ips = [ipaddress.ip_address(row[4][0]) for row in addresses]
    except (OSError, ValueError):
        raise PublicSearchError("public_dns_unavailable") from None
    if not ips or not all(ip.is_global for ip in ips):
        raise PublicSearchError("nonpublic_dns_denied")
    return str(sorted(ips, key=lambda ip: (ip.version != 4, int(ip)))[0])


def _fetch(query: str, cutoff_epoch: int) -> bytes:
    args = urlencode({
        "query": query,
        "tags": "story",
        "numericFilters": f"created_at_i>={cutoff_epoch},points>=10",
        "hitsPerPage": MAX_HITS,
        "page": 0,
    })
    conn = _PinnedConnection(_global_ip())
    try:
        conn.request("GET", f"{ENDPOINT}?{args}", headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "Hermes-ReadOnly-Discussion-Pilot/1.0",
        })
        response = conn.getresponse()
        if response.status != 200:
            raise PublicSearchError("public_http_refused")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise PublicSearchError("encoding_denied")
        if not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise PublicSearchError("content_type_denied")
        if response.getheader("Content-Length") and int(response.getheader("Content-Length")) > MAX_BYTES:
            raise PublicSearchError("size_limit")
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise PublicSearchError("size_limit")
        return body
    except (OSError, TimeoutError, http.client.HTTPException):
        raise PublicSearchError("public_network_failure") from None
    finally:
        conn.close()


def normalize_results(payload: bytes, *, now: datetime) -> list[dict]:
    """Convert an Algolia API snapshot into untrusted discussion records."""
    if not isinstance(payload, bytes) or len(payload) > MAX_BYTES:
        raise PublicSearchError("payload_size_invalid")
    try:
        data = json.loads(payload)
    except (UnicodeError, ValueError):
        raise PublicSearchError("payload_json_invalid") from None
    if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
        raise PublicSearchError("payload_schema_invalid")
    if len(data["hits"]) > MAX_HITS:
        raise PublicSearchError("too_many_hits")
    if now.tzinfo is None or now.utcoffset() is None:
        raise PublicSearchError("now_timezone_required")
    now = now.astimezone(UTC)
    records: list[dict] = []
    for item in data["hits"]:
        if not isinstance(item, dict):
            continue
        identifier = item.get("objectID")
        title = item.get("title")
        points = item.get("points")
        date = item.get("created_at_i")
        if (not isinstance(identifier, str) or not identifier.isascii()
                or not identifier.isdecimal() or not 0 < len(identifier) <= 12
                or int(identifier) <= 0 or not isinstance(title, str)
                or not title.strip() or len(title) > 180
                or any(ord(c) < 32 or ord(c) == 127 for c in title)
                or type(points) is not int or not MIN_POINTS <= points <= 100000
                or type(date) is not int or not 0 < date <= int(now.timestamp())):
            continue
        try:
            published = datetime.fromtimestamp(date, UTC)
        except (OverflowError, OSError, ValueError):
            continue
        if now - published > timedelta(days=30):
            continue
        records.append({
            "source": "hackernews",
            "url": f"https://news.ycombinator.com/item?id={identifier}",
            "title": title,
            "published_at": published.isoformat(),
            "retrieved_at": now.isoformat(),
            "score": points,
        })
    return records


def run(topic: str, *, now: datetime, transport=None) -> dict:
    """A single fetch at most; no retries, persistence or scheduled runs."""
    if topic not in TOPICS:
        raise PublicSearchError("topic_not_allowed")
    if now.tzinfo is None or now.utcoffset() is None:
        raise PublicSearchError("now_timezone_required")
    reference = now.astimezone(UTC)
    cutoff = int((reference - timedelta(days=30)).timestamp())
    raw = (transport or _fetch)(TOPICS[topic], cutoff)
    records = normalize_results(raw, now=reference)
    digest = build_digest(records, now=reference)
    digest["topic"] = topic
    digest["source"] = "HN_ALGOLIA_PUBLIC_SEARCH_NOT_AUTHORITATIVE"
    digest["search_limit"] = MAX_HITS
    digest["minimum_points"] = MIN_POINTS
    digest["observed_count"] = len(records)
    digest["network_requests"] = 1 if transport is None else 0
    digest["completeness"] = "SAMPLE_ONLY_NOT_FULL_30_DAY_COVERAGE"
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded HN public-source snapshot (explicit opt-in)")
    parser.add_argument("--topic", required=True, choices=sorted(TOPICS))
    parser.add_argument("--execute", action="store_true", help="Permit exactly one public GET")
    args = parser.parse_args(argv)
    if not args.execute:
        print("PUBLIC_SEARCH_NOT_RUN: pass --execute for the one-shot free public request")
        return 0
    try:
        result = run(args.topic, now=datetime.now(UTC))
    except (PublicSearchError, ValueError) as exc:
        print(f"PUBLIC_SEARCH_ERROR: {exc}")
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
