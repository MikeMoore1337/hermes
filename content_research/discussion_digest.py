"""Issue #542: offline 30-day discussion signal pilot, no network or API keys."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
import re

ALLOWED_SOURCES = {"github": "github.com", "hackernews": "news.ycombinator.com"}
GH_PATH = re.compile(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|discussions|pull)/[1-9][0-9]*\Z")
HN_QUERY = re.compile(r"id=[1-9][0-9]*\Z")
MAX_RECORDS = 200
DAYS = 30


def _text(value: object, name: str, maximum: int) -> str:
    if (not isinstance(value, str) or not value.strip()
            or len(value) > maximum or any(ord(ch) < 32 for ch in value)):
        raise ValueError(f"{name}: invalid")
    return value.strip()


def _instant(value: object, name: str) -> datetime:
    raw = _text(value, name, 40)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name}: invalid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name}: timezone required")
    return parsed.astimezone(UTC)


def _source_url(source: str, url: object) -> str:
    value = _text(url, "url", 600)
    parts = urlsplit(value)
    if (parts.scheme != "https" or parts.netloc != ALLOWED_SOURCES[source]
            or parts.fragment or parts.username or parts.password or parts.port):
        raise ValueError("url: source/host/scheme not allowed")
    if source == "github":
        if parts.query or not GH_PATH.fullmatch(parts.path):
            raise ValueError("url: expected exact GitHub issue, pull or discussion")
    elif parts.path != "/item" or not HN_QUERY.fullmatch(parts.query):
        raise ValueError("url: expected exact Hacker News item id")
    return value


def build_digest(records: object, *, now: datetime) -> dict:
    """Validate all records first. Popularity is not scientific-quality evidence."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now: timezone required")
    reference = now.astimezone(UTC)
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError(f"records: expected list with at most {MAX_RECORDS} entries")
    cutoff = reference - timedelta(days=DAYS)
    seen: dict[str, dict] = {}
    expired = 0
    duplicates = 0
    for i, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValueError(f"records[{i}]: expected object")
        if set(item) != {"source", "url", "title", "published_at", "retrieved_at", "score"}:
            raise ValueError(f"records[{i}]: required exact fields")
        source = _text(item["source"], "source", 30)
        if source not in ALLOWED_SOURCES:
            raise ValueError("source: unsupported source")
        url = _source_url(source, item["url"])
        title = _text(item["title"], "title", 180)
        published = _instant(item["published_at"], "published_at")
        retrieved = _instant(item["retrieved_at"], "retrieved_at")
        if published > retrieved or retrieved > reference:
            raise ValueError("timestamp: invalid ordering or future retrieval")
        score = item["score"]
        if type(score) is not int or not 0 <= score <= 100000:
            raise ValueError("score: expected integer 0..100000")
        if published < cutoff:
            expired += 1
            continue
        normal = {
            "source": source, "url": url, "title": title,
            "published_at": published.isoformat(), "retrieved_at": retrieved.isoformat(),
            "discussion_score": score,
            "scientific_evidence": False,
        }
        previous = seen.get(url)
        if previous:
            if (previous["title"], previous["published_at"], previous["source"]) != (title, normal["published_at"], source):
                raise ValueError("duplicate: conflicting source metadata")
            duplicates += 1
            if retrieved > datetime.fromisoformat(previous["retrieved_at"]):
                seen[url] = normal
        else:
            seen[url] = normal
    ordered = sorted(seen.values(), key=lambda d: (-d["discussion_score"], d["url"]))
    return {
        "status": "DISCUSSION_ONLY_NOT_SCIENTIFIC_EVIDENCE",
        "window_days": DAYS,
        "as_of": reference.isoformat(),
        "items": ordered[:20],
        "counts": {"received": len(records), "expired": expired, "duplicates": duplicates, "kept": len(ordered)},
        "network_requests": 0,
        "provider_cost": "NOT_MEASURED",
    }
