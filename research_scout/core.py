"""Hermes Research Scout: offline evidence triage, never fetch or publish.

All records are untrusted; source hosts are an allowlist, not proof of truth.
No model invocation, network, credentials, storage or subprocesses.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SOURCE_KINDS = {
    "pubmed.ncbi.nlm.nih.gov": "primary",
    "bjsm.bmj.com": "primary",
    "docs.python.org": "primary",
    "github.com": "primary",
    "www.acsm.org": "primary",
    "www.sciencedaily.com": "secondary",
    "medicalxpress.com": "secondary",
}
MAX_AGE_DAYS = 45
MAX_RECORDS = 100
PROMPT_INJECTION = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|system\s+prompt|developer\s+instructions"
    r"|act\s+as\s+(?:the\s+)?system"
    r"|<\|(?:im_start|system|assistant)\|>|BEGIN\s+SYSTEM\s+PROMPT"
    r"|игнорируй\s+(?:все\s+)?(?:предыдущие|прежние)\s+инструкции"
    r"|системн(?:ый|ые|ого)\s+(?:промпт|инструкции)"
    r"|инструкции\s+разработчика",
    re.IGNORECASE,
)


class EvidenceError(ValueError):
    """Bounded input rejected; error message contains no untrusted source text."""


def timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise EvidenceError(f"{field}_missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field}_invalid") from exc
    if result.tzinfo is None:
        raise EvidenceError(f"{field}_timezone_required")
    return result.astimezone(UTC)


def safe_source_url(value: Any) -> tuple[str, str]:
    """Allow only exact approved HTTPS hosts; refuse SSRF primitives."""
    if not isinstance(value, str) or len(value) > 900 or any(ord(ch) < 32 for ch in value):
        raise EvidenceError("url_invalid")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise EvidenceError("url_invalid") from exc
    if (parts.scheme != "https" or not host or parts.username is not None
            or parts.password is not None or port not in (None, 443)
            or parts.fragment or parts.query):
        raise EvidenceError("url_not_allowlisted")
    host = host.lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise EvidenceError("ip_literals_forbidden")
    if host not in SOURCE_KINDS or value.count("@") or not parts.path.startswith("/"):
        raise EvidenceError("host_not_allowlisted")
    return urlunsplit(("https", host, parts.path, "", "")), SOURCE_KINDS[host]


def bounded_text(value: Any, name: str, maximum: int) -> str:
    if (not isinstance(value, str) or not value.strip()
            or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise EvidenceError(f"{name}_invalid")
    return value.strip()


def normalize(source: Any, *, now: datetime) -> dict[str, Any]:
    """Extract only safe metadata; source claims remain unverified."""
    if not isinstance(source, dict) or set(source) != {
        "url", "title", "published_at", "claim_id", "polarity", "summary"
    }:
        raise EvidenceError("schema_invalid")
    url, source_kind = safe_source_url(source["url"])
    title = bounded_text(source["title"], "title", 180)
    summary = bounded_text(source["summary"], "summary", 1200)
    claim = bounded_text(source["claim_id"], "claim_id", 64)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", claim):
        raise EvidenceError("claim_id_invalid")
    if source["polarity"] not in ("supports", "contradicts"):
        raise EvidenceError("polarity_invalid")
    published = timestamp(source["published_at"], field="published_at")
    if published > now + timedelta(days=1):
        raise EvidenceError("published_in_future")
    # Suspected instruction injection remains the primary review blocker
    # even when the same source also happens to be stale.
    if PROMPT_INJECTION.search(title + " " + summary):
        warning = "prompt_injection"
    elif now - published > timedelta(days=MAX_AGE_DAYS):
        warning = "stale_source"
    else:
        warning = None
    return {
        "claim_id": claim, "polarity": source["polarity"],
        "url": url, "title": title, "published_at": published.isoformat(),
        "source_kind": source_kind, "host": urlsplit(url).hostname,
        "warning": warning,
        # Deliberately do NOT return untrusted summary or a truth/confidence score.
    }


def compile_digest(raw: Any, *, now: datetime) -> dict[str, Any]:
    """Rank provenance for human review without claiming factual verification."""
    if now.tzinfo is None:
        raise EvidenceError("now_timezone_required")
    now = now.astimezone(UTC)
    if not isinstance(raw, list) or len(raw) > MAX_RECORDS:
        raise EvidenceError("batch_invalid")
    if not raw:
        return {"status": "NO_DATA", "candidates": [], "rejections": []}
    normalized: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for index, record in enumerate(raw):
        try:
            entry = normalize(record, now=now)
            if entry["url"] in seen_urls:
                raise EvidenceError("duplicate_url")
            seen_urls.add(entry["url"])
            normalized.append(entry)
        except EvidenceError as exc:
            rejections.append({"index": index, "code": str(exc)})
    by_claim: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in normalized:
        by_claim[entry["claim_id"]].append(entry)
    answer: list[dict[str, Any]] = []
    for entry in normalized:
        group = by_claim[entry["claim_id"]]
        competing = {e["polarity"] for e in group if e["warning"] is None}
        primary_hosts = {
            e["host"] for e in group if e["warning"] is None
            and e["source_kind"] == "primary"
            and e["polarity"] == entry["polarity"]
        }
        if entry["warning"]:
            reason = entry["warning"]
        elif len(competing) > 1:
            reason = "contradictory_evidence"
        elif len(primary_hosts) < 2:
            reason = "insufficient_independent_primary_sources"
        else:
            reason = "human_review_required"
        answer.append({
            "claim_id": entry["claim_id"], "title": entry["title"],
            "url": entry["url"], "published_at": entry["published_at"],
            "source_kind": entry["source_kind"],
            "status": "READY_FOR_REVIEW" if reason == "human_review_required" else "HOLD",
            "reason": reason,
        })
    answer.sort(key=lambda x: (x["status"] != "READY_FOR_REVIEW", x["claim_id"], x["url"]))
    return {
        "status": "READY_FOR_REVIEW" if any(
            x["status"] == "READY_FOR_REVIEW" for x in answer
        ) else "HOLD",
        "candidates": answer, "rejections": rejections,
    }
