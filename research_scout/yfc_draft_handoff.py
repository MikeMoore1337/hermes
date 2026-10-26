"""I4 #599: strictly draft-only, HMAC authenticated YFC long-form article transfer.

Requires operator-provided full text and independent private source snapshots.
Never produces scientific claims from a bibliography, calls a model, publishes,
reads Root Telegram auth, or installs/enables a timer. Network POST needs an
additional explicit runtime opt-in and the *existing* shared HMAC secret.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener,
)

SCHEMA = "hermes-i4-reviewed-content-v1"
INTAKE_SCHEMA = "hermes-web-article-intake-v1"
POLICY = "AUTO_DRAFT_ONLY"
SOURCE_DIR = Path("/var/lib/hermes-research-scout/i4-primary-texts")
REVIEWED_FILE = Path("/var/lib/hermes-research-scout/i4-reviewed-content.json")
INTAKE_URL = "https://app.your-fitness-coach.ru/api/v1/hermes/articles/intake"
MAX_REQUEST = 128 * 1024
MAX_SOURCE = 512 * 1024
MAX_RESPONSE = 16 * 1024
MAX_SOURCES = 16
ALLOWED_HOSTS = frozenset({
    "pmc.ncbi.nlm.nih.gov", "pubmed.ncbi.nlm.nih.gov",
    "europepmc.org", "www.mdpi.com",
})
SAFE_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
SAFE_HEX = re.compile(r"[a-f0-9]{64}\Z")
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class HandoffHold(ValueError):
    """Fixed machine reason codes, never user material."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise HandoffHold(code)


def _protected_bytes(path: Path, *, max_size: int) -> bytes:
    """Bound file to OS identity, strict mode and O_NOFOLLOW; do not log bytes."""
    try:
        parent = path.parent.lstat()
        meta = path.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                and stat.S_IMODE(parent.st_mode) == 0o700,
                "SOURCE_DIRECTORY_UNTRUSTED")
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1
                and 0 < meta.st_size <= max_size, "SOURCE_FILE_UNTRUSTED")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            require((st.st_ino, st.st_dev, st.st_size) ==
                    (meta.st_ino, meta.st_dev, meta.st_size), "SOURCE_FILE_CHANGED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(max_size + 1)
        finally:
            os.close(fd)
        require(len(data) == meta.st_size, "SOURCE_FILE_CHANGED")
        return data
    except (OSError, UnicodeError):
        raise HandoffHold("SOURCE_UNAVAILABLE") from None


def _validate_url(value: object) -> str:
    require(type(value) is str and 18 <= len(value) <= 900,
            "SOURCE_URL_INVALID")
    try:
        uri = urlsplit(value)
        host = uri.hostname
        port = uri.port
    except ValueError:
        raise HandoffHold("SOURCE_URL_INVALID") from None
    require(uri.scheme == "https" and host in ALLOWED_HOSTS
            and uri.username is None and uri.password is None
            and port in (None, 443) and not uri.query and not uri.fragment
            and bool(uri.path) and uri.netloc == host,
            "SOURCE_URL_NOT_ALLOWLISTED")
    return value


def _validate_article(article: object) -> tuple[str, list[tuple[str, str]]]:
    require(type(article) is dict and type(article.get("slug")) is str
            and SLUG.fullmatch(article["slug"]) is not None,
            "ARTICLE_SLUG_INVALID")
    require(article.get("article_kind") in ("evidence_review", "research_update")
            and article.get("risk_level") in ("low", "moderate", "unknown")
            and article.get("evidence_level") in (
                "limited", "unknown", "preliminary", "conflicting"
            ) and article.get("domain_reviewer") is None,
            "ARTICLE_SCOPE_UNVERIFIED")
    sections = article.get("body_sections")
    require(type(sections) is list and 2 <= len(sections) <= 24 and all(
        type(section) is dict and type(section.get("heading")) is str
        and section["heading"].strip()
        and type(section.get("paragraphs")) is list
        and 1 <= len(section["paragraphs"]) <= 8
        and all(type(p) is str and 40 <= len(p) <= 3000 for p in section["paragraphs"])
        for section in sections), "ARTICLE_CONTENT_INCOMPLETE")
    claims, matrix = article.get("claims"), article.get("claim_source_matrix")
    sources = article.get("sources")
    require(type(claims) is list and 1 <= len(claims) <= 80
            and type(matrix) is list and len(matrix) == len(claims)
            and type(sources) is list and 2 <= len(sources) <= MAX_SOURCES,
            "ARTICLE_EVIDENCE_INCOMPLETE")
    require(all(type(c) is dict and type(c.get("claim_id")) is str
                and SAFE_ID.fullmatch(c["claim_id"]) and
                type(c.get("claim_text")) is str and c["claim_text"].strip()
                for c in claims), "ARTICLE_CLAIMS_INVALID")
    claim_ids = [c["claim_id"] for c in claims]
    require(len(claim_ids) == len(set(claim_ids)), "ARTICLE_CLAIMS_INVALID")
    resolved = []
    for source in sources:
        require(type(source) is dict and type(source.get("source_id")) is str
                and SAFE_ID.fullmatch(source["source_id"]),
                "ARTICLE_SOURCES_INVALID")
        resolved.append((source["source_id"], _validate_url(source.get("url"))))
    ids = [k for k, _ in resolved]
    urls = [u for _, u in resolved]
    require(len(ids) == len(set(ids)) and len(urls) == len(set(urls)),
            "ARTICLE_SOURCES_DUPLICATE")
    actual = []
    for item in matrix:
        require(type(item) is dict and item.get("review_status") == "pending"
                and type(item.get("claim_id")) is str
                and type(item.get("source_ids")) is list
                and 1 <= len(item["source_ids"]) <= 15
                and all(k in ids for k in item["source_ids"]),
                "ARTICLE_REVIEW_NOT_ATTESTED")
        actual.append(item["claim_id"])
    require(len(actual) == len(set(actual)) and set(actual) == set(claim_ids),
            "ARTICLE_MATRIX_INCOMPLETE")
    require("published" not in article and "publication_allowed" not in article
            and "scientific_claims_verified" not in article,
            "ARTICLE_PRIVILEGE_ESCALATION")
    return article["slug"], resolved


def _evidence_guard(entries: object, sources: list[tuple[str, str]],
                    *, source_dir: Path) -> None:
    """Hash locally cached primary texts; no inferred results or rights clearance."""
    require(type(entries) is list and len(entries) == len(sources),
            "PRIMARY_TEXT_RECEIPTS_MISSING")
    mapping = {}
    for row in entries:
        require(type(row) is dict and set(row) == {
            "source_id", "url", "full_text_sha256",
        } and type(row["source_id"]) is str
                and SAFE_ID.fullmatch(row["source_id"]) is not None
                and type(row["full_text_sha256"]) is str
                and SAFE_HEX.fullmatch(row["full_text_sha256"]) is not None,
                "PRIMARY_TEXT_RECEIPT_INVALID")
        require(row["source_id"] not in mapping, "PRIMARY_TEXT_DUPLICATE")
        mapping[row["source_id"]] = row
    require(set(mapping) == {identifier for identifier, _ in sources},
            "PRIMARY_TEXT_RECEIPT_MISMATCH")
    for identifier, url in sources:
        row = mapping[identifier]
        require(row["url"] == url, "PRIMARY_TEXT_RECEIPT_MISMATCH")
        raw = _protected_bytes(source_dir / (identifier + ".txt"), max_size=MAX_SOURCE)
        require(hashlib.sha256(raw).hexdigest() == row["full_text_sha256"],
                "PRIMARY_TEXT_DIGEST_MISMATCH")


def build_payload(document: object, *, source_dir: Path = SOURCE_DIR) -> dict:
    """Prepare a Pydantic-compatible YFC HMAC request. No I/O beyond local hashes."""
    require(type(document) is dict
            and set(document) == {"schema", "article", "source_receipts", "research_version"}
            and document["schema"] == SCHEMA
            and type(document["research_version"]) is str
            and re.fullmatch(r"i4-[a-zA-Z0-9_.:-]{4,61}",
                             document["research_version"]) is not None,
            "ENVELOPE_CONTRACT_INVALID")
    article = document["article"]
    slug, sources = _validate_article(article)
    _evidence_guard(document["source_receipts"], sources, source_dir=source_dir)
    unique = json.dumps(
        {"schema": "hermes-i4-autocandidate-v1", "slug": slug,
         "source_urls": sorted(url for _, url in sources)},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    digest = hashlib.sha256(unique.encode("utf-8")).hexdigest()
    provenance = {
        "provider": "local",
        "model": "hermes-reviewed-source",
        "prompt_version": "i4-source-bound-v1",
        "skill_version": "yfc-hermes-editorial-v1",
    }
    stable = json.dumps({"article": article,
                         "research_version": document["research_version"],
                         "provenance": provenance}, sort_keys=True,
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    revision = hashlib.sha256(stable).hexdigest()
    return {
        "schema_version": INTAKE_SCHEMA,
        "idempotency_key": "i4-" + revision[:32],
        "request_nonce": "i4-" + revision[32:],
        "candidate_id": digest[:32],
        "research_version": document["research_version"],
        "article": article,
        "provenance": provenance,
    }


def _encode(payload: dict) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    require(len(raw) <= MAX_REQUEST, "INTAKE_REQUEST_TOO_LARGE")
    return raw


def headers(payload: dict, secret: str, key_id: str,
            *, timestamp: int | None = None) -> dict[str, str]:
    """Sign exactly the bytes sent, matching YFC HMAC-SHA256 contract."""
    require(bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", key_id or ""))
            and type(secret) is str and len(secret) >= 16,
            "HMAC_NOT_CONFIGURED")
    moment = str(int(time.time()) if timestamp is None else timestamp)
    body = _encode(payload)
    nonce = payload["request_nonce"]
    signature = hmac.new(secret.encode("utf-8"),
                         moment.encode("ascii") + b"\n" +
                         nonce.encode("ascii") + b"\n" + body,
                         hashlib.sha256).hexdigest()
    return {
        "X-Hermes-Key-Id": key_id,
        "X-Hermes-Timestamp": moment,
        "X-Hermes-Nonce": nonce,
        "X-Hermes-Signature": "sha256=" + signature,
        "Content-Type": "application/json",
    }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def transmit(payload: dict, *, secret: str, key_id: str, approved: bool,
             opener=None) -> str:
    require(approved is True, "OWNER_SUBMIT_GATE_CLOSED")
    body = _encode(payload)
    header = headers(payload, secret, key_id)
    transport = opener or build_opener(ProxyHandler({}),
                                      HTTPSHandler(context=ssl.create_default_context()),
                                      _NoRedirect())
    request = Request(INTAKE_URL, data=body, method="POST", headers=header)
    try:
        with transport.open(request, timeout=10) as response:
            require(response.status == 200
                    and response.url == INTAKE_URL, "INTAKE_RESPONSE_UNTRUSTED")
            raw = response.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, "INTAKE_RESPONSE_UNTRUSTED")
        answer = json.loads(raw)
    except (OSError, HTTPError, URLError, json.JSONDecodeError, UnicodeError):
        raise HandoffHold("INTAKE_NETWORK_OR_CONTRACT_FAILED") from None
    require(type(answer) is dict and
            answer.get("status") in ("accepted", "duplicate")
            and answer.get("article_status") == "draft"
            and type(answer.get("article_id")) is str
            and re.fullmatch(r"[a-f0-9]{32}", answer["article_id"]) is not None
            and type(answer.get("content_version")) is int
            and answer["content_version"] >= 1,
            "INTAKE_RESPONSE_UNTRUSTED")
    return answer["status"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="I4 owner-gated draft-only HMAC handoff")
    parser.add_argument("--submit", action="store_true")
    args = parser.parse_args(argv)
    try:
        data = json.loads(_protected_bytes(REVIEWED_FILE, max_size=MAX_REQUEST))
        payload = build_payload(data)
        if not args.submit:
            print(json.dumps({"status": "READY_NOT_SUBMITTED",
                              "policy": POLICY, "public_url": None,
                              "model_calls": 0, "writes": 0}))
            return 0
        require(os.environ.get("HERMES_I4_DRAFT_SUBMIT_APPROVED") == "YES",
                "OWNER_SUBMIT_GATE_CLOSED")
        status = transmit(
            payload,
            secret=os.environ.get("HERMES_I4_HMAC_SECRET", ""),
            key_id=os.environ.get("HERMES_I4_HMAC_KEY_ID", ""),
            approved=True,
        )
        print(json.dumps({"status": status.upper() + "_DRAFT_ONLY",
                          "policy": POLICY, "public_url": None,
                          "model_calls": 0, "publisher_invoked": False}))
        return 0
    except (HandoffHold, ValueError, TypeError, UnicodeError) as exc:
        code = str(exc) if type(exc) is HandoffHold else "INPUT_UNAVAILABLE"
        print(json.dumps({"status": "HOLD", "reason": code,
                          "policy": POLICY, "publisher_invoked": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
