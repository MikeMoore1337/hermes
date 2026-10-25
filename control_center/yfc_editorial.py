"""I4: bounded, one-shot YFC Root editorial transport for future Hermes UI.

This module has NO scheduler, token store, web route, or automatic publication.
Only an explicit interactive owner action can call publish_existing_draft.
The YFC API validates the real Telegram Root identity independently of Hermes.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

YFC_ORIGIN = "https://app.your-fitness-coach.ru"
LIST_ENDPOINT = "/api/v1/admin/articles/drafts"
PUBLISH_ENDPOINT = "/api/v1/admin/articles/drafts/publish"
ARTICLE_ID = re.compile(r"[0-9a-f]{32}\Z")
CONTENT_HASH = re.compile(r"[0-9a-f]{64}\Z")
ACCESS_TOKEN = re.compile(r"[A-Za-z0-9._-]{20,4096}\Z")
DRAFT_STATUSES = frozenset({"draft", "review", "update_required"})
MAX_LIST_BODY = 256 * 1024
MAX_DETAIL_BODY = 512 * 1024
MAX_RESULT_BODY = 16 * 1024


class EditorialTransportError(ValueError):
    """Fixed-coded failure. No bearer, remote JSON or headers in exceptions."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _token(token: str) -> str:
    if type(token) is not str or ACCESS_TOKEN.fullmatch(token) is None:
        raise EditorialTransportError("yfc_root_token_required")
    return token


def _identifier(value: str, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise EditorialTransportError(code)
    return value


def _request(
    *,
    path: str,
    root_token: str,
    method: str,
    payload: dict[str, Any] | None,
    max_bytes: int,
    opener=None,
) -> Any:
    # A caller cannot supply an origin, URL, host, port, or redirects.
    if not path.startswith("/api/v1/admin/articles/drafts"):
        raise EditorialTransportError("yfc_endpoint_denied")
    token = _token(root_token)
    body = None
    if method == "POST":
        if path != PUBLISH_ENDPOINT or payload is None:
            raise EditorialTransportError("yfc_write_operation_denied")
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    elif method != "GET" or payload is not None:
        raise EditorialTransportError("yfc_method_denied")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(YFC_ORIGIN + path, data=body, headers=headers, method=method)
    try:
        with (opener or build_opener(_NoRedirect)).open(req, timeout=15) as resp:
            if resp.status != 200:
                raise EditorialTransportError("yfc_unexpected_response")
            encoded = resp.read(max_bytes + 1)
            if len(encoded) > max_bytes:
                raise EditorialTransportError("yfc_response_too_large")
            return json.loads(encoded)
    except EditorialTransportError:
        raise
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise EditorialTransportError("yfc_root_auth_required") from None
        if exc.code == 409:
            raise EditorialTransportError("yfc_article_revision_conflict") from None
        if exc.code in (404, 422):
            raise EditorialTransportError("yfc_article_not_publishable") from None
        raise EditorialTransportError("yfc_request_failed") from None
    except (URLError, TimeoutError, OSError, ValueError, TypeError):
        raise EditorialTransportError("yfc_request_unavailable") from None


def list_drafts(root_token: str, *, limit: int = 25, offset: int = 0, opener=None) -> list[dict]:
    """Owner Root gets unpublished drafts; no public leak or status mutation."""
    if type(limit) is not int or not 1 <= limit <= 50:
        raise EditorialTransportError("yfc_limit_invalid")
    if type(offset) is not int or not 0 <= offset <= 5000:
        raise EditorialTransportError("yfc_offset_invalid")
    args = urlencode({"limit": limit, "offset": offset})
    data = _request(
        path=LIST_ENDPOINT + "?" + args,
        root_token=root_token,
        method="GET",
        payload=None,
        max_bytes=MAX_LIST_BODY,
        opener=opener,
    )
    if not isinstance(data, list) or len(data) > limit or any(
        not isinstance(row, dict)
        or row.get("article_status") not in DRAFT_STATUSES
        or ARTICLE_ID.fullmatch(str(row.get("article_id", ""))) is None
        for row in data
    ):
        raise EditorialTransportError("yfc_draft_response_invalid")
    return data


def get_draft(root_token: str, article_id: str, *, opener=None) -> dict:
    """Read a real exact YFC draft, source matrix and blockers for review."""
    article_id = _identifier(article_id, ARTICLE_ID, "yfc_article_id_invalid")
    data = _request(
        path=LIST_ENDPOINT + "/" + article_id,
        root_token=root_token,
        method="GET",
        payload=None,
        max_bytes=MAX_DETAIL_BODY,
        opener=opener,
    )
    if (
        not isinstance(data, dict)
        or data.get("article_id") != article_id
        or data.get("article_status") not in DRAFT_STATUSES
        or not isinstance(data.get("claim_source_matrix"), list)
        or not isinstance(data.get("sources"), list)
        or not isinstance(data.get("review_blockers"), list)
        or CONTENT_HASH.fullmatch(str(data.get("content_hash", ""))) is None
        or type(data.get("content_version")) is not int
        or data["content_version"] < 1
    ):
        raise EditorialTransportError("yfc_draft_response_invalid")
    return data


def publish_existing_draft(
    root_token: str,
    *,
    article_id: str,
    content_hash: str,
    content_version: int,
    owner_confirmed: bool,
    opener=None,
) -> dict[str, Any]:
    """No call without independent Root token AND explicit per-action owner confirmation."""
    if owner_confirmed is not True:
        raise EditorialTransportError("owner_confirmation_required")
    article_id = _identifier(article_id, ARTICLE_ID, "yfc_article_id_invalid")
    content_hash = _identifier(content_hash, CONTENT_HASH, "yfc_hash_invalid")
    if type(content_version) is not int or content_version < 1:
        raise EditorialTransportError("yfc_version_invalid")
    payload = {
        "article_id": article_id,
        "expected_content_hash": content_hash,
        "expected_content_version": content_version,
        "acknowledge_unverified_evidence": True,
        "confirm_exact_revision": True,
    }
    data = _request(
        path=PUBLISH_ENDPOINT,
        root_token=root_token,
        method="POST",
        payload=payload,
        max_bytes=MAX_RESULT_BODY,
        opener=opener,
    )
    if not isinstance(data, dict) or (
        data.get("article_id") != article_id
        or data.get("article_status") != "published"
        or data.get("content_version") != content_version
        or data.get("editorial_decision") != "root_owner_publication"
        or data.get("scientific_verification") != "not_attested"
    ):
        raise EditorialTransportError("yfc_publication_receipt_invalid")
    canonical = data.get("canonical_url")
    if type(canonical) is not str:
        raise EditorialTransportError("yfc_publication_receipt_invalid")
    parsed = urlsplit(canonical)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"your-fitness-coach.ru", "app.your-fitness-coach.ru"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/articles/")
    ):
        raise EditorialTransportError("yfc_publication_receipt_invalid")
    return {
        "article_id": article_id,
        "content_version": content_version,
        "article_status": "published",
        "canonical_url": canonical,
        "editorial_decision": "root_owner_publication",
        "scientific_verification": "not_attested",
    }
