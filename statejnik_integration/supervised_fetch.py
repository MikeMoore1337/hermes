"""Offline-gated, externally killable H12 HTTPS metadata fetch candidate.

This is deliberately NOT registered by runner, CLI, HTTP server or systemd.
Outer watchdog always kills the dedicated worker/process group at deadline,
including stuck libc DNS where a Python SIGALRM alone is insufficient.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from scripts.bounded_subprocess import BoundedProcessError, run_bounded
from .html_review import HtmlReviewDenied, _safe_field
from .network_boundary import NetworkDenied, target

WORKER = Path(__file__).resolve().with_name("_fetch_worker.py")
MAX_WALL_SECONDS = 20
MAX_STDOUT_BYTES = 8192
MAX_STDERR_BYTES = 2048


class SupervisedFetchDenied(ValueError):
    """Fixed reason codes only; never echo URLs, headers or HTML."""


def _command(url: str, allowed_hosts: frozenset[str]) -> list[str]:
    # Reject any query, embedded token, or credential-looking URL before
    # it could appear in an OS process command line.
    try:
        target(url, allowed_hosts)
    except NetworkDenied:
        raise SupervisedFetchDenied("url_not_admitted") from None
    if (len(url) > 512 or not url.isascii() or "?" in url
            or not WORKER.is_file()):
        raise SupervisedFetchDenied("url_not_admitted")
    return [sys.executable, "-I", "-B", str(WORKER), url, *sorted(allowed_hosts)]


def _verify_result(packet: Any, expected_url: str) -> dict[str, object]:
    if type(packet) is not dict or len(packet) > 16:
        raise SupervisedFetchDenied("worker_response_denied")
    if (packet.get("schema") != "hermes-h12-public-html-review-v1"
            or packet.get("status") != "MANUAL_REVIEW_REQUIRED"
            or packet.get("requested_url") != expected_url
            or packet.get("source_authenticity_verified") is not False
            or packet.get("final_redirect_url_verified") is not False
            or packet.get("search_demand_verified") is not False
            or packet.get("wordstat_volume") is not None
            or packet.get("publication_allowed") is not False
            or packet.get("yfc_write_allowed") is not False):
        raise SupervisedFetchDenied("worker_response_denied")
    page = packet.get("page")
    if (type(page) is not dict or page.get("url") != expected_url
            or any(type(page.get(k)) is not str
                   or not 0 < len(page[k]) <= 180 for k in ("title", "h1"))):
        raise SupervisedFetchDenied("worker_response_denied")
    try:
        if any(_safe_field(page[k]) != page[k] for k in ("title", "h1")):
            raise SupervisedFetchDenied("worker_response_denied")
    except HtmlReviewDenied:
        raise SupervisedFetchDenied("worker_response_denied") from None
    digest = packet.get("source_sha256")
    size = packet.get("source_bytes")
    if (type(digest) is not str or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
            or type(size) is not int or not 10 <= size <= 262144):
        raise SupervisedFetchDenied("worker_response_denied")
    # Return only the approved fields, not arbitrary child JSON.
    return {
        "schema": packet["schema"],
        "status": packet["status"],
        "requested_url": expected_url,
        "source_sha256": digest,
        "source_bytes": size,
        "page": {"url": expected_url, "title": page["title"], "h1": page["h1"]},
        "source_authenticity_verified": False,
        "final_redirect_url_verified": False,
        "search_demand_verified": False,
        "wordstat_volume": None,
        "publication_allowed": False,
        "yfc_write_allowed": False,
    }


def fetch_metadata(
    url: str, *,
    allowed_hosts: frozenset[str],
    network_authorized: bool = False,
) -> dict[str, object]:
    """Explicit candidate; defaults to deny before starting any subprocess.

    Only a parent-supervised OS process can initiate the HTTPS operation.
    Live network still requires a separately enforced egress firewall GO.
    """
    if network_authorized is not True:
        raise SupervisedFetchDenied("network_not_enabled")
    command = _command(url, allowed_hosts)
    try:
        completed = run_bounded(
            command, timeout=MAX_WALL_SECONDS, stdout_limit=MAX_STDOUT_BYTES,
            stderr_limit=MAX_STDERR_BYTES,
            env={"PATH": os.environ.get("PATH", ""),
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (BoundedProcessError, OSError):
        raise SupervisedFetchDenied("worker_timeout_or_failure") from None
    try:
        packet = json.loads(completed.stdout.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, AttributeError):
        raise SupervisedFetchDenied("worker_response_denied") from None
    return _verify_result(packet, url)
