"""Strict admission for vendor Statejnik's local `site.py gap` subcommand.

Only fixed filenames from an explicitly admitted workspace. This adapter
never scrapes a site, contacts Wordstat, reads external folders or publishes.
Unverified demand, reach or scientific correctness must not be inferred.
"""
from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path

MAX_BYTES = 256 * 1024
MAX_PAGES = 250
MAX_PHRASES = 300


class OfflineGapDenied(ValueError):
    """Stable reason code; never echo paths or user-authored SEO text."""


def _text(value: object, max_length: int) -> bool:
    return (type(value) is str and 0 < len(value) <= max_length
            and all(ord(c) >= 32 and ord(c) != 127 and c not in "|\\"
                    for c in value))


def _read(workspace: Path, filename: str) -> object:
    path = workspace / filename
    if path.is_symlink():
        raise OfflineGapDenied("gap_input_unsafe")
    try:
        info = path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > MAX_BYTES or info.st_size < 2):
            raise OfflineGapDenied("gap_input_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                raise OfflineGapDenied("gap_input_unsafe")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise OfflineGapDenied("gap_input_unsafe")
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise OfflineGapDenied("gap_input_invalid") from None


def _site(doc: object) -> None:
    if type(doc) is not dict or len(doc) > 16:
        raise OfflineGapDenied("gap_site_invalid")
    if "url" in doc and not _text(doc["url"], 260):
        raise OfflineGapDenied("gap_site_invalid")
    for field in ("pages", "urls", "article_urls", "article_sections"):
        values = doc.get(field, [])
        if type(values) is not list or len(values) > MAX_PAGES:
            raise OfflineGapDenied("gap_site_invalid")
        if field in ("urls", "article_urls"):
            if any(not _text(v, 260) for v in values):
                raise OfflineGapDenied("gap_site_invalid")
        elif field == "pages":
            for page in values:
                if type(page) is not dict or len(page) > 18:
                    raise OfflineGapDenied("gap_site_invalid")
                if any(not _text(v, 300) for k, v in page.items()
                       if k in ("url", "title", "heading", "h1", "kind", "og_title")
                       and v != ""):
                    raise OfflineGapDenied("gap_site_invalid")
                if not _text(page.get("url"), 260):
                    raise OfflineGapDenied("gap_site_invalid")
        else:
            for section in values:
                if (type(section) is not dict or
                        not _text(section.get("path"), 200)):
                    raise OfflineGapDenied("gap_site_invalid")


def _keywords(doc: object) -> None:
    if type(doc) is not list or not 1 <= len(doc) <= MAX_PHRASES:
        raise OfflineGapDenied("gap_keywords_invalid")
    for item in doc:
        if type(item) is not dict or len(item) > 14:
            raise OfflineGapDenied("gap_keywords_invalid")
        if not _text(item.get("phrase"), 120):
            raise OfflineGapDenied("gap_keywords_invalid")
        for key in ("cluster", "article_type"):
            if key in item and item[key] is not None and not _text(item[key], 120):
                raise OfflineGapDenied("gap_keywords_invalid")
        # Real Wordstat counts are NOT admitted from arbitrary JSON. This
        # workflow handles only operator-supplied synthetic/unverified phrases.
        count = item.get("count")
        if count is not None and (type(count) is not int or count != 0):
            raise OfflineGapDenied("gap_unverified_volume_denied")
        if "sources" in item:
            if item["sources"] != []:
                raise OfflineGapDenied("gap_unverified_sources_denied")
        if "article_fit" in item:
            fit = item["article_fit"]
            if type(fit) not in (int, float) or not math.isfinite(fit) or not 0 <= fit <= 1:
                raise OfflineGapDenied("gap_keywords_invalid")


def admit(workspace: Path) -> list[str]:
    """Return FIXED vendor arguments, with no user-supplied path or switches."""
    if not isinstance(workspace, Path) or not workspace.is_dir() or workspace.is_symlink():
        raise OfflineGapDenied("gap_workspace_invalid")
    expected = {".hermes-statejnik-offline", "site.json", "keywords.json"}
    try:
        if {p.name for p in workspace.iterdir()} != expected:
            raise OfflineGapDenied("gap_workspace_extra_files")
    except OSError:
        raise OfflineGapDenied("gap_workspace_invalid") from None
    _site(_read(workspace, "site.json"))
    _keywords(_read(workspace, "keywords.json"))
    return ["gap", "site.json", "keywords.json", "--out", "gap.json",
            "--plan", "plan.md", "--top", "25"]


def catalog() -> dict[str, object]:
    return {
        "status": "OFFLINE_SITE_GAP_READY_WITH_INPUTS",
        "command": "site-gap",
        "source_file": "site.py gap",
        "input_files": ["site.json", "keywords.json"],
        "outputs": ["gap.json", "plan.md"],
        "read_only_network": True,
        "network_enabled": False,
        "wordstat_verified": False,
        "measured_search_volumes": False,
        "scientific_claims_verified": False,
        "publication_allowed": False,
        "resident_agent_allowed": False,
    }
