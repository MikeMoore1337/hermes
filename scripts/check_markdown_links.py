"""H-16: deterministic Markdown-relative-link and heading-anchor checks.

No HTTP requests, paid tools, GitHub tokens, file writes or third-party deps.
The network status of external URLs is NOT inferred here.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_MARKDOWN_BYTES = 256_000
MAX_DIAGNOSTICS = 100
LINK = re.compile(r"\[[^\]\n]+\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
INLINE_CODE = re.compile(r"`[^`\n]*`")
INLINE_HTML = re.compile(r"<[^>]*>")


def _lines(text: str):
    """Only visible Markdown text outside fenced code and inline code."""
    fence_char = ""
    fence_length = 0
    for number, line in enumerate(text.splitlines(), 1):
        marker = FENCE.match(line)
        if marker:
            chars = marker.group(1)
            if not fence_char:
                fence_char, fence_length = chars[0], len(chars)
                continue
            if chars[0] == fence_char and len(chars) >= fence_length:
                fence_char, fence_length = "", 0
                continue
        if fence_char:
            continue
        clean = INLINE_CODE.sub("", line.split("<!--", 1)[0])
        yield number, clean


def _slug(title: str) -> str:
    title = INLINE_HTML.sub("", title)
    title = title.replace("`", "").replace("*", "").replace("_", "")
    title = title.strip().casefold()
    # Approximate GitHub heading slug for ordinary text; don't guess
    # whether a remote server serves an external anchor.
    title = "".join(c for c in title if
                    c in "-_ " or unicodedata.category(c)[0] in ("L", "N", "M"))
    return re.sub(r"\s+", "-", title)


def _anchors(text: str) -> set[str]:
    used: Counter[str] = Counter()
    anchors: set[str] = set()
    for _, line in _lines(text):
        match = HEADING.match(line)
        if match:
            key = _slug(match.group(1))
            suffix = used[key]
            used[key] += 1
            anchors.add(key if suffix == 0 else f"{key}-{suffix}")
    return anchors


def check(root: Path) -> list[str]:
    """Check local Markdown links without dereferencing paths outside root."""
    root = root.resolve(strict=True)
    problems: list[str] = []
    for doc in sorted(root.rglob("*.md")):
        if len(problems) >= MAX_DIAGNOSTICS:
            break
        relative = doc.relative_to(root).as_posix()
        if doc.is_symlink() or not doc.is_file():
            problems.append(f"{relative}:0:unsafe_document")
            continue
        try:
            if doc.stat().st_size > MAX_MARKDOWN_BYTES:
                problems.append(f"{relative}:0:markdown_oversize")
                continue
            text = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            problems.append(f"{relative}:0:markdown_unavailable")
            continue
        for number, line in _lines(text):
            for match in LINK.finditer(line):
                raw = match.group(1).strip("<>")
                # Remote link validation is separate and must not run in CI.
                url = urlsplit(raw)
                if url.scheme.lower() in ("http", "https", "mailto") or url.netloc:
                    continue
                if url.scheme or raw.startswith("/") or "\\" in raw:
                    problems.append(f"{relative}:{number}:unsafe_local_link")
                    continue
                path = unquote(url.path)
                anchor = unquote(url.fragment)
                target = doc if not path else doc.parent / path
                try:
                    resolved = target.resolve(strict=False)
                    if not resolved.is_relative_to(root):
                        problems.append(f"{relative}:{number}:link_outside_repository")
                        continue
                    if not resolved.exists():
                        problems.append(f"{relative}:{number}:missing_local_target")
                        continue
                    if anchor and (not resolved.is_file()
                                   or anchor not in _anchors(resolved.read_text(encoding="utf-8"))):
                        problems.append(f"{relative}:{number}:missing_local_anchor")
                except (OSError, UnicodeError, ValueError):
                    problems.append(f"{relative}:{number}:target_unavailable")
                if len(problems) >= MAX_DIAGNOSTICS:
                    return problems
    return problems


def main() -> int:
    failures = check(ROOT)
    for item in failures:
        print("FAIL:", item)
    if failures:
        return 1
    print("PASS: local Markdown targets and anchors; external HTTP not checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
