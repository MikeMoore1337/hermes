"""H-13: bounded offline Russian text hints, never a legal verdict."""
from __future__ import annotations
import argparse
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 65_536
MAX_FINDINGS = 24
SCHEMA = "hermes-h13-editorial-preflight-v1"
PROFILES = frozenset({"general", "legal"})
SUFFIXES = frozenset({".txt", ".md"})
PATTERNS = (
    ("LEGAL_NORM_REFERENCE_REVIEW", re.compile(
        r"(?iu)\b(?:Федеральн(?:ый|ого|ом|ому)\s+закон(?:а|е|у)?|\d{1,3}\s*[-–]?\s*ФЗ|"
        r"КоАП\s*РФ|ГК\s*РФ|стать(?:я|е|и|ёй|ю)\s+\d{1,4}\s+(?:КоАП|ГК|ФЗ))\b")),
    ("LEGAL_FINE_REVIEW", re.compile(
        r"(?iu)\bштраф(?:а|ов|ы|ом)?\b.{0,32}\b(?:до|от|руб(?:лей|ля)?)\b")),
    ("LEGAL_OBLIGATION_REVIEW", re.compile(
        r"(?iu)\b(?:обязан(?:а|ы|о)?|обязаны|обязательно)\b.{0,40}"
        r"\b(?:закон|сайт|оператор|пользовател|согласи)")),
    ("STYLE_FORMULAIC_INTRO", re.compile(
        r"(?iu)\b(?:на сегодняшний день|важно отметить,?\s+что|"
        r"следует отметить,?\s+что|в современном мире)\b")),
    ("STYLE_UNVERIFIED_ABSOLUTE", re.compile(
        r"(?iu)\b(?:гарантированно|стопроцентн(?:ая|ое|ый|о)|"
        r"100\s*%\s*(?:результат|эффект|гарантия))\b")),
)
URLS = re.compile(r"https?://[^\s<>\x60\"']+", re.I)
INLINE_CODE = re.compile(r"(?s)\x60[^\x60\n]*\x60")


class PreflightDenied(ValueError):
    """Fixed refusal code, never reveal user's draft or filename."""


def _mask_non_prose(text: str) -> str:
    fenced = False
    result = []
    for line in text.splitlines(keepends=True):
        if re.match(r"^\s{0,3}(\x60{3}|~~~)", line):
            fenced = not fenced
            result.append(" " * len(line))
        elif fenced or re.match(r"^\s{0,3}>", line):
            result.append(" " * len(line))
        else:
            result.append(line)
    return INLINE_CODE.sub(lambda m: " " * len(m.group()), "".join(result))


def _official_link_hint(text: str) -> bool:
    for m in URLS.finditer(text):
        try:
            parsed = urlsplit(m.group().rstrip(".,);]"))
            if (parsed.scheme == "https" and
                    parsed.hostname in ("pravo.gov.ru", "publication.pravo.gov.ru")
                    and parsed.username is None and parsed.password is None
                    and parsed.port in (None, 443)):
                return True
        except ValueError:
            continue
    return False


def review(text: str, *, profile: str = "general") -> dict[str, object]:
    if type(text) is not str or type(profile) is not str or profile not in PROFILES:
        raise PreflightDenied("input_invalid")
    try:
        size = len(text.encode("utf-8", "strict"))
    except UnicodeError:
        raise PreflightDenied("input_invalid") from None
    if (not 1 <= size <= MAX_BYTES or "\x00" in text
            or any(ord(c) < 32 and c not in "\n\r\t" for c in text)):
        raise PreflightDenied("input_invalid")
    masked = _mask_non_prose(text)
    hits = sorted(
        (m.start(), code) for code, pattern in PATTERNS
        for m in pattern.finditer(masked)
    )
    findings = [
        {"code": code, "offset": offset,
         "review": "MANUAL_LEGAL_SOURCE_CHECK" if code.startswith("LEGAL_")
                   else "OPTIONAL_EDITOR_REVIEW",
         "text_excerpt_included": False}
        for offset, code in hits[:MAX_FINDINGS]
    ]
    return {
        "schema": SCHEMA, "profile": profile,
        "status": "REVIEW_HINTS" if hits else "NO_FINDINGS_NOT_APPROVAL",
        "finding_total": len(hits), "findings": findings,
        "truncated": len(hits) > MAX_FINDINGS,
        "official_portal_link_seen_not_verified": _official_link_hint(masked),
        "legal_source_review_required": profile == "legal"
            or any(code.startswith("LEGAL_") for _, code in hits),
        "legal_compliance_verified": False, "current_legislation_verified": False,
        "scientific_claims_verified": False, "automatic_edits": False,
        "network_used": False, "llm_used": False,
        "publication_allowed": False, "personal_data_exported": False,
    }


def _read_file(name: str) -> str:
    if not name or "\x00" in name:
        raise PreflightDenied("file_not_admitted")
    path = Path(name)
    if not path.is_absolute() or path.suffix.lower() not in SUFFIXES:
        raise PreflightDenied("file_not_admitted")
    try:
        meta = path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or not 1 <= meta.st_size <= MAX_BYTES):
            raise PreflightDenied("file_not_admitted")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (meta.st_dev, meta.st_ino)):
                raise PreflightDenied("file_not_admitted")
            data = stream.read(MAX_BYTES + 1)
        if not 1 <= len(data) <= MAX_BYTES:
            raise PreflightDenied("file_not_admitted")
        return data.decode("utf-8", "strict")
    except (OSError, UnicodeError):
        raise PreflightDenied("file_not_admitted") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manual offline RU editorial hints")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--file")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="general")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "publication_allowed": False}))
        return 0
    try:
        if args.file is None:
            raise PreflightDenied("file_not_admitted")
        result = review(_read_file(args.file), profile=args.profile)
    except PreflightDenied as exc:
        print(json.dumps({"status": "DENIED", "reason": str(exc),
                          "publication_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
