"""Suggest manual checks for public synthetic science copy, never a legal verdict.

This never edits text, accesses URLs, checks statutes or publishes.
"""
from __future__ import annotations
import json
import re
from typing import Any

SCHEMA = "hermes-h13-public-draft-v1"
RESULT = "hermes-h13-review-candidates-v1"
SOURCE_ID = re.compile(r"S[1-9][0-9]{0,2}")
CITATION = re.compile(r"\[ref:(S[1-9][0-9]{0,2})\]")
QUANTITY = re.compile(r"(?<!\w)\d+(?:[.,]\d+)?\s*%")
MEDICAL = re.compile(
    r"\b(?:гарантированно\s+(?:лечит|вылечит)"
    r"|полностью\s+безопас(?:ен|на|но|ны)"
    r"|не\s+(?:имеет|имеют)\s+побочных\s+эффектов)\b", re.I
)
LEGAL = re.compile(r"\b(?:нарушает\s+закон|штраф\s+составит|полностью\s+соответствует\s+закону)\b", re.I)

class EditorialReviewError(ValueError):
    """Unexpected or unsafe input is rejected, not reinterpreted."""

def review(data: Any) -> dict[str, Any]:
    if type(data) is not dict or set(data) != {"schema", "visibility", "kind", "text", "source_ids"}:
        raise EditorialReviewError("input_schema_invalid")
    if data["schema"] != SCHEMA or data["visibility"] != "PUBLIC_SYNTHETIC" or data["kind"] != "scientific_draft":
        raise EditorialReviewError("scope_not_allowed")
    text, refs = data["text"], data["source_ids"]
    if type(text) is not str or not 1 <= len(text) <= 8192 or any(ord(c) < 32 and c not in "\n\t" for c in text):
        raise EditorialReviewError("text_invalid")
    if type(refs) is not list or len(refs) > 30 or any(type(ref) is not str or not SOURCE_ID.fullmatch(ref) for ref in refs) or len(refs) != len(set(refs)):
        raise EditorialReviewError("sources_invalid")
    issues: list[dict[str, object]] = []
    body, in_code = [], False
    for line in text.splitlines():
        if line.strip().startswith(chr(96)*3):
            in_code = not in_code
            continue
        if not in_code:
            body.append(line)
    if in_code:
        raise EditorialReviewError("unfinished_code_fence")
    sentences = re.split(r"(?<=[.!?])\s+", "\n".join(body))
    for number, sentence in enumerate(sentences, start=1):
        cited = set(CITATION.findall(sentence))
        if any(source not in refs for source in cited):
            issues.append({"sentence": number, "code": "UNKNOWN_CITATION", "requires": "EDITOR_REVIEW"})
        if QUANTITY.search(sentence) and not (cited & set(refs)):
            issues.append({"sentence": number, "code": "QUANTITY_WITHOUT_CITATION", "requires": "EDITOR_REVIEW"})
        if MEDICAL.search(sentence):
            issues.append({"sentence": number, "code": "MEDICAL_ABSOLUTE_CLAIM", "requires": "EXPERT_REVIEW"})
        if LEGAL.search(sentence):
            issues.append({"sentence": number, "code": "LEGAL_ASSERTION", "requires": "LAWYER_REVIEW"})
    return {
        "schema": RESULT, "mode": "OFFLINE_PUBLIC_SYNTHETIC_ONLY",
        "status": "MANUAL_REVIEW_REQUIRED" if issues else "NO_FLAGS_NOT_APPROVAL",
        "findings": issues, "source_content_verified": False,
        "legal_compliance_verified": False, "medical_accuracy_verified": False,
        "original_text_modified": False, "publication_allowed": False,
        "network_calls": 0,
    }

def main() -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Offline H-13 candidate checks (never legal advice)")
    parser.add_argument("--stdin", action="store_true", required=True)
    parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise EditorialReviewError("input_too_large")
        result = review(json.loads(raw))
    except (EditorialReviewError, ValueError, TypeError):
        print(json.dumps({"status": "REJECTED", "reason": "invalid_public_draft"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
