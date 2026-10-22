"""H-478: deterministic comparison of PUBLIC_SYNTHETIC Russian science drafts.

No external evidence, model, edits or publishing. Existing editorial_review
remains the authority for its already supported warning categories.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any

from editorial_review.public_draft import (
    SCHEMA as DRAFT_SCHEMA, EditorialReviewError, review as review_public,
)

SCHEMA = "hermes-h478-editorial-pair-v1"
RESULT_SCHEMA = "hermes-h478-editorial-rubric-v1"
MAX_TEXT = 8192
CITATION = re.compile(r"\[ref:(S[1-9][0-9]{0,2})\]")
DOI = re.compile(r"(?i)\b10\.[0-9]{4,9}/[^\s\]\[<>),;]+")
PMID = re.compile(r"(?i)\bPMID\s*:?\s*[0-9]{4,10}\b")
NUMBER = re.compile(r"(?<!\w)[0-9]+(?:[.,][0-9]+)?(?!\w)")
URL = re.compile(r"(?i)https?://[^\s\]\[<>),;]+")
NEGATION = re.compile(r"(?iu)\bне\b")
EPISTEMIC = re.compile(
    r"(?iu)\b(?:возможно|вероятно|предварительн(?:ый|ая|ое|ые|о)|"
    r"может|могут|некоторые|часть|все|каждый|только|лишь|предположительно)\b"
)
POPULATION = re.compile(
    r"(?iu)\b(?:взрослые|дети|подростки|животные|мыши|крысы|"
    r"пациенты|спортсмены|женщины|мужчины)\b"
)
CAUSAL = re.compile(
    r"(?iu)\b(?:доказали|доказал|доказано|доказывает|гарантирует|"
    r"приводит\s+к|вызывает|излечивает|лечит|устраняет)\b"
)
TEMPLATES = (
    re.compile(r"(?iu)\bважно\s+отметить,?\s+что\b"),
    re.compile(r"(?iu)\bна\s+сегодняшний\s+день\b"),
    re.compile(r"(?iu)\bв\s+современном\s+мире\b"),
    re.compile(r"(?iu)\bследует\s+отметить,?\s+что\b"),
)
UNSAFE_CODES = frozenset({
    "UNKNOWN_CITATION", "QUANTITY_WITHOUT_CITATION",
    "MEDICAL_ABSOLUTE_CLAIM", "LEGAL_ASSERTION",
})


class ComparisonError(ValueError):
    """Fixed denial code, never echo submitted text."""


def _text(value: Any) -> str:
    if type(value) is not str:
        raise ComparisonError("invalid_synthetic_text")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError:
        raise ComparisonError("invalid_synthetic_text") from None
    if (not 1 <= size <= MAX_TEXT or "\x00" in value
            or chr(96) * 3 in value or "~~~" in value
            or any(ord(ch) < 32 and ch not in "\n\t" for ch in value)):
        raise ComparisonError("invalid_synthetic_text")
    return value


def _tokens(text: str) -> dict[str, Counter]:
    citations = Counter(CITATION.findall(text))
    if text.count("[ref:") != sum(citations.values()):
        raise ComparisonError("malformed_citation")
    dois = Counter(match.group(0).rstrip(".").casefold() for match in DOI.finditer(text))
    pmids = Counter(re.sub(r"\s+", "", match.group(0)).casefold() for match in PMID.finditer(text))
    remaining = CITATION.sub(" ", text)
    remaining = DOI.sub(" ", remaining)
    remaining = PMID.sub(" ", remaining)
    return {
        "citations": citations,
        "doi": dois,
        "pmid": pmids,
        "numbers": Counter(NUMBER.findall(remaining)),
    }


def _duplicate_sentences(text: str) -> int:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    normalized = [re.sub(r"\s+", " ", part).strip().casefold()
                  for part in parts if part.strip()]
    values = Counter(normalized)
    return sum(count - 1 for count in values.values() if count > 1)


def _template_count(text: str) -> int:
    return sum(len(pattern.findall(text)) for pattern in TEMPLATES)


def _distinct_sentence_markers(text: str, pattern: re.Pattern) -> Counter:
    """Allow removing exact duplicate prose, not dropping a protected marker."""
    unique = {
        re.sub(r"\s+", " ",part).strip().casefold()
        for part in re.split(r"(?<=[.!?])\s+|\n+", text)
        if part.strip()
    }
    return Counter(
        match.group(0).casefold().rstrip(".")
        for sentence in unique for match in pattern.finditer(sentence)
    )


def compare(payload: Any) -> dict[str, Any]:
    """Compare two supplied synthetic drafts; never select a new truth."""
    if (type(payload) is not dict
            or set(payload) != {"schema", "visibility", "kind",
                                "source_ids", "original", "candidate"}
            or payload["schema"] != SCHEMA
            or payload["visibility"] != "PUBLIC_SYNTHETIC"
            or payload["kind"] != "scientific_draft"):
        raise ComparisonError("scope_or_schema_invalid")
    original = _text(payload["original"])
    candidate = _text(payload["candidate"])
    sources = payload["source_ids"]
    if type(sources) is not list:
        raise ComparisonError("source_ids_invalid")
    try:
        before = review_public({
            "schema": DRAFT_SCHEMA, "visibility": "PUBLIC_SYNTHETIC",
            "kind": "scientific_draft", "source_ids": sources, "text": original,
        })
        after = review_public({
            "schema": DRAFT_SCHEMA, "visibility": "PUBLIC_SYNTHETIC",
            "kind": "scientific_draft", "source_ids": sources, "text": candidate,
        })
    except EditorialReviewError:
        raise ComparisonError("draft_contract_invalid") from None

    original_tokens = _tokens(original)
    candidate_tokens = _tokens(candidate)
    original_issues = Counter(item["code"] for item in before["findings"])
    candidate_issues = Counter(item["code"] for item in after["findings"])
    refusals: list[str] = []
    for field, reason in (
        ("citations", "CITATIONS_CHANGED"),
        ("doi", "DOI_CHANGED"),
        ("pmid", "PMID_CHANGED"),
        ("numbers", "NUMERIC_FACTS_CHANGED"),
    ):
        if original_tokens[field] != candidate_tokens[field]:
            refusals.append(reason)
    if original_issues["UNKNOWN_CITATION"] or candidate_issues["UNKNOWN_CITATION"]:
        refusals.append("UNKNOWN_CITATION")
    if any(candidate_issues[code] > original_issues[code] for code in UNSAFE_CODES):
        refusals.append("NEW_EDITORIAL_RISK")
    if _distinct_sentence_markers(original, NEGATION) != _distinct_sentence_markers(candidate, NEGATION):
        refusals.append("NEGATION_CHANGED")
    # A repeated identical sentence may be removed safely, but a changed
    # qualifier, population or source URL must not be silently accepted.
    for pattern, reason in (
        (EPISTEMIC, "EPISTEMIC_QUALIFIER_CHANGED"),
        (POPULATION, "STUDY_POPULATION_CHANGED"),
        (URL, "SOURCE_URL_CHANGED"),
    ):
        if pattern is URL:
            original_markers = Counter(x.casefold().rstrip(".") for x in pattern.findall(original))
            candidate_markers = Counter(x.casefold().rstrip(".") for x in pattern.findall(candidate))
        else:
            original_markers = _distinct_sentence_markers(original, pattern)
            candidate_markers = _distinct_sentence_markers(candidate, pattern)
        if original_markers != candidate_markers:
            refusals.append(reason)
    if len(CAUSAL.findall(candidate)) > len(CAUSAL.findall(original)):
        refusals.append("UNSUPPORTED_CAUSALITY_ADDED")

    before_formulas, after_formulas = _template_count(original), _template_count(candidate)
    before_repeats, after_repeats = (
        _duplicate_sentences(original), _duplicate_sentences(candidate)
    )
    signals = []
    if after_formulas < before_formulas:
        signals.append("FEWER_TEMPLATE_PHRASES")
    if after_repeats < before_repeats:
        signals.append("FEWER_EXACT_REPETITIONS")

    status = ("REFUSED" if refusals else
              "REVIEW_CANDIDATE" if signals and original != candidate else
              "NO_CHANGE")
    return {
        "schema": RESULT_SCHEMA,
        "status": status,
        "refusals": sorted(set(refusals)),
        "signals": signals if not refusals else [],
        "rubric": {
            "template_phrases_before": before_formulas,
            "template_phrases_after": after_formulas,
            "repeated_sentences_before": before_repeats,
            "repeated_sentences_after": after_repeats,
        },
        "source_content_verified": False,
        "scientific_facts_verified": False,
        "citation_sentence_alignment_verified": False,
        "author_voice_verified": False,
        "independent_expert_blind_review": "NOT_RUN",
        "decision_is_advisory": True,
        "automatic_replacement": False,
        "publication_allowed": False,
        "network_calls": 0,
        "model_calls": 0,
    }
