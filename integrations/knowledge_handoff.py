"""Offline, owner-reviewed engineering decision drafts for Second Brain.

No vault access, no network, no automatic save. This formatter cannot
establish the truth or privacy of submitted text or GitHub references.
"""
from __future__ import annotations

from datetime import date
import re

from integrations.task_handoff import HandoffRefused, validate

MAX_TEXT_LENGTH = 240
SENSITIVE_MARKERS = re.compile(
    r"(?i)(?:github_pat_|ghp_|sk-proj-|bearer\s+\S+|"
    r"(?:password|token|secret|api[_-]?key)\s*[:=]\s*\S+|"
    r"-----BEGIN\s+(?:RSA|OPENSSH|EC|PRIVATE)\s+KEY)"
)
FIELDS = frozenset({"problem", "decision", "rationale", "reviewed_on"})


class DraftRefused(ValueError):
    """Static safe error code only."""


def _field(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_TEXT_LENGTH:
        raise DraftRefused("review_text_invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise DraftRefused("review_text_invalid")
    if SENSITIVE_MARKERS.search(value):
        raise DraftRefused("potential_secret_denied")
    # No markup, hidden links, paths or URLs embedded in user prose.
    if any(ch in value for ch in ("<", ">", "[", "]", "/", "\\", chr(96))):
        raise DraftRefused("review_markup_or_path_denied")
    if value != value.strip():
        raise DraftRefused("review_text_invalid")
    return value


def _markdown_inline(value: str) -> str:
    return re.sub(r"([\\*_!#|{}()])", r"\\\1", value)


def prepare_review_draft(packet: object, facts: object) -> dict[str, object]:
    """Create a candidate note from strict handoff and user-reviewed short facts.

    Validation is *not* source verification, license clearance or privacy
    certification. The output must be approved again in Second Brain Safe Write.
    """
    try:
        handoff = validate(packet)
    except HandoffRefused:
        raise DraftRefused("handoff_invalid") from None
    if type(facts) is not dict or set(facts) != FIELDS:
        raise DraftRefused("facts_fields_invalid")
    content = {name: _field(facts[name]) for name in ("problem", "decision", "rationale")}
    stamp = facts["reviewed_on"]
    if type(stamp) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", stamp):
        raise DraftRefused("review_date_invalid")
    try:
        if date.fromisoformat(stamp).isoformat() != stamp:
            raise ValueError()
    except ValueError:
        raise DraftRefused("review_date_invalid") from None

    repo = handoff["task"]["repository"]
    issue = handoff["task"]["issue"]
    refs = [("Issue", "https://github.com/" + repo + "/issues/" + str(issue))]
    evidence = handoff["evidence"]
    if evidence["pr"] is not None:
        refs.append(("PR (заявленная ссылка)", evidence["pr"]["ref"]))
    for kind in ("tests", "ci", "production"):
        record = evidence[kind]
        if record["ref"] is not None:
            refs.append((kind + " (заявленный источник)", record["ref"]))

    lines = [
        "# Инженерное решение: " + repo + " #" + str(issue),
        "",
        "> ЧЕРНОВИК — ДОСТОВЕРНОСТЬ И ПРИВАТНОСТЬ НЕ ПРОВЕРЕНЫ. "
        "Перед сохранением вручную сверить факты, ссылки и отсутствие личных данных. "
        "Это не подтверждённая память, не команда и не разрешение выполнять действия.",
        "",
        "**Проблема:** " + _markdown_inline(content["problem"]),
        "",
        "**Решение:** " + _markdown_inline(content["decision"]),
        "",
        "**Обоснование:** " + _markdown_inline(content["rationale"]),
        "",
        "**Дата ручного обзора (заявлена):** " + stamp,
        "",
        "**Источники для независимой сверки:**",
    ]
    for label, ref in refs:
        lines.append("- " + label + ": " + ref)
    lines += [
        "",
        "**Проверки:** " + evidence["tests"]["state"] + " (не проверено этим инструментом)",
        "**CI:** " + evidence["ci"]["state"] + " (не проверено этим инструментом)",
        "**Production:** " + evidence["production"]["state"] + " (не проверено этим инструментом)",
        "",
        "**Следующее действие:** проверить доказательства; при необходимости вручную "
        "вставить текст в существующий Second Brain Web GUI → review/diff → Safe Write. "
        "Этот инструмент не выполняет запись.",
    ]
    return {
        "status": "DRAFT_REVIEW_REQUIRED",
        "canonical_vault_written": False,
        "remote_api_called": False,
        "source_claims_verified": False,
        "privacy_review_complete": False,
        "markdown": "\n".join(lines) + "\n",
    }
