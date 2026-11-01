"""Fail-closed GitHub event observations, without scheduling or executing agents.

The existing H-04 QA Advisor remains the sole CI polling client. This module
receives GitHub Actions event files only; it never calls GitHub or a model.
No response field grants authority to perform the suggested operation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from qa_advisor.signal_store import REPO, WORKFLOW

SCHEMA = "hermes-github-event-observe-v1"
MAX_EVENT_BYTES = 1_048_576
CI_WORKFLOW_ID = int(WORKFLOW.removeprefix("workflow-"))
MAX_ID = 10**18
SHA = re.compile(r"[0-9a-f]{40}\Z")
EVENT_ACTIONS = {
    "issues": frozenset({"opened", "reopened"}),
    "issue_comment": frozenset({"created"}),
    "pull_request_target": frozenset({"opened", "reopened", "synchronize", "ready_for_review"}),
    "workflow_run": frozenset({"completed"}),
}
CI_CONCLUSIONS = frozenset({
    "success", "failure", "cancelled", "timed_out", "startup_failure",
    "neutral", "skipped", "action_required",
})


class ObserveRefused(ValueError):
    """Fixed codes only, without untrusted event values."""


def _object(value: object, code: str) -> dict:
    if type(value) is not dict:
        raise ObserveRefused(code)
    return value


def _id(value: object, code: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_ID:
        raise ObserveRefused(code)
    return value


def _sha(value: object) -> str:
    if type(value) is not str or not SHA.fullmatch(value):
        raise ObserveRefused("event_sha_invalid")
    return value


def load_event(path: Path) -> dict:
    """Read only one bounded regular file; never follow a symbolic link."""
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ObserveRefused("event_file_unsafe")
    try:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_EVENT_BYTES:
            raise ObserveRefused("event_file_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_EVENT_BYTES:
                raise ObserveRefused("event_file_unsafe")
            raw = stream.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            raise ObserveRefused("event_file_unsafe")
        data = json.loads(raw)
    except ObserveRefused:
        raise
    except (OSError, UnicodeError, ValueError):
        raise ObserveRefused("event_file_unreadable") from None
    return _object(data, "event_shape_invalid")


def observe(event_type: str, payload: object, *, delivery_run_id: int) -> dict:
    """Classify an event as a suggestion, never as executable authority.

    The observation key is stable for a workflow rerun of the same GitHub
    Actions run_id. It is NOT persistent deduplication across separate runs.
    """
    _id(delivery_run_id, "delivery_id_invalid")
    if type(event_type) is not str or event_type not in EVENT_ACTIONS:
        raise ObserveRefused("event_type_denied")
    body = _object(payload, "event_shape_invalid")
    source = _object(body.get("repository"), "repository_missing")
    if source.get("full_name") != REPO:
        raise ObserveRefused("repository_denied")
    action = body.get("action")
    if type(action) is not str or action not in EVENT_ACTIONS[event_type]:
        raise ObserveRefused("event_action_denied")

    if event_type == "issues":
        item = _object(body.get("issue"), "issue_missing")
        subject_type, number = "issue", _id(item.get("number"), "issue_number_invalid")
        source_id = _id(item.get("id"), "issue_id_invalid")
        candidate, reason = "REVIEW_ISSUE", "ISSUE_OPENED_OR_REOPENED"
        version = action
    elif event_type == "issue_comment":
        issue = _object(body.get("issue"), "issue_missing")
        comment = _object(body.get("comment"), "comment_missing")
        number = _id(issue.get("number"), "issue_number_invalid")
        source_id = _id(comment.get("id"), "comment_id_invalid")
        subject_type = "pr_comment" if "pull_request" in issue else "issue_comment"
        candidate, reason = "REVIEW_FOLLOWUP", "NEW_CONTEXT_NOT_AUTHORITY"
        version = action
    elif event_type == "pull_request_target":
        item = _object(body.get("pull_request"), "pr_missing")
        number = _id(item.get("number"), "pr_number_invalid")
        source_id = _id(item.get("id"), "pr_id_invalid")
        base = _object(item.get("base"), "pr_base_invalid")
        base_repo = _object(base.get("repo"), "pr_base_invalid")
        if base.get("ref") != "main" or base_repo.get("full_name") != REPO:
            raise ObserveRefused("pr_base_denied")
        head = _object(item.get("head"), "pr_head_invalid")
        version = _sha(head.get("sha"))
        subject_type = "pull_request"
        candidate, reason = "REVIEW_PR", "PR_STATE_CHANGED"
    else:
        item = _object(body.get("workflow_run"), "workflow_run_missing")
        number = source_id = _id(item.get("id"), "workflow_run_id_invalid")
        if (item.get("workflow_id") != CI_WORKFLOW_ID
                or type(item.get("workflow_id")) is not int
                or item.get("event") != "push"
                or item.get("head_branch") != "main"
                or item.get("status") != "completed"):
            raise ObserveRefused("workflow_scope_denied")
        version = _sha(item.get("head_sha"))
        conclusion = item.get("conclusion")
        if type(conclusion) is not str or conclusion not in CI_CONCLUSIONS:
            raise ObserveRefused("workflow_conclusion_denied")
        subject_type = "ci_run"
        if conclusion == "success":
            candidate, reason = "NONE", "QUALITY_CI_SUCCESS"
        elif conclusion in {"failure", "startup_failure", "timed_out"}:
            candidate, reason = "REVIEW_CI_FAILURE", "QUALITY_CI_FAILED"
        else:
            candidate, reason = "REVIEW_CI_UNCERTAIN", "QUALITY_CI_NOT_PROVEN"

    identity = f"{REPO}:{event_type}:{action}:{source_id}:{version}:{delivery_run_id}"
    return {
        "schema": SCHEMA,
        "mode": "OBSERVE_ONLY",
        "repo": REPO,
        "event_type": event_type,
        "action": action,
        "subject_type": subject_type,
        "subject_number": number,
        "observation_key": hashlib.sha256(identity.encode("ascii")).hexdigest()[:24],
        "candidate": candidate,
        "reason": reason,
        "decision": "WOULD_REVIEW" if candidate != "NONE" else "NO_REVIEW",
        "source_trust": "UNTRUSTED_EVENT_CONTEXT",
        "evidence": "GITHUB_ACTIONS_EVENT_SHAPE_ONLY",
        "dedup": "KEY_ONLY_NO_DURABLE_STATE",
        "owner_approval": "NOT_GRANTED",
        "action_authorized": False,
        "execution_authorized": False,
        "outbound_messages": 0,
        "model_calls": 0,
        "external_requests": 0,
        "state_writes": 0,
    }


# The report contains no user-supplied title, body, comment, URL or instruction.
# Destination URLs are reconstructed from the already-validated numeric subject.
REVIEW_LABELS = {
    "REVIEW_ISSUE": "Проверить задачу",
    "REVIEW_FOLLOWUP": "Проверить новое обсуждение",
    "REVIEW_PR": "Проверить PR",
    "REVIEW_CI_FAILURE": "Разобрать сбой CI",
    "REVIEW_CI_UNCERTAIN": "Проверить неопределённый результат CI",
    "NONE": "Проверка не требуется",
}
SUBJECT_NAMES = {
    "issue": ("Issue", "issues"),
    "issue_comment": ("Issue", "issues"),
    "pr_comment": ("PR", "pull"),
    "pull_request": ("PR", "pull"),
    "ci_run": ("CI", "actions/runs"),
}


def render_summary(report: object) -> str:
    """Safe, human-readable GitHub Actions Summary; not an executable mandate."""
    data = _object(report, "summary_invalid")
    kind, candidate, number = (
        data.get("subject_type"), data.get("candidate"), data.get("subject_number")
    )
    if (data.get("schema") != SCHEMA or data.get("mode") != "OBSERVE_ONLY"
            or data.get("repo") != REPO
            or type(kind) is not str or kind not in SUBJECT_NAMES
            or type(candidate) is not str or candidate not in REVIEW_LABELS
            or type(number) is not int or not 1 <= number <= MAX_ID
            or data.get("action_authorized") is not False
            or data.get("execution_authorized") is not False
            or data.get("owner_approval") != "NOT_GRANTED"
            or data.get("source_trust") != "UNTRUSTED_EVENT_CONTEXT"):
        raise ObserveRefused("summary_invalid")
    category, path = SUBJECT_NAMES[kind]
    url = f"https://github.com/{REPO}/{path}/{number}"
    verdict = "Нужна проверка" if candidate != "NONE" else "Без действий"
    tick = chr(96)
    # URL components are constants or a strictly validated positive integer.
    # No untrusted strings are interpolated into Markdown.
    return "\n".join((
        "### Hermes · Наблюдение GitHub",
        "",
        f"**{verdict}** · {REVIEW_LABELS[candidate]}",
        "",
        f"- Источник: [{category} #{number}]({url})",
        f"- Предложение: {tick}{candidate}{tick}",
        f"- Режим: {tick}OBSERVE_ONLY{tick}, только информация",
        "- Разрешения на запуск или запись: **не выдавались**",
        "- Решение принимает владелец после проверки источника и полномочий.",
        "",
    ))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GitHub event observer (no execution)")
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--summary", action="store_true", help="Safe GitHub Actions Markdown")
    parser.add_argument("--event", choices=sorted(EVENT_ACTIONS))
    parser.add_argument("--event-file", type=Path)
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    if not args.observe:
        print(json.dumps({"status": "NOT_EXECUTED", "mode": "OBSERVE_ONLY"}))
        return 0
    try:
        if os.environ.get("GITHUB_REPOSITORY") not in (None, REPO):
            raise ObserveRefused("repository_denied")
        name = args.event or os.environ.get("GITHUB_EVENT_NAME")
        path = args.event_file or Path(os.environ.get("GITHUB_EVENT_PATH", ""))
        run_id = args.run_id if args.run_id is not None else int(
            os.environ.get("GITHUB_RUN_ID", "0")
        )
        result = observe(name, load_event(path), delivery_run_id=run_id)
    except ObserveRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc),
                          "execution_authorized": False, "model_calls": 0}))
        return 2
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "REFUSED", "reason": "observation_unavailable",
                          "execution_authorized": False, "model_calls": 0}))
        return 2
    print(render_summary(result) if args.summary else json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
