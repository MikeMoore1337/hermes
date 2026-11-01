"""Bounded GitHub Observe feed for existing QA watcher and Operator Inbox.

This is a projection of GitHub Actions *run metadata*, not a transport of
trusted agent instructions. Uses existing Actions:read credential and state
directory; no new service, agent, database or privileged API endpoint.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from qa_advisor.github_event_observe import EVENT_ACTIONS, CI_CONCLUSIONS
from qa_advisor.github_public import get_json, _private_token, TOKEN_FILE
from qa_advisor.signal_store import DIR, REPO, _dir

SCHEMA = "hermes-gh-observe-inbox-v1"
OBSERVE_WORKFLOW_ID = 403765637  # Verified original Actions workflow, not quality.yml.
OBSERVE_WORKFLOW = "Hermes GitHub event observe (no executor)"
FILE = "github-observe-inbox.json"
MAX_RUNS = 12
MAX_EVENTS = 10
MAX_ID = 10**18
MAX_BYTES = 8192
MAX_AGE = timedelta(minutes=45)
WINDOW = timedelta(hours=24)
SKEW = timedelta(minutes=2)
TITLE = re.compile(
    r"observe:(issues|issue_comment|pull_request_target|workflow_run):"
    r"(opened|reopened|created|synchronize|ready_for_review|completed):"
    r"([1-9][0-9]{0,17}):(none|success|failure|cancelled|timed_out|startup_failure|neutral|skipped|action_required):"
    r"([1-9][0-9]{0,17})\Z"
)
API_PATH = (
    f"/repos/{REPO}/actions/workflows/{OBSERVE_WORKFLOW_ID}/runs?"
    f"per_page={MAX_RUNS}"
)


class FeedRefused(ValueError):
    """Constant codes only. Raw GitHub responses never enter diagnostics."""


def utc(value: object) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise FeedRefused("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FeedRefused("timestamp_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise FeedRefused("timestamp_invalid")
    return parsed.astimezone(UTC)


def _ident(number: object) -> int:
    if type(number) is not int or not 1 <= number <= MAX_ID:
        raise FeedRefused("id_invalid")
    return number


def _candidate(kind: str, action: str, outcome: str) -> str:
    if kind not in EVENT_ACTIONS or action not in EVENT_ACTIONS[kind]:
        raise FeedRefused("event_scope_invalid")
    if kind == "workflow_run":
        if outcome not in CI_CONCLUSIONS:
            raise FeedRefused("event_outcome_invalid")
        if outcome == "success":
            return "NONE"
        if outcome in ("failure", "timed_out", "startup_failure"):
            return "REVIEW_CI_FAILURE"
        return "REVIEW_CI_UNCERTAIN"
    if outcome != "none":
        raise FeedRefused("event_outcome_invalid")
    if kind == "issues":
        return "REVIEW_ISSUE"
    if kind == "issue_comment":
        return "REVIEW_FOLLOWUP"
    return "REVIEW_PR"


def _validate(record: object) -> dict:
    if type(record) is not dict or set(record) != {
        "schema", "repo", "workflow_id", "observed_at", "scope",
        "inspected_count", "events", "owner_approval", "execution_authorized",
    }:
        raise FeedRefused("feed_shape_invalid")
    if (record["schema"] != SCHEMA or record["repo"] != REPO
            or type(record["workflow_id"]) is not int
            or record["workflow_id"] != OBSERVE_WORKFLOW_ID
            or record["scope"] != "GITHUB_ACTIONS_METADATA_ONLY"
            or record["owner_approval"] != "NOT_GRANTED"
            or record["execution_authorized"] is not False
            or type(record["inspected_count"]) is not int
            or not 0 <= record["inspected_count"] <= MAX_RUNS):
        raise FeedRefused("feed_scope_invalid")
    captured = utc(record["observed_at"])
    rows = record["events"]
    if type(rows) is not list or len(rows) > MAX_EVENTS:
        raise FeedRefused("feed_events_invalid")
    seen = set()
    for item in rows:
        if type(item) is not dict or set(item) != {
            "event", "action", "subject_number", "run_id",
            "occurred_at", "candidate", "outcome",
        }:
            raise FeedRefused("feed_event_shape_invalid")
        event, action, outcome = item["event"], item["action"], item["outcome"]
        if type(event) is not str or type(action) is not str or type(outcome) is not str:
            raise FeedRefused("feed_event_scope_invalid")
        if item["candidate"] != _candidate(event, action, outcome):
            raise FeedRefused("feed_event_candidate_invalid")
        if item["candidate"] == "NONE":
            raise FeedRefused("feed_non_actionable_event")
        subject = _ident(item["subject_number"])
        _ident(item["run_id"])
        when = utc(item["occurred_at"])
        if when > captured + SKEW or captured - when > WINDOW:
            raise FeedRefused("feed_event_timestamp_invalid")
        key = (event, subject)
        if key in seen:
            raise FeedRefused("feed_duplicate_event")
        seen.add(key)
    if len(rows) > record["inspected_count"]:
        raise FeedRefused("feed_window_invalid")
    return record


def from_runs(response: object, *, now: datetime) -> dict:
    """Accept only successful known workflow metadata and safe numeric run names."""
    if type(response) is not dict:
        raise FeedRefused("workflow_response_invalid")
    rows = response.get("workflow_runs")
    if type(rows) is not list or len(rows) > MAX_RUNS:
        raise FeedRefused("workflow_window_invalid")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise FeedRefused("clock_invalid")
    at = now.astimezone(UTC)
    entries = []
    for run in rows:
        if type(run) is not dict:
            raise FeedRefused("workflow_row_invalid")
        if (type(run.get("workflow_id")) is not int
                or run["workflow_id"] != OBSERVE_WORKFLOW_ID
                or type(run.get("repository")) is not dict
                or run["repository"].get("full_name") != REPO
                or run.get("name") != OBSERVE_WORKFLOW):
            raise FeedRefused("workflow_identity_invalid")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue  # A failed observer provides NO action recommendation.
        name = run.get("display_title")
        if type(name) is not str or len(name) > 120:
            continue
        match = TITLE.fullmatch(name)
        if match is None:
            continue  # Historical untrusted Issue/PR titles never become events.
        kind, action, number_text, outcome, signed_run_id = match.groups()
        run_id = _ident(run.get("id"))
        # Older workflow runs used PR/Issue titles (attacker-editable).
        # New run-name binds these fixed labels to GitHub-assigned run IDs.
        if int(signed_run_id) != run_id:
            raise FeedRefused("run_title_identity_mismatch")
        if run.get("event") != kind:
            raise FeedRefused("event_identity_mismatch")
        candidate = _candidate(kind, action, outcome)
        if candidate == "NONE":
            continue
        subject = _ident(int(number_text))
        stamp = utc(run.get("created_at"))
        if stamp > at + SKEW:
            raise FeedRefused("workflow_timestamp_future")
        if at - stamp > WINDOW:
            continue
        entries.append({
            "event": kind, "action": action, "subject_number": subject,
            "run_id": run_id, "occurred_at": stamp.isoformat().replace("+00:00", "Z"),
            "candidate": candidate, "outcome": outcome,
        })
    # Prefer the newest completed observation of the same issue/PR/event type.
    entries.sort(key=lambda v: v["run_id"], reverse=True)
    dedup, seen = [], set()
    for row in entries:
        key = (row["event"], row["subject_number"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(row)
        if len(dedup) >= MAX_EVENTS:
            break
    return _validate({
        "schema": SCHEMA, "repo": REPO, "workflow_id": OBSERVE_WORKFLOW_ID,
        "observed_at": at.isoformat().replace("+00:00", "Z"),
        "scope": "GITHUB_ACTIONS_METADATA_ONLY",
        "owner_approval": "NOT_GRANTED", "execution_authorized": False,
        "inspected_count": len(rows), "events": dedup,
    })


def poll(*, now: datetime, opener=None, token_file: Path = TOKEN_FILE) -> dict:
    """Exactly one fixed GET, with the existing protected Actions:read token."""
    token = _private_token(token_file)
    # Legacy main CI read may take 12s; cap this extra GET at 5s so the
    # existing 22s systemd oneshot remains within its original budget.
    response = get_json(API_PATH, opener=opener, token=token, timeout=5)
    return from_runs(response, now=now)


def save(record: dict, *, directory: Path = DIR) -> str:
    value = _validate(record)
    try:
        _dir(directory)  # Reuse existing root-owned 0700 QA watcher state.
    except (OSError, ValueError):
        raise FeedRefused("feed_directory_unsafe") from None
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise FeedRefused("feed_size_invalid")
    fd, filename = tempfile.mkstemp(prefix=".github-observe-", dir=directory)
    target = directory / FILE
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(filename, target)
    except OSError:
        raise FeedRefused("feed_write_unavailable") from None
    finally:
        Path(filename).unlink(missing_ok=True)
    return "STORED_SAFE_GITHUB_OBSERVATIONS"


def read(*, directory: Path = DIR) -> dict | None:
    try:
        _dir(directory)
        file = directory / FILE
        if file.is_symlink():
            raise FeedRefused("feed_file_unsafe")
        if not file.exists():
            return None
        fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 1 <= info.st_size <= MAX_BYTES):
                raise FeedRefused("feed_file_unsafe")
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise FeedRefused("feed_file_unsafe")
        value = json.loads(raw)
    except FeedRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise FeedRefused("feed_unavailable") from None
    return _validate(value)


def fresh(record: object, *, now: datetime) -> bool:
    """Absence, future skew or stale observation is NOT a healthy source."""
    try:
        parsed = _validate(record)
        elapsed = now.astimezone(UTC) - utc(parsed["observed_at"])
        return -SKEW <= elapsed <= MAX_AGE
    except (FeedRefused, AttributeError, TypeError, ValueError):
        return False
