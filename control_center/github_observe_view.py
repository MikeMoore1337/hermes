"""Read-only verifier for the QA watch -> Control Center release boundary.

The web release ships control_center/ but NOT qa_advisor/. Keep this module
self-contained: only the existing root snapshot collector reads the 0600 QA
feed, then the existing owner-only overview and Inbox serve reduced facts.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import stat

SCHEMA = "hermes-gh-observe-inbox-v1"
REPO = "MikeMoore1337/hermes"
WORKFLOW_ID = 403765637
FILE = Path("/var/lib/hermes-qa-watch/github-observe-inbox.json")
MAX_BYTES = 8192
MAX_EVENTS = 10
MAX_ID = 10**18
MAX_AGE = timedelta(minutes=45)
SKEW = timedelta(minutes=2)
WINDOW = timedelta(hours=24)


class FeedRefused(ValueError):
    """Fixed error codes, no raw payloads or private filesystem paths."""


def _utc(value):
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise FeedRefused("feed_timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FeedRefused("feed_timestamp_invalid") from None
    if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise FeedRefused("feed_timestamp_invalid")
    return stamp.astimezone(UTC)


def _id(value):
    if type(value) is not int or not 1 <= value <= MAX_ID:
        raise FeedRefused("feed_id_invalid")
    return value


def _candidate(kind, action, outcome):
    if any(type(s) is not str for s in (kind, action, outcome)):
        raise FeedRefused("feed_event_invalid")
    if kind == "issues" and action in ("opened", "reopened") and outcome == "none":
        return "REVIEW_ISSUE"
    if kind == "issue_comment" and action == "created" and outcome == "none":
        return "REVIEW_FOLLOWUP"
    if (kind == "pull_request_target" and action in (
            "opened", "reopened", "synchronize", "ready_for_review")
            and outcome == "none"):
        return "REVIEW_PR"
    if kind == "workflow_run" and action == "completed":
        if outcome in ("failure", "timed_out", "startup_failure"):
            return "REVIEW_CI_FAILURE"
        if outcome in ("cancelled", "neutral", "skipped", "action_required"):
            return "REVIEW_CI_UNCERTAIN"
    raise FeedRefused("feed_event_invalid")


def validate(raw: object) -> dict:
    if type(raw) is not dict or set(raw) != {
        "schema", "repo", "workflow_id", "observed_at", "scope",
        "inspected_count", "events", "owner_approval", "execution_authorized",
    }:
        raise FeedRefused("feed_shape_invalid")
    if (raw["schema"] != SCHEMA or raw["repo"] != REPO
            or type(raw["workflow_id"]) is not int or raw["workflow_id"] != WORKFLOW_ID
            or raw["scope"] != "GITHUB_ACTIONS_METADATA_ONLY"
            or raw["owner_approval"] != "NOT_GRANTED"
            or raw["execution_authorized"] is not False
            or type(raw["inspected_count"]) is not int
            or not 0 <= raw["inspected_count"] <= 12):
        raise FeedRefused("feed_source_invalid")
    captured = _utc(raw["observed_at"])
    entries = raw["events"]
    if type(entries) is not list or len(entries) > MAX_EVENTS:
        raise FeedRefused("feed_entries_invalid")
    seen = set()
    for item in entries:
        if type(item) is not dict or set(item) != {
            "event", "action", "subject_number", "run_id",
            "occurred_at", "candidate", "outcome",
        }:
            raise FeedRefused("feed_entry_invalid")
        event, action, outcome = item["event"], item["action"], item["outcome"]
        if item["candidate"] != _candidate(event, action, outcome):
            raise FeedRefused("feed_candidate_invalid")
        number = _id(item["subject_number"])
        _id(item["run_id"])
        when = _utc(item["occurred_at"])
        if when > captured + SKEW or captured - when > WINDOW:
            raise FeedRefused("feed_timestamp_invalid")
        key = (event, number)
        if key in seen:
            raise FeedRefused("feed_duplicate")
        seen.add(key)
    if len(entries) > raw["inspected_count"]:
        raise FeedRefused("feed_window_invalid")
    return raw


def load(path: Path = FILE) -> dict | None:
    """Root-owned bounded file reader; no network, shell, token or writes."""
    try:
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise FeedRefused("feed_directory_unsafe")
        d = parent.stat()
        if d.st_uid != os.geteuid() or stat.S_IMODE(d.st_mode) != 0o700:
            raise FeedRefused("feed_directory_unsafe")
        if path.is_symlink():
            raise FeedRefused("feed_file_unsafe")
        if not path.exists():
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 1 <= info.st_size <= MAX_BYTES):
                raise FeedRefused("feed_file_unsafe")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise FeedRefused("feed_file_unsafe")
        decoded = json.loads(data)
    except FeedRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise FeedRefused("feed_unavailable") from None
    return validate(decoded)


def fresh(value: object, *, now: datetime) -> bool:
    try:
        validated = validate(value)
        age = now.astimezone(UTC) - _utc(validated["observed_at"])
        return -SKEW <= age <= MAX_AGE
    except (FeedRefused, ValueError, AttributeError, TypeError):
        return False
