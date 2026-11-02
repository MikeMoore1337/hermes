"""Root-only projection of public code-project GitHub observations.

Independent from qa_advisor package: Control Center release contains only
control_center/ and research_scout/. This module never accesses GitHub or a
GitHub token; the web server sees only the sanitized root snapshot.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import stat

FILE = Path("/var/lib/hermes-qa-watch/github-projects-inbox.json")
SCHEMA = "hermes-public-project-observe-v1"
MAX_BYTES = 16384
MAX_RUNS = 6
MAX_EVENTS = 5
MAX_ID = 10**18
MAX_AGE = timedelta(minutes=45)
WINDOW = timedelta(hours=24)
SKEW = timedelta(minutes=2)
PROJECTS = {
    "toolkit": ("MikeMoore1337/ai-development-toolkit", 404394421),
    "yfc": ("MikeMoore1337/your-fitness-coach", 0),
    "second_brain": ("MikeMoore1337/second-brain", 0),
}
CANDIDATES = {
    "issues": frozenset({"REVIEW_ISSUE"}),
    "issue_comment": frozenset({"REVIEW_FOLLOWUP"}),
    "pull_request_target": frozenset({"REVIEW_PR"}),
    "workflow_run": frozenset({"REVIEW_CI_FAILURE", "REVIEW_CI_UNCERTAIN"}),
}


class ProjectFeedRefused(ValueError):
    """No untrusted payload in any error reason."""


def _utc(value):
    if type(value) is not str or not 1 <= len(value) <= 40:
        raise ProjectFeedRefused("timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ProjectFeedRefused("timestamp_invalid") from None
    if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise ProjectFeedRefused("timestamp_invalid")
    return stamp.astimezone(UTC)


def _id(number):
    if type(number) is not int or not 1 <= number <= MAX_ID:
        raise ProjectFeedRefused("id_invalid")
    return number


def validate(value):
    if type(value) is not dict or set(value) != {
        "schema", "observed_at", "sources", "scope",
        "owner_approval", "execution_authorized",
    }:
        raise ProjectFeedRefused("shape_invalid")
    if (value["schema"] != SCHEMA or value["scope"] != "PUBLIC_METADATA_ONLY"
            or value["owner_approval"] != "NOT_GRANTED"
            or value["execution_authorized"] is not False
            or type(value["sources"]) is not dict
            or set(value["sources"]) != set(PROJECTS)):
        raise ProjectFeedRefused("scope_invalid")
    observed = _utc(value["observed_at"])
    for key, record in value["sources"].items():
        repo, expected_id = PROJECTS[key]
        if type(record) is not dict or set(record) != {
            "repo", "workflow_id", "status", "inspected_count", "events",
        }:
            raise ProjectFeedRefused("source_shape_invalid")
        if (record["repo"] != repo or type(record["workflow_id"]) is not int
                or record["workflow_id"] != expected_id
                or record["status"] not in ("PARTIAL", "NOT_AVAILABLE")
                or type(record["inspected_count"]) is not int
                or not 0 <= record["inspected_count"] <= MAX_RUNS
                or type(record["events"]) is not list
                or len(record["events"]) > MAX_EVENTS
                or len(record["events"]) > record["inspected_count"]):
            raise ProjectFeedRefused("source_invalid")
        if record["status"] == "PARTIAL" and expected_id == 0:
            raise ProjectFeedRefused("disabled_source")
        if record["status"] != "PARTIAL" and (record["inspected_count"] or record["events"]):
            raise ProjectFeedRefused("unverified_events")
        seen = set()
        for item in record["events"]:
            if type(item) is not dict or set(item) != {
                "kind", "number", "run_id", "candidate", "occurred_at",
            }:
                raise ProjectFeedRefused("event_shape_invalid")
            kind = item["kind"]
            if type(kind) is not str or kind not in CANDIDATES:
                raise ProjectFeedRefused("event_type_invalid")
            if type(item["candidate"]) is not str or item["candidate"] not in CANDIDATES[kind]:
                raise ProjectFeedRefused("event_candidate_invalid")
            number, run_id = _id(item["number"]), _id(item["run_id"])
            when = _utc(item["occurred_at"])
            if when > observed + SKEW or observed - when > WINDOW:
                raise ProjectFeedRefused("event_timestamp_invalid")
            key2 = (kind, number)
            if key2 in seen:
                raise ProjectFeedRefused("duplicate")
            seen.add(key2)
    return value


def load(path: Path = FILE):
    try:
        directory = path.parent
        if directory.is_symlink() or not directory.is_dir():
            raise ProjectFeedRefused("directory_unsafe")
        info = directory.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ProjectFeedRefused("directory_unsafe")
        if path.is_symlink():
            raise ProjectFeedRefused("file_unsafe")
        if not path.exists():
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 1 <= info.st_size <= MAX_BYTES):
                raise ProjectFeedRefused("file_unsafe")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ProjectFeedRefused("file_unsafe")
        raw = json.loads(data)
    except ProjectFeedRefused:
        raise
    except (OSError, ValueError, UnicodeError):
        raise ProjectFeedRefused("feed_unavailable") from None
    return validate(raw)


def fresh(feed, *, now):
    try:
        value = validate(feed)
        age = now.astimezone(UTC) - _utc(value["observed_at"])
        return -SKEW <= age <= MAX_AGE
    except (ProjectFeedRefused, ValueError, TypeError, AttributeError):
        return False
