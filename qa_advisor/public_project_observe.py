"""Public, opt-in GitHub Actions observation for other source repositories.

No GitHub token, issue bodies, PR contents, log downloads, API writes, model
calls, vault access or new resident scheduler. Existing Hermes QA timer invokes
at most one bounded GET per enabled public repository each tick.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import stat
import tempfile

from qa_advisor.github_public import GithubPublicError, get_json
from qa_advisor.github_event_observe import EVENT_ACTIONS
from qa_advisor.github_observe_feed import TITLE, _candidate, utc
from qa_advisor.signal_store import DIR, _dir

SCHEMA = "hermes-public-project-observe-v1"
FILE = "github-projects-inbox.json"
MAX_RUNS = 6
# The optional exporter is in protected YFC dev, not master. Use public
# GitHub-native events and its *existing* CI workflow without modifying YFC.
YFC_NATIVE_CI_ID = 259698256
YFC_MAX_PUBLIC_EVENTS = 20
YFC_MAX_INSPECTED = MAX_RUNS + YFC_MAX_PUBLIC_EVENTS
YFC_EVENTS_PATH = "/repos/MikeMoore1337/your-fitness-coach/events?per_page=20"
YFC_CI_PATH = (
    "/repos/MikeMoore1337/your-fitness-coach/actions/workflows/ci.yml/runs?per_page=6"
)
YFC_PUBLIC_EVENT_TYPES = {
    "IssuesEvent": ("issues", "issue", frozenset({"opened", "reopened"})),
    "IssueCommentEvent": ("issue_comment", "issue", frozenset({"created"})),
    "PullRequestEvent": ("pull_request_target", "pull_request",
                         frozenset({"opened", "reopened", "synchronize", "ready_for_review"})),
}
MAX_EVENTS = 5
MAX_BYTES = 16384
MAX_ID = 10**18
MAX_AGE = timedelta(minutes=45)
EVENT_WINDOW = timedelta(hours=24)
SKEW = timedelta(minutes=2)
WORKFLOW = "Project GitHub Observe (read only)"
WORKFLOW_FILE = "github-observe-export.yml"
# Numeric IDs must be checked against actual GitHub public workflow REST
# results after merge. 0 means disabled / unverified, never 'available'.
PROJECTS = {
    "toolkit": ("MikeMoore1337/ai-development-toolkit", 404394421),
    "yfc": ("MikeMoore1337/your-fitness-coach", 259698256),
    "second_brain": ("MikeMoore1337/second-brain", 0),
}


class PublicObserveError(ValueError):
    """Only fixed error codes (no untrusted text)."""


def _integer(value):
    if type(value) is not int or not 1 <= value <= MAX_ID:
        raise PublicObserveError("invalid_id")
    return value


def _read_runs(repo, workflow_id, data, now):
    if type(data) is not dict or type(data.get("workflow_runs")) is not list:
        raise PublicObserveError("invalid_runs")
    rows = data["workflow_runs"]
    if len(rows) > MAX_RUNS:
        raise PublicObserveError("unbounded_runs")
    found = []
    for run in rows:
        if type(run) is not dict:
            raise PublicObserveError("invalid_run")
        source = run.get("repository")
        if (type(source) is not dict or source.get("full_name") != repo
                or type(run.get("workflow_id")) is not int
                or run["workflow_id"] != workflow_id):
            raise PublicObserveError("wrong_source")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        name, display = run.get("name"), run.get("display_title")
        if type(name) is not str or type(display) is not str:
            continue
        if len(name) > 120 or len(display) > 120 or name != display:
            continue
        match = TITLE.fullmatch(name)
        if match is None:
            continue
        kind, action, number, outcome, encoded_run_id = match.groups()
        run_id = _integer(run.get("id"))
        if int(encoded_run_id) != run_id or run.get("event") != kind:
            raise PublicObserveError("event_identity_mismatch")
        if kind not in EVENT_ACTIONS or action not in EVENT_ACTIONS[kind]:
            raise PublicObserveError("event_denied")
        try:
            candidate = _candidate(kind, action, outcome)
            stamp = utc(run.get("created_at"))
        except (ValueError, TypeError):
            raise PublicObserveError("event_invalid") from None
        if stamp > now + SKEW:
            raise PublicObserveError("event_in_future")
        if now - stamp > EVENT_WINDOW or candidate == "NONE":
            continue
        found.append({
            "kind": kind, "number": _integer(int(number)),
            "run_id": run_id, "candidate": candidate,
            "occurred_at": stamp.isoformat().replace("+00:00", "Z"),
        })
    found.sort(key=lambda x: x["run_id"], reverse=True)
    unique, seen = [], set()
    for item in found:
        key = (item["kind"], item["number"])
        if key in seen:
            continue
        unique.append(item)
        seen.add(key)
        if len(unique) >= MAX_EVENTS:
            break
    return {"status": "PARTIAL", "inspected_count": len(rows), "events": unique}



def _yfc_native_events(raw_events, raw_ci, now):
    """Reduce GitHub public events and existing CI to fixed enums/numbers.

    Public Events API can be delayed/incomplete; only PARTIAL is reported.
    GitHub user-controlled titles/bodies/URLs never leave this function.
    """
    repo = PROJECTS["yfc"][0]
    if (type(raw_events) is not dict or type(raw_events.get("events")) is not list
            or type(raw_ci) is not dict or type(raw_ci.get("workflow_runs")) is not list):
        raise PublicObserveError("yfc_native_shape_invalid")
    events, runs = raw_events["events"], raw_ci["workflow_runs"]
    if len(events) > YFC_MAX_PUBLIC_EVENTS or len(runs) > MAX_RUNS:
        raise PublicObserveError("yfc_native_window_invalid")
    found = []
    for raw in events:
        if type(raw) is not dict or type(raw.get("repo")) is not dict:
            raise PublicObserveError("yfc_event_shape_invalid")
        if raw["repo"].get("name") != repo:
            raise PublicObserveError("yfc_event_repo_invalid")
        kind = raw.get("type")
        if type(kind) is not str or kind not in YFC_PUBLIC_EVENT_TYPES:
            continue  # Push/Create/Delete/etc are not evidence of user tasks.
        mapped, item_key, permitted = YFC_PUBLIC_EVENT_TYPES[kind]
        payload = raw.get("payload")
        if type(payload) is not dict:
            raise PublicObserveError("yfc_event_payload_invalid")
        action = payload.get("action")
        if type(action) is not str or action not in permitted:
            continue
        issue = payload.get(item_key)
        if type(issue) is not dict:
            raise PublicObserveError("yfc_event_subject_invalid")
        number = _integer(issue.get("number"))
        event_id = raw.get("id")
        if (type(event_id) is not str or not 1 <= len(event_id) <= 18
                or not event_id.isascii() or not event_id.isdecimal()
                or event_id.startswith("0")):
            raise PublicObserveError("yfc_event_id_invalid")
        run_id = _integer(int(event_id))
        try:
            stamp = utc(raw.get("created_at"))
            candidate = _candidate(mapped, action, "none")
        except (ValueError, TypeError):
            raise PublicObserveError("yfc_event_metadata_invalid") from None
        if stamp > now + SKEW:
            raise PublicObserveError("yfc_event_in_future")
        if now - stamp > EVENT_WINDOW:
            continue
        found.append({
            "kind": mapped, "number": number, "run_id": run_id,
            "candidate": candidate,
            "occurred_at": stamp.isoformat().replace("+00:00", "Z"),
        })

    for raw in runs:
        if type(raw) is not dict:
            raise PublicObserveError("yfc_ci_row_invalid")
        source, head = raw.get("repository"), raw.get("head_repository")
        if (type(source) is not dict or source.get("full_name") != repo
                or type(head) is not dict or head.get("full_name") != repo
                or type(raw.get("workflow_id")) is not int
                or raw["workflow_id"] != YFC_NATIVE_CI_ID
                or raw.get("name") != "CI"):
            raise PublicObserveError("yfc_ci_source_invalid")
        event, branch = raw.get("event"), raw.get("head_branch")
        if event == "push" and branch not in ("dev", "master"):
            continue
        if event not in ("push", "pull_request"):
            continue
        if raw.get("status") != "completed":
            continue
        conclusion = raw.get("conclusion")
        try:
            candidate = _candidate("workflow_run", "completed", conclusion)
            number = _integer(raw.get("id"))
            stamp = utc(raw.get("created_at"))
        except (ValueError, TypeError):
            raise PublicObserveError("yfc_ci_metadata_invalid") from None
        if stamp > now + SKEW:
            raise PublicObserveError("yfc_ci_in_future")
        if now - stamp > EVENT_WINDOW or candidate == "NONE":
            continue
        found.append({
            "kind": "workflow_run", "number": number, "run_id": number,
            "candidate": candidate,
            "occurred_at": stamp.isoformat().replace("+00:00", "Z"),
        })

    # Different GitHub event IDs and Actions run IDs use different sequences.
    # Timestamps, not cross-system numeric IDs, determine newest observations.
    found.sort(key=lambda x: (x["occurred_at"], x["run_id"]), reverse=True)
    seen, unique = set(), []
    for item in found:
        key = (item["kind"], item["number"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        if len(unique) >= MAX_EVENTS:
            break
    return {
        "status": "PARTIAL",
        "inspected_count": len(events) + len(runs),
        "events": unique,
    }


def _get_yfc_native(*, when, reader):
    repo, workflow_id = PROJECTS["yfc"]
    if workflow_id != YFC_NATIVE_CI_ID:
        return _source("yfc", None)
    try:
        # Two anonymous fixed GETs overlap in time. No new resident worker or
        # scheduler and no developer PAT for YFC, even on a partial failure.
        with ThreadPoolExecutor(max_workers=2) as pool:
            events = pool.submit(reader, YFC_EVENTS_PATH, token=None, timeout=2)
            runs = pool.submit(reader, YFC_CI_PATH, token=None, timeout=2)
            observations = events.result()
            ci = runs.result()
        return _source("yfc", _yfc_native_events(observations, ci, when))
    except (GithubPublicError, PublicObserveError, OSError, ValueError, TimeoutError):
        return _source("yfc", None)


def _source(key, result):
    repo, workflow_id = PROJECTS[key]
    if workflow_id == 0:
        return {"repo": repo, "workflow_id": 0,
                "status": "NOT_AVAILABLE", "inspected_count": 0, "events": []}
    if result is None:
        return {"repo": repo, "workflow_id": workflow_id,
                "status": "NOT_AVAILABLE", "inspected_count": 0, "events": []}
    return {"repo": repo, "workflow_id": workflow_id, **result}


def validate(record):
    if type(record) is not dict or set(record) != {
        "schema", "observed_at", "sources", "scope", "owner_approval",
        "execution_authorized",
    }:
        raise PublicObserveError("feed_shape_invalid")
    if (record["schema"] != SCHEMA or record["scope"] != "PUBLIC_METADATA_ONLY"
            or record["owner_approval"] != "NOT_GRANTED"
            or record["execution_authorized"] is not False
            or type(record["sources"]) is not dict
            or set(record["sources"]) != set(PROJECTS)):
        raise PublicObserveError("feed_scope_invalid")
    captured = utc(record["observed_at"])
    for key, entry in record["sources"].items():
        repo, configured_id = PROJECTS[key]
        if type(entry) is not dict or set(entry) != {
            "repo", "workflow_id", "status", "inspected_count", "events",
        }:
            raise PublicObserveError("source_shape_invalid")
        if (entry["repo"] != repo or type(entry["workflow_id"]) is not int
                or entry["workflow_id"] != configured_id
                or entry["status"] not in ("PARTIAL", "NOT_AVAILABLE")
                or type(entry["inspected_count"]) is not int
                or not 0 <= entry["inspected_count"] <= (
                    YFC_MAX_INSPECTED if key == "yfc" and configured_id == YFC_NATIVE_CI_ID
                    else MAX_RUNS)
                or type(entry["events"]) is not list
                or len(entry["events"]) > MAX_EVENTS
                or len(entry["events"]) > entry["inspected_count"]):
            raise PublicObserveError("source_invalid")
        if entry["status"] != "PARTIAL" and (entry["events"] or entry["inspected_count"]):
            raise PublicObserveError("unverified_events")
        if entry["status"] == "PARTIAL" and configured_id == 0:
            raise PublicObserveError("unconfigured_source")
        seen = set()
        for x in entry["events"]:
            if type(x) is not dict or set(x) != {
                "kind", "number", "run_id", "candidate", "occurred_at",
            }:
                raise PublicObserveError("event_shape_invalid")
            if type(x["kind"]) is not str or x["kind"] not in EVENT_ACTIONS:
                raise PublicObserveError("event_kind_invalid")
            if type(x["candidate"]) is not str or x["candidate"] not in (
                    "REVIEW_ISSUE", "REVIEW_FOLLOWUP", "REVIEW_PR",
                    "REVIEW_CI_FAILURE", "REVIEW_CI_UNCERTAIN"):
                raise PublicObserveError("event_candidate_invalid")
            _integer(x["number"])
            _integer(x["run_id"])
            dt = utc(x["occurred_at"])
            if dt > captured + SKEW or captured - dt > EVENT_WINDOW:
                raise PublicObserveError("event_time_invalid")
            identity = (x["kind"], x["number"])
            if identity in seen:
                raise PublicObserveError("event_duplicate")
            seen.add(identity)
    return record


def _get_one(key, *, when, reader):
    repo, wf = PROJECTS[key]
    if wf == 0:
        return _source(key, None)
    if key == "yfc" and wf == YFC_NATIVE_CI_ID:
        return _get_yfc_native(when=when, reader=reader)
    path = f"/repos/{repo}/actions/workflows/{WORKFLOW_FILE}/runs?per_page={MAX_RUNS}"
    try:
        # Public repo only. Absolutely no Hermes token to third-party projects.
        data = reader(path, token=None, timeout=2)
        return _source(key, _read_runs(repo, wf, data, when))
    except (GithubPublicError, PublicObserveError, OSError, ValueError, TimeoutError):
        return _source(key, None)


def poll(*, now, reader=get_json):
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise PublicObserveError("clock_invalid")
    timestamp = now.astimezone(UTC)
    keys = list(PROJECTS)
    active = [k for k in keys if PROJECTS[k][1] != 0]
    results = {k: _source(k, None) for k in keys}
    # Only ephemeral network threads. Existing QA timer is the sole scheduler.
    if active:
        with ThreadPoolExecutor(max_workers=min(3, len(active))) as pool:
            future = {key: pool.submit(_get_one, key, when=timestamp, reader=reader) for key in active}
            for key in active:
                results[key] = future[key].result()
    return validate({
        "schema": SCHEMA, "observed_at": timestamp.isoformat().replace("+00:00", "Z"),
        "scope": "PUBLIC_METADATA_ONLY", "owner_approval": "NOT_GRANTED",
        "execution_authorized": False, "sources": results,
    })


def save(record, *, directory=DIR):
    safe = validate(record)
    _dir(directory)
    payload = (json.dumps(safe, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
               + "\n").encode("utf-8")
    if len(payload) > MAX_BYTES:
        raise PublicObserveError("feed_oversize")
    fd, temp_name = tempfile.mkstemp(prefix=".gh-projects-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, directory / FILE)
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return "STORED_PUBLIC_PROJECT_OBSERVATIONS"
