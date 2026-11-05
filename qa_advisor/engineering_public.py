"""Opt-in, bounded public GitHub observations for Hermes engineering prechecks.

Public REST only; no credentials, proxy, redirect, retries, Git writes, agents,
new timers or repository content execution. A result never grants owner GO.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from datetime import UTC, datetime
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from qa_advisor.release_guard import evaluate as assess_release, REPOSITORIES
from qa_advisor.merge_control import review as assess_merge, MAX_FILES
from qa_advisor.opensource_radar import assess as assess_radar, _repo as validate_slug
from qa_advisor.github_public import public_opener

BASE = "https://api.github.com"
MAX_HTTP_BYTES = 750_000
MAX_REQUESTS = 36
MAX_PR_WINDOW = 10
WORKFLOW_IDS = {
    "MikeMoore1337/hermes": {"PR": (381262090,), "RELEASE": (381262090, 386820934)},
    "MikeMoore1337/ai-development-toolkit": {"PR": (388394026,), "RELEASE": (388394026,)},
    "MikeMoore1337/your-fitness-coach": {"PR": (259698256,), "RELEASE": (259698256,)},
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DEPENDENCY = re.compile(r"(?im)^Depends-on:[ \t]*#([1-9][0-9]{0,17})[ \t]*$")
_ROOT = r"/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"
_SUFFIX = (
    r"(?:"
    r"|/pulls/[1-9][0-9]{0,17}"
    r"|/pulls/[1-9][0-9]{0,17}/reviews\?per_page=100"
    r"|/pulls/[1-9][0-9]{0,17}/files\?per_page=100&page=[12]"
    r"|/pulls\?state=open&per_page=10&page=[12]"
    r"|/branches/[A-Za-z0-9._~%-]+"
    r"|/actions/runs\?head_sha=[0-9a-f]{40}&per_page=100"
    r"|/license\?ref=[0-9a-f]{40}"
    r"|/contents\?ref=[0-9a-f]{40}"
    r"|/contents/NOTICE(?:\.txt|\.md)?\?ref=[0-9a-f]{40}"
    r"|/releases/latest"
    r"|/security-advisories\?per_page=5"
    r")"
)
URL_PATH = re.compile("^" + _ROOT + _SUFFIX + r"\Z")


class SourceUnavailable(ValueError):
    """Only a fixed safe code, never a response body or user URL."""


def _safe_id(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 10**18:
        raise SourceUnavailable("id_invalid")
    return value


def _safe_sha(value: Any) -> str:
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise SourceUnavailable("sha_invalid")
    return value


def _repo(value: str) -> str:
    if type(value) is not str or value not in REPOSITORIES:
        raise SourceUnavailable("repo_not_allowlisted")
    return value


def _obj(value: Any) -> dict:
    if type(value) is not dict:
        raise SourceUnavailable("source_shape_invalid")
    return value


def _array(value: Any, *, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise SourceUnavailable("source_window_invalid")
    return value


def _utc(now: datetime | None) -> datetime:
    value = now if now is not None else datetime.now(UTC)
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise SourceUnavailable("clock_invalid")
    return value.astimezone(UTC)


def _iso(now: datetime | None) -> str:
    return _utc(now).isoformat().replace("+00:00", "Z")


def _unique_json(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SourceUnavailable("duplicate_json_key")
        out[key] = value
    return out


class PublicGithub:
    """Bounded, unauthenticated public API reader; path comes from typed helpers."""

    def __init__(self, *, opener=None):
        self._opener = opener if opener is not None else public_opener()
        self.calls = 0

    def get(self, path: str):
        if (type(path) is not str or len(path) > 300 or not URL_PATH.fullmatch(path)
                or ".." in path or "//" in path or "\\" in path
                or "%2e" in path.lower()):
            raise SourceUnavailable("endpoint_not_allowlisted")
        if self.calls >= MAX_REQUESTS:
            raise SourceUnavailable("request_budget_exceeded")
        self.calls += 1
        req = urllib.request.Request(BASE + path, method="GET", headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Hermes-Engineering-Readonly/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with self._opener.open(req, timeout=6) as response:
                if response.status != 200:
                    raise SourceUnavailable("github_unavailable")
                raw = response.read(MAX_HTTP_BYTES + 1)
        except urllib.error.HTTPError as exc:
            code = "github_not_found" if exc.code == 404 else (
                "github_forbidden_or_limited" if exc.code in (401, 403, 429)
                else "github_unavailable")
            raise SourceUnavailable(code) from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise SourceUnavailable("github_network_unavailable") from None
        if len(raw) > MAX_HTTP_BYTES:
            raise SourceUnavailable("response_oversized")
        try:
            return json.loads(raw, object_pairs_hook=_unique_json)
        except SourceUnavailable:
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise SourceUnavailable("response_json_invalid") from None


def _reader(client):
    return client if client is not None else PublicGithub()


def _runs(source, repo: str, sha: str, workflow_ids: tuple[int, ...], *,
          stage: str, branch: str) -> list[dict]:
    # GitHub may return an incomplete window. Never treat it as all checks.
    rows = _obj(source.get(
        f"/repos/{repo}/actions/runs?head_sha={sha}&per_page=100"
    ))
    data = _array(rows.get("workflow_runs"), maximum=100)
    total = rows.get("total_count")
    if (type(total) is not int or total < len(data) or total > len(data)
            or len(data) == 100):
        raise SourceUnavailable("actions_run_window_incomplete")
    selected: dict[int, dict] = {}
    for raw in data:
        entry = _obj(raw)
        ident = entry.get("workflow_id")
        if type(ident) is not int or ident not in workflow_ids:
            continue
        required_event = "pull_request" if stage == "PR" else "push"
        if entry.get("event") != required_event:
            continue
        if stage == "RELEASE" and entry.get("head_branch") != branch:
            continue
        if _obj(entry.get("repository")).get("full_name") != repo:
            raise SourceUnavailable("actions_repo_mismatch")
        if entry.get("head_sha") != sha:
            raise SourceUnavailable("actions_sha_mismatch")
        _safe_id(entry.get("id"))
        previous = selected.get(ident)
        if previous is None or entry["id"] > previous["id"]:
            selected[ident] = entry
    return [{
        "workflow_id": work,
        "run_id": record["id"],
        "head_sha": record["head_sha"],
        "status": record.get("status"),
        "conclusion": record.get("conclusion"),
    } for work, record in sorted(selected.items())]


def _approval(source, repo: str, pr_number: int, sha: str) -> dict:
    entries = _array(source.get(
        f"/repos/{repo}/pulls/{pr_number}/reviews?per_page=100"
    ), maximum=100)
    if len(entries) == 100:
        return {"state": "unknown", "head_sha": None}
    recent: dict[str, dict] = {}
    for entry in entries:
        review = _obj(entry)
        user = review.get("user")
        if type(user) is not dict or type(user.get("login")) is not str:
            continue
        state = review.get("state")
        if state not in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            continue
        _safe_id(review.get("id"))
        login = user["login"].lower()
        if login not in recent or review["id"] > recent[login]["id"]:
            recent[login] = review
    active = list(recent.values())
    if any(r["state"] == "CHANGES_REQUESTED" for r in active):
        return {"state": "changes_requested", "head_sha": None}
    approvals = [r for r in active if r["state"] == "APPROVED" and r.get("commit_id") == sha]
    if approvals:
        return {"state": "approved", "head_sha": sha}
    return {"state": "pending" if not active else "unknown", "head_sha": None}


def _mergeability(value: Any) -> str:
    return "clean" if value is True else "dirty" if value is False else "unknown"


def _branch_sha(source, repo: str, branch: str) -> str:
    if branch not in ("dev", "main", "master"):
        raise SourceUnavailable("branch_not_allowlisted")
    obj = _obj(source.get(f"/repos/{repo}/branches/{branch}"))
    if obj.get("name") != branch:
        raise SourceUnavailable("branch_identity_mismatch")
    return _safe_sha(_obj(obj.get("commit")).get("sha"))


def release_snapshot(repo: str, *, stage: str, pr: int | None = None,
                     client=None, now: datetime | None = None) -> dict:
    """One-shot capture from GitHub and offline assessment. Never a merge GO."""
    _repo(repo)
    if type(stage) is not str or stage not in ("PR", "RELEASE"):
        raise SourceUnavailable("stage_invalid")
    source = _reader(client)
    branch = REPOSITORIES[repo][stage]
    stamp = _iso(now)
    if stage == "PR":
        number = _safe_id(pr)
        raw = _obj(source.get(f"/repos/{repo}/pulls/{number}"))
        if raw.get("number") != number or raw.get("state") != "open":
            raise SourceUnavailable("pr_identity_invalid")
        base = _obj(raw.get("base"))
        if base.get("ref") != branch or _obj(base.get("repo")).get("full_name") != repo:
            raise SourceUnavailable("pr_base_invalid")
        sha = _safe_sha(_obj(raw.get("head")).get("sha"))
        draft = raw.get("draft")
        if type(draft) is not bool:
            raise SourceUnavailable("pr_draft_invalid")
        mergeable = _mergeability(raw.get("mergeable"))
        review = _approval(source, repo, number, sha)
    else:
        if pr is not None:
            raise SourceUnavailable("pr_not_allowed_in_release")
        sha = _branch_sha(source, repo, branch)
        draft, mergeable = None, "not_applicable"
        review = {"state": "not_applicable", "head_sha": None}
    required = WORKFLOW_IDS[repo][stage]
    checks = _runs(source, repo, sha, required, stage=stage, branch=branch)
    # Re-read the actual identity to reject a race during the bounded calls.
    if stage == "PR":
        after = _obj(source.get(f"/repos/{repo}/pulls/{number}"))
        if (after.get("state") != "open" or _obj(after.get("head")).get("sha") != sha
                or _obj(after.get("base")).get("ref") != branch
                or after.get("draft") is not draft):
            raise SourceUnavailable("pr_changed_during_capture")
    elif _branch_sha(source, repo, branch) != sha:
        raise SourceUnavailable("branch_changed_during_capture")
    data = {
        "schema": "hermes-releaseguard-evidence-v1", "repo": repo,
        "stage": stage, "branch": branch, "candidate_sha": sha,
        "observed_head_sha": sha, "observed_at": stamp,
        "required_workflows": list(required), "checks": checks,
        "review": review, "mergeability": mergeable, "draft": draft,
    }
    result = assess_release(data, now=_utc(now))
    # Live API contact alone cannot prove branch-protection policy completeness
    # or provide owner release approval. Preserve core's unverified fields.
    return result


def merge_snapshot(repo: str, *, client=None, now: datetime | None = None) -> dict:
    """Bounded open-PR sampling and changed-path risk; no textual merge proof."""
    _repo(repo)
    source = _reader(client)
    stamp = _iso(now)
    rows = _array(source.get(
        f"/repos/{repo}/pulls?state=open&per_page={MAX_PR_WINDOW}&page=1"
    ), maximum=MAX_PR_WINDOW)
    complete = len(rows) < MAX_PR_WINDOW
    if not complete:
        extra = _array(source.get(
            f"/repos/{repo}/pulls?state=open&per_page={MAX_PR_WINDOW}&page=2"
        ), maximum=MAX_PR_WINDOW)
        complete = len(extra) == 0
    prs = []
    incomplete_sources = 0
    for item in rows:
        try:
            num = _safe_id(_obj(item).get("number"))
            raw = _obj(source.get(f"/repos/{repo}/pulls/{num}"))
            if raw.get("number") != num or raw.get("state") != "open":
                raise SourceUnavailable("pr_changed_during_capture")
            base = _obj(raw.get("base"))
            branch = base.get("ref")
            if branch not in REPOSITORIES[repo].values():
                complete = False
                continue
            if _obj(base.get("repo")).get("full_name") != repo:
                raise SourceUnavailable("base_repo_invalid")
            head_sha = _safe_sha(_obj(raw.get("head")).get("sha"))
            base_sha = _safe_sha(base.get("sha"))
            files = _array(source.get(
                f"/repos/{repo}/pulls/{num}/files?per_page=100&page=1"
            ), maximum=100)
            if len(files) == 100:
                extra = _array(source.get(
                    f"/repos/{repo}/pulls/{num}/files?per_page=100&page=2"
                ), maximum=100)
                files += extra
            expected_files = raw.get("changed_files")
            files_complete = (type(expected_files) is int and expected_files == len(files)
                              and len(files) <= MAX_FILES)
            sanitized = []
            for changed in files[:MAX_FILES]:
                f = _obj(changed)
                state = f.get("status")
                if state not in ("added", "modified", "removed", "renamed"):
                    files_complete = False
                    continue
                sanitized.append({
                    "path": f.get("filename"),
                    "previous_path": f.get("previous_filename") if state == "renamed" else None,
                    "status": state,
                })
            # Recheck identity after paginated file reads. A synchronized PR may
            # otherwise combine a new head with old changed paths.
            current = _obj(source.get(f"/repos/{repo}/pulls/{num}"))
            if (current.get("number") != num or current.get("state") != "open"
                    or _obj(current.get("head")).get("sha") != head_sha
                    or _obj(current.get("base")).get("sha") != base_sha
                    or current.get("changed_files") != expected_files):
                raise SourceUnavailable("pr_changed_during_capture")
            body = raw.get("body")
            dependencies = []
            if type(body) is str and len(body) <= 2048:
                dependencies = sorted(set(int(x) for x in DEPENDENCY.findall(body)))
                dependencies = [x for x in dependencies if x != num][:10]
            elif body:
                complete = False
            draft = raw.get("draft")
            if type(draft) is not bool:
                raise SourceUnavailable("pr_draft_invalid")
            prs.append({
                "number": num, "head_sha": head_sha, "base_sha": base_sha,
                "base_branch": branch, "draft": draft,
                "mergeable": _mergeability(raw.get("mergeable")),
                "files_complete": files_complete, "files": sanitized,
                "depends_on": dependencies,
            })
        except SourceUnavailable as exc:
            # A changed HEAD/base cannot be downgraded into partial evidence:
            # the snapshot itself raced during capture.
            if str(exc) == "pr_changed_during_capture":
                raise
            complete = False
            incomplete_sources += 1
            continue
        except (ValueError, TypeError):
            # Malformed unrelated PR data cannot erase evidence from other PRs
            # or convert an incomplete window into a clean signal.
            complete = False
            incomplete_sources += 1
            continue
    evidence = {
        "schema": "hermes-mergecontrol-evidence-v1", "repo": repo,
        "observed_at": stamp, "window_complete": complete, "prs": prs,
    }
    result = assess_merge(evidence, now=_utc(now))
    # Counts are from observed list entries only; no imaginary full history.
    result["skipped_prs"] = incomplete_sources
    result["window_exhaustive_verified"] = False
    return result


MAX_SOURCE_FILE = 131072


def _verified_public_blob(record: object) -> str:
    """Hash a bounded file and verify its GitHub git-blob SHA-1 identifier.

    The hash is content integrity against the REST source, not a signature,
    license permission, clean supply chain, or human-reviewed provenance.
    """
    raw = _obj(record)
    value = raw.get("content")
    if (raw.get("encoding") != "base64"
            or type(value) is not str or len(value) > 190000
            or type(raw.get("size")) is not int
            or not 0 < raw["size"] <= MAX_SOURCE_FILE
            or type(raw.get("sha")) is not str
            or re.fullmatch(r"[0-9a-f]{40}", raw["sha"]) is None):
        raise SourceUnavailable("public_blob_invalid")
    try:
        content = base64.b64decode("".join(value.splitlines()), validate=True)
    except (ValueError, binascii.Error):
        raise SourceUnavailable("public_blob_invalid") from None
    if len(content) != raw["size"]:
        raise SourceUnavailable("public_blob_size_mismatch")
    git_hash = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    ).hexdigest()
    if git_hash != raw["sha"]:
        raise SourceUnavailable("public_blob_sha_mismatch")
    return hashlib.sha256(content).hexdigest()


_ROOT_MARKERS = frozenset({
    "pyproject.toml", "uv.lock", "requirements.txt", "setup.py",
    "package.json", "package-lock.json", "pnpm-lock.yaml",
    "Cargo.toml", "go.mod", "LICENSE", "LICENSE.txt", "LICENSE.md",
    "NOTICE", "NOTICE.txt", "NOTICE.md",
})
_RECOGNIZED_LANGUAGES = frozenset({
    "Python", "JavaScript", "TypeScript", "Go", "Rust", "Java",
    "Shell", "C", "C++", "C#", "Ruby", "PHP", "Kotlin", "Swift",
})
_PILOT_STEPS = (
    "Подтвердить источник и закрепить точный commit SHA.",
    "Проверить текст LICENSE и NOTICE и условия использования.",
    "Изучить применимые security advisories и зависимости.",
    "Проверить совместимость с целевым проектом в изолированной среде.",
    "Получить разрешение владельца до установки или интеграции.",
)


def _root_metadata(source, canonical: str, sha: str) -> dict:
    """Read pinned root filename metadata only; never download its code."""
    try:
        entries = source.get(f"/repos/{canonical}/contents?ref={sha}")
    except SourceUnavailable as exc:
        if str(exc) in ("github_not_found", "github_forbidden_or_limited"):
            return {"coverage": "NOT_AVAILABLE", "entry_count": 0, "markers": []}
        raise
    if type(entries) is not list:
        raise SourceUnavailable("root_structure_invalid")
    if len(entries) > 512:
        return {"coverage": "PARTIAL", "entry_count": 0, "markers": []}
    markers = set()
    for item in entries:
        if type(item) is not dict or type(item.get("name")) is not str:
            raise SourceUnavailable("root_structure_invalid")
        if item.get("type") == "file" and item["name"] in _ROOT_MARKERS:
            markers.add(item["name"])
    return {
        "coverage": "OBSERVED_PINNED_ROOT",
        "entry_count": len(entries),
        "markers": sorted(markers),
    }


def radar_snapshot(source_repo: str, target_repo: str, *, client=None,
                   now: datetime | None = None) -> dict:
    """Observed immutable GitHub source and declared policy hints; not approval."""
    _repo(target_repo)
    try:
        candidate = validate_slug(source_repo)
    except ValueError:
        raise SourceUnavailable("source_repo_invalid") from None
    source = _reader(client)
    stamp = _iso(now)
    raw = _obj(source.get(f"/repos/{candidate}"))
    canonical = raw.get("full_name")
    if type(canonical) is not str or canonical.lower() != candidate.lower():
        raise SourceUnavailable("source_identity_invalid")
    canonical = validate_slug(canonical)
    branch = raw.get("default_branch")
    if (type(branch) is not str or not 1 <= len(branch) <= 80
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch)
            or ".." in branch or "//" in branch):
        raise SourceUnavailable("source_branch_invalid")
    # Branch names can contain a slash; GitHub's API accepts an encoded segment.
    encoded_branch = urllib.parse.quote(branch, safe="")
    branch_obj = _obj(source.get(f"/repos/{canonical}/branches/{encoded_branch}"))
    sha = _safe_sha(_obj(branch_obj.get("commit")).get("sha"))
    root_meta = _root_metadata(source, canonical, sha)
    language = raw.get("language")
    language = language if type(language) is str and language in _RECOGNIZED_LANGUAGES else "UNKNOWN"
    licence = "UNKNOWN"
    license_digest = None
    try:
        license_record = _obj(source.get(f"/repos/{canonical}/license?ref={sha}"))
        license_digest = _verified_public_blob(license_record)
        license_obj = _obj(license_record.get("license"))
        claimed = license_obj.get("spdx_id")
        from qa_advisor.opensource_radar import LICENCES
        if type(claimed) is str and claimed in LICENCES:
            licence = claimed
    except SourceUnavailable as exc:
        if str(exc) != "github_not_found":
            raise
    # Only conventional root filenames are probed. Missing files do not prove
    # the project has no NOTICE/license obligations anywhere else.
    notice_digest = None
    notice_name = None
    for name in ("NOTICE", "NOTICE.txt", "NOTICE.md"):
        try:
            notice_record = _obj(source.get(
                f"/repos/{canonical}/contents/{name}?ref={sha}"
            ))
        except SourceUnavailable as exc:
            if str(exc) == "github_not_found":
                continue
            raise
        notice_digest = _verified_public_blob(notice_record)
        notice_name = name
        break
    release_date = None
    try:
        release = _obj(source.get(f"/repos/{canonical}/releases/latest"))
        release_date = release.get("published_at")
    except SourceUnavailable as exc:
        if str(exc) != "github_not_found":
            raise
    advisories = "UNKNOWN"
    try:
        safety = _array(source.get(
            f"/repos/{canonical}/security-advisories?per_page=5"
        ), maximum=5)
        advisories = "REPORTED" if safety else "NONE_OBSERVED"
    except SourceUnavailable as exc:
        if str(exc) not in ("github_not_found", "github_forbidden_or_limited"):
            raise
    metadata = {
        "schema": "hermes-ossradar-evidence-v1",
        "source_repo": canonical, "target_repo": target_repo,
        "observed_at": stamp, "commit_sha": sha, "default_branch": branch,
        "is_archived": raw.get("archived"), "is_fork": raw.get("fork"),
        "pushed_at": raw.get("pushed_at"), "last_release_at": release_date,
        "license_spdx": licence, "advisory_signal": advisories,
        "compatibility_signal": "UNKNOWN",
    }
    # The upstream default branch can advance during metadata retrieval.
    # Refuse to combine observations if its current SHA changed.
    final = _obj(source.get(f"/repos/{canonical}/branches/{encoded_branch}"))
    if _safe_sha(_obj(final.get("commit")).get("sha")) != sha:
        raise SourceUnavailable("source_commit_moved_during_capture")
    result = assess_radar(metadata, now=_utc(now))
    result["dominant_language"] = language
    result["root_metadata"] = root_meta
    result["pilot_steps"] = list(_PILOT_STEPS)
    result["release_tag_verified"] = False
    result["license_file_sha256"] = license_digest
    result["notice_file_sha256"] = notice_digest
    result["notice_checked_filename"] = notice_name
    result["notice_status"] = (
        "FOUND_STANDARD_ROOT_FILE" if notice_digest else "NOT_FOUND_STANDARD_ROOT_PATHS"
    )
    # Git blob integrity is not legal license review or full source provenance.
    # Keep assess_radar's source_verified/license_verified=False and owner hold.
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in public GitHub engineering prechecks")
    parser.add_argument("mode", nargs="?", choices=("release-pr", "release-main", "merge-prs", "radar"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--repository", choices=sorted(REPOSITORIES))
    parser.add_argument("--pr", type=int)
    parser.add_argument("--source")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        if args.mode == "release-pr" and args.repository is not None and args.pr is not None and args.source is None:
            result = release_snapshot(args.repository, stage="PR", pr=args.pr)
        elif args.mode == "release-main" and args.repository is not None and args.pr is None and args.source is None:
            result = release_snapshot(args.repository, stage="RELEASE")
        elif args.mode == "merge-prs" and args.repository is not None and args.pr is None and args.source is None:
            result = merge_snapshot(args.repository)
        elif args.mode == "radar" and args.source is not None and args.repository is not None and args.pr is None:
            result = radar_snapshot(args.source, args.repository)
        else:
            raise SourceUnavailable("arguments_invalid")
    except (SourceUnavailable, ValueError, TypeError):
        print(json.dumps({"status": "INCONCLUSIVE", "reason": "source_or_evidence_unavailable",
                          "owner_approval": "NOT_GRANTED", "execution_authorized": False}))
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
