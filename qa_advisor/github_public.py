"""Opt-in one-shot GitHub Actions metadata, public YFC or scoped private Hermes.

Private access requires an explicit root-owned 0600 file with a narrowly
scoped Actions: read token. No raw logs, retries, redirects or write actions.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
import re
import urllib.error
import urllib.request
from typing import Any

from qa_advisor.core import ALLOWED_REPOS, InvalidEvidence, analyze

MAX_RUNS = 3
MAX_BODY_BYTES = 700_000
API_ORIGIN = "https://api.github.com"
PRIVATE_REPO = "MikeMoore1337/hermes"
TOKEN_FILE = Path("/etc/hermes-agent/github-actions-read.token")
MAX_TOKEN_BYTES = 255


class GithubPublicError(ValueError):
    """Sanitized refusal without including HTTP bodies or secrets."""


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def public_opener():
    """Ignore environment proxies and reject redirects for this read-only call."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), RefuseRedirect()
    )


def _private_token(path: Path) -> str:
    """Load only owner-controlled scoped credential; never log its value."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise GithubPublicError("github_private_token_unavailable") from None
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1 or metadata.st_size > MAX_TOKEN_BYTES):
            raise GithubPublicError("github_token_file_unsafe")
        try:
            token = os.read(fd, MAX_TOKEN_BYTES + 1).decode("ascii").strip()
        except (OSError, UnicodeError):
            raise GithubPublicError("github_private_token_invalid") from None
    finally:
        os.close(fd)
    if (not 20 <= len(token) <= MAX_TOKEN_BYTES
            or not token.isascii() or not token.isprintable()
            or any(ch.isspace() for ch in token)):
        raise GithubPublicError("github_private_token_invalid")
    return token


def get_json(path: str, *, opener: Any = None, token: str | None = None) -> dict[str, Any]:
    if not re.fullmatch(
        r"/repos/MikeMoore1337/(?:hermes|your-fitness-coach)/actions/runs\?per_page=3",
        path,
    ):
        raise GithubPublicError("endpoint_not_allowlisted")
    is_private = path.startswith("/repos/MikeMoore1337/hermes/")
    if is_private and token is None:
        raise GithubPublicError("github_private_token_required")
    if not is_private and token is not None:
        raise GithubPublicError("github_token_scope_denied")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Hermes-QA-Advisor-Readonly/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token is not None:
        if (type(token) is not str or not 20 <= len(token) <= MAX_TOKEN_BYTES
                or not token.isascii() or not token.isprintable()
                or any(ch.isspace() for ch in token)):
            raise GithubPublicError("github_private_token_invalid")
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        API_ORIGIN + path, headers=headers, method="GET"
    )
    try:
        with (opener or public_opener()).open(request, timeout=12) as response:
            if response.status != 200:
                raise GithubPublicError("public_api_unavailable")
            body = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # No raw URL body, rate-limit metadata, token or other sensitive detail.
        if exc.code in (403, 429):
            raise GithubPublicError("public_rate_limited_or_denied") from None
        raise GithubPublicError("public_api_http_error") from None
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise GithubPublicError("public_api_network_error") from None
    if len(body) > MAX_BODY_BYTES:
        raise GithubPublicError("response_too_large")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise GithubPublicError("invalid_public_json") from None
    if not isinstance(data, dict):
        raise GithubPublicError("invalid_public_shape")
    return data


def public_runs(
    repo: str, *, opener: Any = None, token_file: Path = TOKEN_FILE,
) -> list[dict[str, Any]]:
    """Whitelist public REST fields before passing into the offline analyzer."""
    if repo not in ALLOWED_REPOS:
        raise GithubPublicError("repository_not_allowlisted")
    token = _private_token(token_file) if repo == PRIVATE_REPO else None
    data = get_json(
        f"/repos/{repo}/actions/runs?per_page=3", opener=opener, token=token
    )
    incoming = data.get("workflow_runs")
    if not isinstance(incoming, list) or len(incoming) > MAX_RUNS:
        raise GithubPublicError("unexpected_run_collection")
    result = []
    for run in incoming:
        if not isinstance(run, dict):
            raise GithubPublicError("unexpected_run_collection")
        workflow_id = run.get("workflow_id")
        if type(workflow_id) is not int or not 1 <= workflow_id <= 10**18:
            raise GithubPublicError("workflow_id_missing")
        result.append({
            "repo": repo,
            "workflow": f"workflow-{workflow_id}",
            "run_id": run.get("id"),
            "head_sha": run.get("head_sha"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            # No extra API request/secret needed. No raw CI job logs.
            "jobs": [],
        })
    try:
        analyze(result)  # schema validation before making data available
    except InvalidEvidence:
        raise GithubPublicError("unexpected_run_metadata") from None
    return result


def run_public_report(
    repo: str, *, opener: Any = None, token_file: Path = TOKEN_FILE,
) -> dict[str, Any]:
    return analyze(public_runs(repo, opener=opener, token_file=token_file))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, choices=sorted(ALLOWED_REPOS))
    args = parser.parse_args()
    try:
        result = run_public_report(args.repository)
    except GithubPublicError as exc:
        result = {"status": "UNKNOWN", "reason": str(exc), "findings": []}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] != "UNKNOWN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
