"""One-shot read-only GitHub Actions metadata client for PUBLIC owner repos only.

This is a host diagnostic, not the Hermes Agent network profile. Never use
GitHub tokens, private logs, automatic actions, retries or redirects.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from qa_advisor.core import ALLOWED_REPOS, InvalidEvidence, analyze

MAX_RUNS = 3
MAX_BODY_BYTES = 700_000
API_ORIGIN = "https://api.github.com"


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


def get_json(path: str, *, opener: Any = None) -> dict[str, Any]:
    if not re.fullmatch(
        r"/repos/MikeMoore1337/(?:hermes|your-fitness-coach)/actions/runs\?per_page=3",
        path,
    ):
        raise GithubPublicError("endpoint_not_allowlisted")
    request = urllib.request.Request(
        API_ORIGIN + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Hermes-QA-Advisor-Readonly/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    if request.headers.get("Authorization") is not None:
        raise GithubPublicError("authorization_not_allowed")
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


def public_runs(repo: str, *, opener: Any = None) -> list[dict[str, Any]]:
    """Whitelist public REST fields before passing into the offline analyzer."""
    if repo not in ALLOWED_REPOS:
        raise GithubPublicError("repository_not_allowlisted")
    data = get_json(f"/repos/{repo}/actions/runs?per_page=3", opener=opener)
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


def run_public_report(repo: str, *, opener: Any = None) -> dict[str, Any]:
    return analyze(public_runs(repo, opener=opener))


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
