"""Sandbox preview and bounded public metadata check; never connect a project."""
from __future__ import annotations

import http.client
import json
import re
import threading

from control_center.brc_snapshot import PROJECTS

WINDOWS_DEVICES = frozenset(("con", "prn", "aux", "nul", *(f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(1, 10))))
PUBLIC_RESPONSE_LIMIT = 65_536
PUBLIC_DEADLINE_SECONDS = 6
_public_checks = threading.BoundedSemaphore(2)

GITHUB_URL = re.compile(
    r"https://github\.com/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)/"
    r"([a-z0-9_][a-z0-9_.-]{0,103})/?\Z",
    re.ASCII | re.IGNORECASE,
)


class PreviewRejected(ValueError):
    """Invalid input without reflecting the supplied URL."""


def preview(repository_url: object) -> dict:
    if not isinstance(repository_url, str) or len(repository_url) > 200:
        raise PreviewRejected("invalid_repository_url")
    match = GITHUB_URL.fullmatch(repository_url)
    if not match:
        raise PreviewRejected("invalid_repository_url")
    owner, repo = match.groups()
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not repo or len(repo) > 100 or repo.endswith(".") or ".." in repo:
        raise PreviewRejected("invalid_repository_url")
    name = repo.lower()
    return {
        "schema": 1, "status": "preview_only",
        "repository": f"https://github.com/{owner}/{name}.git",
        "device": "Windows sandbox", "root": f"/workspace/projects/{name}",
        "scope": "sandbox", "catalog": "reserved" if name in PROJECTS or name.partition(".")[0] in WINDOWS_DEVICES else "not_reserved",
        "remote": "not_checked", "filesystem": "not_checked", "can_connect": False,
    }


def check_public_repository(repository_url: str) -> str:
    """Check public GitHub metadata only; never follow redirects or use credentials."""
    value = preview(repository_url)
    if value["catalog"] == "reserved":
        return "not_checked"
    match = GITHUB_URL.fullmatch(value["repository"])
    if match is None:
        raise PreviewRejected("invalid_repository_url")
    owner, repository = match.groups()
    repository = repository[:-4]  # preview() always returns a canonical .git URL.
    if not _public_checks.acquire(blocking=False):
        return "unavailable"
    done = threading.Event()
    result = ["unavailable"]

    def worker():
        connection = None
        try:
            connection = http.client.HTTPSConnection("api.github.com", timeout=4)
            connection.request("GET", f"/repos/{owner}/{repository}", headers={
                "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                "User-Agent": "Hermes-Control-Center/1",
            })
            response = connection.getresponse()
            if response.status != 200:
                return
            raw = response.read(PUBLIC_RESPONSE_LIMIT + 1)
            if len(raw) > PUBLIC_RESPONSE_LIMIT:
                return

            def unique_pairs(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate_json_key")
                    value[key] = item
                return value

            def reject_constant(_):
                raise ValueError("json_constant")

            data = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
            if (not isinstance(data, dict) or data.get("private") is not False
                or data.get("visibility") != "public" or not isinstance(data.get("full_name"), str)
                or not data["full_name"].isascii()
                or data["full_name"].casefold() != (owner + "/" + repository).casefold()):
                return
            result[0] = "public_confirmed"
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            return
        finally:
            try:
                if connection is not None:
                    connection.close()
            except OSError:
                pass
            finally:
                _public_checks.release()
                done.set()

    try:
        threading.Thread(target=worker, daemon=True).start()
    except RuntimeError:
        _public_checks.release()
        return "unavailable"
    return result[0] if done.wait(PUBLIC_DEADLINE_SECONDS) else "unavailable"
