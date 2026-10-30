"""Non-executing sandbox project preview; this does not connect a project."""
from __future__ import annotations

import re

from control_center.brc_snapshot import PROJECTS

WINDOWS_DEVICES = frozenset(("con", "prn", "aux", "nul", *(f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(1, 10))))

GITHUB_URL = re.compile(
    r"https://github\.com/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)/"
    r"([a-z][a-z0-9-]{1,79})(?:\.git)?/?\Z",
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
    name = repo.lower()
    return {
        "schema": 1, "status": "preview_only",
        "repository": f"https://github.com/{owner}/{name}.git",
        "device": "Windows sandbox", "root": f"/workspace/projects/{name}",
        "scope": "sandbox", "catalog": "reserved" if name in PROJECTS or name in WINDOWS_DEVICES else "not_reserved",
        "remote": "not_checked", "filesystem": "not_checked", "can_connect": False,
    }
