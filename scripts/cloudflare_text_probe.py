"""One-shot Workers Free inference check: one request, no retry or fallback.

This is host-side diagnostic, NOT an agent or a recurring service.
Never log credentials, HTTP bodies, account identifiers or the model's text.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ENV_PATH = Path("/var/lib/hermes-agent/.env")
ALLOWED_MODEL = "@cf/openai/gpt-oss-20b"
BASE_URL = re.compile(
    r"https://api\.cloudflare\.com/client/v4/accounts/[a-fA-F0-9]{32}/ai/v1"
)
ALLOWED_KEYS = frozenset({
    "CLOUDFLARE_WORKERS_AI_API_TOKEN",
    "CLOUDFLARE_WORKERS_AI_BASE_URL",
})


class ProbeError(Exception):
    """Only controlled, non-secret failure categories."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect with a credential."""

    def redirect_request(
        self, req: urllib.request.Request, fp: Any,
        code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def read_env(path: Path = ENV_PATH) -> tuple[str, str]:
    """Read two expected variables without shell sourcing or printing values."""
    if path.is_symlink() or not path.is_file():
        raise ProbeError("credentials_missing")
    mode = path.stat()
    if stat.S_IMODE(mode.st_mode) != 0o600:
        raise ProbeError("credential_permissions")
    values: dict[str, str] = {}
    try:
        contents = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ProbeError("credentials_unreadable") from exc
    if len(contents) > 4096:
        raise ProbeError("credentials_oversized")
    for line in contents.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ProbeError("credentials_malformed")
        name, value = line.split("=", 1)
        if name not in ALLOWED_KEYS or name in values:
            raise ProbeError("credentials_malformed")
        values[name] = value
    token = values.get("CLOUDFLARE_WORKERS_AI_API_TOKEN", "")
    endpoint = values.get("CLOUDFLARE_WORKERS_AI_BASE_URL", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{20,256}", token):
        raise ProbeError("credentials_malformed")
    if BASE_URL.fullmatch(endpoint) is None:
        raise ProbeError("endpoint_not_allowlisted")
    return token, endpoint


def one_request(
    token: str, endpoint: str, *,
    opener: Any = None,
) -> dict[str, Any]:
    """Send a single bounded model request; output sanitized numerical evidence."""
    if BASE_URL.fullmatch(endpoint) is None:
        raise ProbeError("endpoint_not_allowlisted")
    if not re.fullmatch(r"[A-Za-z0-9._-]{20,256}", token):
        raise ProbeError("credentials_malformed")
    payload = {
        "model": ALLOWED_MODEL,
        "messages": [{"role": "user", "content": "Reply exactly with the word: OK"}],
        "reasoning_effort": "low",
        "max_tokens": 160,
        "stream": False,
    }
    request = urllib.request.Request(
        endpoint + "/chat/completions",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    client = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    try:
        with client.open(request, timeout=25) as response:
            status = response.status
            raw = response.read(32768)
    except urllib.error.HTTPError as exc:
        # Error text can contain untrusted account or token content. Do not log it.
        return {"result": "rejected", "http_status": exc.code}
    except (OSError, TimeoutError, urllib.error.URLError):
        return {"result": "network_error"}
    if status != 200:
        return {"result": "rejected", "http_status": status}
    try:
        data = json.loads(raw)
        choices = data["choices"]
        content = choices[0]["message"].get("content")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return {"result": "unexpected_response", "http_status": status}
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    safe_usage = {
        field: value for field in ("prompt_tokens", "completion_tokens", "total_tokens")
        if type(value := usage.get(field)) is int and 0 <= value < 100000
    }
    return {
        "result": "ok" if isinstance(content, str) and "OK" in content.upper() else "model_response_without_expected_text",
        "http_status": status,
        "model": ALLOWED_MODEL,
        "usage": safe_usage,
    }


def main() -> int:
    try:
        token, endpoint = read_env()
        result = one_request(token, endpoint)
        del token
    except ProbeError as exc:
        result = {"result": "configuration_error", "reason": str(exc)}
    except Exception:
        # Fail closed and avoid exception text which can include endpoints/secrets.
        result = {"result": "probe_error"}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["result"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
