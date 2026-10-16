"""Strict systemd LoadCredential text parser (never run shell on secrets)."""
from pathlib import Path
import os
import re


def load_runtime_credentials(name: str, environ=None) -> dict[str, str] | None:
    if name not in ("web.env", "broker.env"):
        raise ValueError("Unknown credential")
    env = os.environ if environ is None else environ
    dirname = env.get("CREDENTIALS_DIRECTORY")
    if not dirname:
        return None
    directory = Path(dirname)
    if not directory.is_absolute():
        raise ValueError("Untrusted credential directory")
    raw = (directory / name).read_bytes()
    if len(raw) > 4096:
        raise ValueError("Credentials too large")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Credential encoding") from exc
    allowed = (
        {"HERMES_CC_AUTH_MODE", "HERMES_CC_PUBLIC_ORIGIN", "HERMES_CC_GITHUB_CLIENT_ID",
         "HERMES_CC_ALLOWED_GITHUB_ID", "HERMES_CC_SESSION_SECRET",
         "HERMES_CC_OAUTH_BROKER_SOCKET"}
        if name == "web.env" else
        {"HERMES_OAUTH_CLIENT_ID", "HERMES_OAUTH_CLIENT_SECRET",
         "HERMES_OAUTH_ALLOWED_GITHUB_ID", "HERMES_OAUTH_SOCKET"}
    )
    values: dict[str, str] = {}
    for line in decoded.splitlines():
        if not line or line.startswith("#"):
            raise ValueError("Empty/comment credential entry not permitted")
        key, sep, value = line.partition("=")
        if not sep or key not in allowed or key in values:
            raise ValueError("Invalid or duplicate credential key")
        if not value or any(ord(char) < 33 for char in value):
            raise ValueError("Credential value missing/control chars")
        values[key] = value
    if set(values) != allowed:
        raise ValueError("Incomplete credential")
    return values
