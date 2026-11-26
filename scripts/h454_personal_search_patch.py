"""Prepare bounded search exclusions in the exact pinned BRC agent build.

The caller applies this only to an isolated candidate release, not a project.
"""
from __future__ import annotations

import hashlib
import json

SOURCE_SHA256 = "5c07c11c2dbfb08f867eba82019b7acdb33104c85fc0a93dede47a6e07b758f3"
BLOCKED = (".git", ".hg", ".svn", ".ssh", ".aws", ".gnupg", ".kube", ".terraform",
           ".next", ".cache", "node_modules", "__pycache__", "vault", ".vault",
           "private-vault", "secrets", ".secrets", "credentials", ".env")
SENSITIVE = ("secret", "secrets", "credential", "credentials", "token", "tokens",
             "password", "passwords", "apikey", "apikeys", "api-key", "api-keys",
             "api_key", "api_keys", "serviceaccount", "serviceaccounts", "service-account",
             "service-accounts", "service_account", "service_accounts", "privatekey", "privatekeys",
             "private-key", "private-keys", "private_key", "private_keys", "configlocal",
             "config.local", "config-local", "config_local")


def exclusions() -> tuple[str, ...]:
    rules = set()
    for name in BLOCKED:
        rules.update((f"!**/{name}", f"!**/{name}/**"))
    rules.update(("!**/.env.*", "!**/.env.*/**"))
    for stem in SENSITIVE:
        for prefix in (stem, "." + stem):
            for name in (prefix, prefix + "[._-]*"):
                rules.update((f"!**/{name}", f"!**/{name}/**"))
    rules.update(f"!**/*{suffix}" for suffix in (".pem", ".key", ".pfx", ".p12", ".kdbx"))
    return tuple(sorted(rules))


def patch(source: bytes) -> bytes:
    """Bind exclusions to both rg modes without changing the upstream checkout."""
    if type(source) is not bytes or hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("personal_search_patch_denied")
    file_anchor = b"            args.push(options.rootPath);\n"
    content_anchor = b"            args.push('--', options.pattern, options.rootPath);\n"
    if source.count(file_anchor) != 1 or source.count(content_anchor) != 1:
        raise ValueError("personal_search_patch_denied")
    rules = json.dumps(exclusions(), separators=(",", ":")).encode("ascii")
    insert = b"            for (const rule of " + rules + b") args.push('--iglob', rule);\n"
    return source.replace(file_anchor, insert + file_anchor, 1).replace(content_anchor, insert + content_anchor, 1)
