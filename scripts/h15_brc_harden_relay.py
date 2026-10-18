#!/usr/bin/env python3
"""Fail-closed source-only BRC WSS hardening (#371).

Pinned MIT upstream only. Rewrites known relay authorization code so device
tokens cannot be accepted from query strings. Does not run on owner machines.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

RELAY = Path("packages/relay/src/app.ts")
VULNERABLE = """    const h = req.headers.authorization;
    const token = h?.startsWith('Bearer ') ? h.slice(7).trim() : url.searchParams.get('token');
    const dev = token ? store.getDeviceByToken(token) : undefined;"""
PATCHED = """    // Reject URI device tokens even when a valid Authorization header is
    // supplied. URI query params can be stored in reverse-proxy/access logs.
    if (url.searchParams.has('token')) {
      socket.write('HTTP/1.1 401 Unauthorized\\r\\n\\r\\n');
      return socket.destroy();
    }
    const h = req.headers.authorization;
    const token = h?.startsWith('Bearer ') ? h.slice(7).trim() : undefined;
    const dev = token ? store.getDeviceByToken(token) : undefined;"""


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    path = root / RELAY
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 250_000:
        raise AuditError("relay_source_unsafe")
    original = path.read_text(encoding="utf-8")
    if original.count(VULNERABLE) != 1 or PATCHED in original:
        raise AuditError("unreviewed_ws_auth_source")
    replacement = original.replace(VULNERABLE, PATCHED)
    if "url.searchParams.get('token')" in replacement:
        raise AuditError("url_token_fallback_remaining")
    if "const dev = token ? store.getDeviceByToken(token)" not in replacement:
        raise AuditError("device_authorization_removed")
    path.write_text(replacement, encoding="utf-8")
    return {
        "status": "WSS_AUTH_SOURCE_HARDENED",
        "sha": sha,
        "ws_uri_token": "DENIED",
        "ws_bearer_header": "REQUIRED",
        "production_ready": False,
        "owner_agents_modified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        result = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
