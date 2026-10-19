#!/usr/bin/env python3
"""Add fail-closed cookie-session POST origin guard to pinned BRC relay (#371).

Only changes disposable source checkout. The gateway OAuth /mcp and
device pairing's unauthenticated polling endpoints remain unaffected.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

APP = Path("packages/relay/src/app.ts")
APP_MARKER = "  app.use(cookieParser());"
APP_GUARD = """  // All owner-authorized browser mutations require an exact same-origin
  // Origin value. SameSite=Lax by itself is NOT our CSRF boundary.
  const ownerMutationPaths = new Set([
    '/auth/consent', '/device/verify', '/device/approve',
    '/auth/clients/delete', '/admin/device',
    '/auth/apikeys', '/auth/apikeys/revoke',
  ]);
  const ownerOrigin = new URL(cfg.publicUrl).origin;
  app.use((req, res, next) => {
    if (req.method !== 'POST' || !ownerMutationPaths.has(req.path)) return next();
    const origin = req.headers.origin;
    const fetchSite = req.headers['sec-fetch-site'];
    if (origin !== ownerOrigin || (fetchSite && fetchSite !== 'same-origin')) {
      return res.status(403).type('text/plain').send('HERMES_BROWSER_ORIGIN_DENIED');
    }
    next();
  });"""

# Existing upstream e2e uses synthetic Node requests without browser Origin.
# Add the correct header ONLY at exact known simulation call sites.
E2E_REWRITES = {
    "scripts/e2e-all.mjs": (
        "headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, "
        "body: new URLSearchParams({ user_code: code, decision: 'allow' })",
        "headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' }, "
        "body: new URLSearchParams({ user_code: code, decision: 'allow' })",
    ),
    "scripts/e2e-oauth.mjs": (
        "headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, "
        "body: new URLSearchParams({ pending, decision: 'allow' })",
        "headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' }, "
        "body: new URLSearchParams({ pending, decision: 'allow' })",
    ),
    "scripts/e2e-admin.mjs": (
        "headers: { ...(cookie ? { cookie } : {}), 'content-type': 'application/x-www-form-urlencoded' }",
        "headers: { ...(cookie ? { cookie, origin: base } : {}), 'content-type': 'application/x-www-form-urlencoded' }",
    ),
}


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    originals: dict[Path, str] = {}
    changes: dict[Path, str] = {}
    path = root / APP
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise AuditError("relay_csrf_source_unsafe")
    raw = path.read_text(encoding="utf-8")
    if raw.count(APP_MARKER) != 1 or APP_GUARD in raw:
        raise AuditError("relay_csrf_original_changed")
    originals[path] = raw
    changes[path] = raw.replace(APP_MARKER, APP_MARKER + "\n" + APP_GUARD)

    for name, (old, new) in E2E_REWRITES.items():
        p = root / name
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 60_000:
            raise AuditError("csrf_fixture_source_unsafe")
        raw = p.read_text(encoding="utf-8")
        if raw.count(old) != 1 or new in raw:
            raise AuditError("csrf_fixture_changed")
        originals[p] = raw
        changes[p] = raw.replace(old, new)

    # All known snippets must match before writing any file.
    for path, content in changes.items():
        if content == originals[path]:
            raise AuditError("csrf_patch_has_no_effect")
    for path, content in changes.items():
        path.write_text(content, encoding="utf-8")
    return {
        "status": "BROWSER_CSRF_ORIGIN_GUARD_APPLIED",
        "protected_mutation_count": 7,
        "missing_origin": "DENIED",
        "cross_origin": "DENIED",
        "same_origin": "ALLOWED",
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    a = parser.parse_args()
    try:
        r = apply(a.source_dir, sha=a.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(r, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
