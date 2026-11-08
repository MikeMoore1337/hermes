#!/usr/bin/env python3
"""H454: make the exact pinned BRC relay admin startup idempotent.

The upstream SqliteStore.upsertUser re-salts and overwrites the admin password
hash on every buildRelay(), including a restart with the same secret. The
paired OCI transaction's strict credential regression guard then (correctly)
refuses the snapshot difference. Preserve a verified existing hash; still
rotate the hash when the configured password actually changes.

Applies ONLY to the pinned upstream checkout in disposable CI; no live DB,
host credentials, relay containers, owner approval or rollback state access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate, safe_read,
)

STORE = Path("packages/relay/src/store/sqlite.ts")
# Git blob of upstream STORE at the exact UPSTREAM_SHA, before any Hermes patch.
UPSTREAM_STORE_BLOB = "7ce9f2fab49d98ec9e1ec10ff270167409aad237"

VULNERABLE = """  upsertUser(username: string, password: string): UserRow {
    const existing = this.getUserByName(username);
    const hash = hashPassword(password);
    if (existing) {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, existing.id);
      return { ...existing, password_hash: hash };
    }
    const row: UserRow = { id: randomToken(12), username, password_hash: hash, created_at: Date.now() };
    this.db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(row.id, row.username, row.password_hash, row.created_at);
    return row;
  }"""

PATCHED = """  upsertUser(username: string, password: string): UserRow {
    const existing = this.getUserByName(username);
    // A restart with the same configured password must not replace the
    // salted scrypt hash. A genuinely changed password still rotates it.
    if (existing && verifyPassword(password, existing.password_hash)) {
      return existing;
    }
    const hash = hashPassword(password);
    if (existing) {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, existing.id);
      return { ...existing, password_hash: hash };
    }
    const row: UserRow = { id: randomToken(12), username, password_hash: hash, created_at: Date.now() };
    this.db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(row.id, row.username, row.password_hash, row.created_at);
    return row;
  }"""


def git_blob(text: str) -> str:
    raw = text.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    # The checkout must retain the exact upstream Git revision and all normal
    # audit invariants. No arbitrary local project or production source edits.
    evaluate(root, sha=sha)
    source = safe_read(root, str(STORE))
    if git_blob(source) != UPSTREAM_STORE_BLOB:
        raise AuditError("unreviewed_admin_store_source")
    if source.count(VULNERABLE) != 1 or PATCHED in source:
        raise AuditError("unreviewed_admin_upsert_contract")
    if "export function verifyPassword(" not in source:
        raise AuditError("admin_password_verifier_missing")
    patched = source.replace(VULNERABLE, PATCHED, 1)
    if patched.count(PATCHED) != 1 or VULNERABLE in patched:
        raise AuditError("admin_upsert_patch_not_exact")
    (root / STORE).write_text(patched, encoding="utf-8")
    return {
        "status": "H454_ADMIN_HASH_STARTUP_IDEMPOTENT_SOURCE_PATCH",
        "upstream_sha": sha,
        "admin_hash_preserved_when_password_valid": True,
        "password_rotation_preserved": True,
        "credential_guard_changed": False,
        "production_mutation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        result = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REFUSED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
