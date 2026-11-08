#!/usr/bin/env python3
"""Patch the exact pinned BRC relay so an unchanged admin password keeps its hash.

A fresh random scrypt salt on every relay startup changes users.password_hash,
which trips Hermes's strict auth snapshot guard during otherwise safe pair
cutovers. Password rotation must still change the hash and be treated as
security-state drift; this patch never relaxes that guard or edits live SQLite.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate

STORE = Path("packages/relay/src/store/sqlite.ts")
UPSTREAM_STORE_BLOB_SHA = "7ce9f2fab49d98ec9e1ec10ff270167409aad237"
ORIGINAL = """  upsertUser(username: string, password: string): UserRow {
    const existing = this.getUserByName(username);
    const hash = hashPassword(password);
    if (existing) {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, existing.id);
      return { ...existing, password_hash: hash };
    }
"""
PATCHED = """  upsertUser(username: string, password: string): UserRow {
    const existing = this.getUserByName(username);
    // Preserve the persisted verifier for an unchanged password. A real
    // password change still rotates the hash and must fail the auth guard.
    if (existing && verifyPassword(password, existing.password_hash)) {
      return existing;
    }
    const hash = hashPassword(password);
    if (existing) {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, existing.id);
      return { ...existing, password_hash: hash };
    }
"""


def git_blob_sha(raw: bytes) -> str:
    """Git object ID for exact upstream source provenance, not a password hash."""
    payload = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    return hashlib.sha1(payload).hexdigest()


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    cursor = root
    for part in STORE.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise AuditError("admin_store_symlink_refused")
    path = root / STORE
    if not path.is_file() or not 100 <= path.stat().st_size <= 65536:
        raise AuditError("admin_store_missing_or_oversize")
    raw = path.read_bytes()
    if git_blob_sha(raw) != UPSTREAM_STORE_BLOB_SHA:
        raise AuditError("admin_store_source_drift")
    old = ORIGINAL.encode("utf-8")
    if raw.count(old) != 1 or raw.count(PATCHED.encode("utf-8")):
        raise AuditError("admin_store_contract_changed")
    updated = raw.replace(old, PATCHED.encode("utf-8"), 1)
    path.write_bytes(updated)
    return {
        "status": "H454_ADMIN_HASH_STABILITY_PATCHED",
        "upstream_sha": UPSTREAM_SHA,
        "same_password": "PRESERVE_HASH_AND_USER_ID",
        "changed_password": "REHASH_AND_REQUIRE_AUTH_GUARD_REVIEW",
        "auth_guard_relaxed": False,
        "production_activated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        report = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError, UnicodeError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REFUSED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
