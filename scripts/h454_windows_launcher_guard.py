"""Prepare a launcher that refuses automatic starts during a pending transition."""
from __future__ import annotations

import hashlib
import re

from scripts.h15_remote_commander_candidate_audit import AuditError

ANCHOR = """    $runtimeLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
"""
GUARD = """    $h454PendingExists = $false; $h454Entries = 0
    foreach ($h454Entry in [IO.Directory]::EnumerateFileSystemEntries([IO.Path]::GetDirectoryName($STATE_PATH))) {
        $h454Entries++
        Require ($h454Entries -le 512) 'H454_STATE_DIRECTORY_OVERSIZE'
        if ([IO.Path]::GetFileName($h454Entry).Equals('h454-wss-transition.pending', [StringComparison]::OrdinalIgnoreCase)) {
            $h454PendingExists = $true; break
        }
    }
    Require (-not $h454PendingExists) 'H454_RECOVERY_REQUIRED'
"""


def patch_launcher(source: str) -> str:
    if source.count(ANCHOR) != 1 or "h454-wss-transition.pending" in source:
        raise AuditError("unreviewed_launcher_guard_source")
    return source.replace(ANCHOR, ANCHOR + GUARD, 1)


def patch_launcher_bytes(source: bytes, expected_sha256: str) -> bytes:
    """Preserve existing bytes while inserting a guard into a pinned launcher."""
    if (not isinstance(source, bytes) or not 0 < len(source) <= 200_000 or
            not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256) or
            hashlib.sha256(source).hexdigest() != expected_sha256.lower()):
        raise AuditError("unreviewed_launcher_guard_input")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError("unreviewed_launcher_guard_source") from exc
    if "\0" in text or "h454-wss-transition.pending" in text.lower():
        raise AuditError("unreviewed_launcher_guard_source")
    anchors = [(ANCHOR.replace("\n", newline), GUARD.replace("\n", newline))
               for newline in ("\n", "\r\n")]
    matches = [(anchor, guard) for anchor, guard in anchors if text.count(anchor) == 1]
    if len(matches) != 1 or sum(text.count(anchor) for anchor, _ in anchors) != 1:
        raise AuditError("unreviewed_launcher_guard_source")
    anchor, guard = matches[0]
    return text.replace(anchor, anchor + guard, 1).encode("utf-8")
