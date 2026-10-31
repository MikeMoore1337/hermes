"""Prepare a launcher that refuses automatic starts during a pending transition."""
from __future__ import annotations

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
