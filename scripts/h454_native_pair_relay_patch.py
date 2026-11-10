"""H454: owner-bound native IDs in existing BRC device/poll (disposable only).

Patch a verified pinned better-remote-commander checkout AFTER existing
relay WSS hardening. This is NOT a new MCP server or a production cutover.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate
from scripts.h15_brc_harden_relay import ROTATE_PATCH

APP = Path("packages/relay/src/app.ts")
ANCHOR = "    const deviceId = device_id || row.device_id || "
BLOCK = """    // H454: native ID comes from the authenticated owner's bound device
    // code, NEVER from agent-controlled device_id or a spoofed name.
    const nativeProfile = [
      { name: 'H454 Windows native read-only', platform: 'win32',
        id: /^h454-win-native-[0-9a-f]{32}$/ },
      { name: 'H454 Hermes VPS native read-only', platform: 'linux',
        id: /^h454-linux-hermes-[0-9a-f]{32}$/ },
      { name: 'H454 YFC VPS native read-only', platform: 'linux',
        id: /^h454-linux-yfc-[0-9a-f]{32}$/ },
    ].find(p => p.name === row.client_name);
    const nativeReserved = !!nativeProfile
      || row.device_id?.startsWith('h454-')
      || (typeof device_id === 'string' && device_id.startsWith('h454-'))
      || name?.startsWith('H454 ');
    if (nativeReserved) {
      if (!nativeProfile || typeof row.device_id !== 'string'
          || !nativeProfile.id.test(row.device_id)
          || device_id !== undefined
          || name !== nativeProfile.name || platform !== nativeProfile.platform
          || store.getDevice(row.device_id)) {
        return res.status(403).json({ error: 'native_pairing_scope_denied' });
      }
    }
"""


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    path = root / APP
    if (path.is_symlink() or not path.is_file()
        or path.stat().st_size > 250_000 or path.parent.is_symlink()):
        raise AuditError("native_pair_relay_source_unsafe")
    original = path.read_text(encoding="utf-8")
    if (original.count(ANCHOR) != 1
        or original.count(ROTATE_PATCH) != 1
        or "native_pairing_scope_denied" in original
        or "store.getDeviceByToken(token)" not in original):
        raise AuditError("native_pair_relay_source_drift")
    patched = original.replace(ANCHOR, BLOCK + ANCHOR, 1)
    if (patched == original or patched.count(BLOCK) != 1
        or patched.index(BLOCK) >= patched.index(ROTATE_PATCH)):
        raise AuditError("native_pair_relay_patch_failed")
    path.write_text(patched, encoding="utf-8")
    return {
        "status": "H454_NATIVE_OWNER_ID_RELAY_PATCHED_SOURCE_ONLY",
        "owner_bound_native_id": True,
        "agent_override": "DENIED",
        "native_devices": 3, "production_modified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        apply(args.source_dir)
        print("H454_NATIVE_OWNER_PAIR_RELAY=SOURCE_PATCHED")
        return 0
    except (OSError, UnicodeError, AuditError, ValueError):
        print("H454_NATIVE_OWNER_PAIR_RELAY=HOLD", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
