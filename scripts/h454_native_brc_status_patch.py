"""H454: add authoritative bearer-bound native-device status to existing BRC.

Patch only the exact source-pinned upstream relay in isolated CI AFTER
native owner-bound pairing patch. No live endpoint or deployment.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate

APP = Path("packages/relay/src/app.ts")
ANCHOR = "  const requireLogin = (req: Request, res: Response, next: NextFunction) =>"
ROUTE = """  // H454: owner-paired status introspection for native agent revocation.
  // Caller must prove possession of the exact CURRENT bearer; a revoked,
  // paused, foreign or rotated token cannot become an active status.
  app.get('/device/native-status', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const auth = req.headers.authorization;
    if (typeof auth !== 'string' ||
        !/^Bearer [A-Za-z0-9_.~-]{40,256}$/.test(auth) ||
        req.originalUrl !== '/device/native-status') {
      return res.status(403).json({ error: 'native_device_denied' });
    }
    const row = store.getDeviceByToken(auth.slice(7));
    const owner = store.getUserByName(cfg.adminUser);
    const profiles = [
      {name:'H454 Windows native read-only',platform:'win32',
       id:/^h454-win-native-[a-f0-9]{32}$/},
      {name:'H454 Hermes VPS native read-only',platform:'linux',
       id:/^h454-linux-hermes-[a-f0-9]{32}$/},
      {name:'H454 YFC VPS native read-only',platform:'linux',
       id:/^h454-linux-yfc-[a-f0-9]{32}$/},
    ];
    const valid = row && owner && row.user_id === owner.id && row.paused === 0 &&
      profiles.some(p => row.name === p.name && row.platform === p.platform &&
                          p.id.test(row.device_id));
    if (!valid) return res.status(403).json({ error: 'native_device_denied' });
    return res.status(200).json({
      schema:'h454-native-device-status-v1',
      device_id:row.device_id,
      active:true, owner_bound:true,
    });
  });

"""


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    path = root / APP
    if (path.is_symlink() or not path.is_file()
        or path.stat().st_size > 250_000 or path.parent.is_symlink()):
        raise AuditError("h454_status_source_unsafe")
    raw = path.read_text(encoding="utf-8")
    if (raw.count(ANCHOR) != 1
        or raw.count("native_pairing_scope_denied") != 1
        or raw.count("hermesAuthTokenHash") != 1
        or "/device/native-status" in raw):
        raise AuditError("h454_status_pinned_source_drift")
    updated = raw.replace(ANCHOR, ROUTE + ANCHOR, 1)
    if updated == raw or updated.count(ROUTE) != 1:
        raise AuditError("h454_status_patch_failed")
    path.write_text(updated, encoding="utf-8")
    return {"status":"H454_NATIVE_DEVICE_STATUS_PATCHED_SOURCE_ONLY",
            "current_bearer_required":True, "owner_bound":True,
            "live_relay_modified":False}


def main(argv=None) -> int:
    ap=argparse.ArgumentParser(description="H454 BRC native status source patch")
    ap.add_argument("--source-dir",required=True,type=Path)
    args=ap.parse_args(argv)
    try:
        apply(args.source_dir)
        print("H454_NATIVE_BRC_STATUS=SOURCE_PATCHED")
        return 0
    except (AuditError,OSError,ValueError,UnicodeError):
        print("H454_NATIVE_BRC_STATUS=HOLD", file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
