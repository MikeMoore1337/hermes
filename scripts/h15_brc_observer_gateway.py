"""#455 pin-only BRC live observation patch — disposable source, never host deploy."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import UPSTREAM_SHA, AuditError, evaluate

APP = Path("packages/relay/src/app.ts")
MODULE = Path("packages/relay/src/hermes-brc-observer.ts")
IMPORT_ANCHOR = "import { DeviceHub } from './device-hub.js';"
OBSERVER_IMPORT = "import { observerEnabled, publishLiveObservation } from './hermes-brc-observer.js';"
START = "  const hub = new DeviceHub(cfg.relayVersion, log);"
TIMER = """  // Owner opt-in through an exact private marker on existing /state.
  // No HTTP route, OAuth bearer, device permission or additional Docker mount.
  const observer = observerEnabled() ? setInterval(() => {
    try {
      if (observerEnabled()) publishLiveObservation(hub, store, admin.id);
    } catch {
      log('warn', 'Hermes BRC observer snapshot refused');
    }
  }, 30_000) : null;
  if (observer) {
    observer.unref();
    try { publishLiveObservation(hub, store, admin.id); }
    catch { log('warn', 'Hermes BRC observer initial snapshot refused'); }
  }
"""
SHUTDOWN = "clearInterval(housekeeping); hub.close();"
OBSERVER_SHUTDOWN = "clearInterval(housekeeping); if (observer) clearInterval(observer); hub.close();"


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    app = root / APP
    target = root / MODULE
    template = Path(__file__).resolve().parents[1] / "deploy/h15/hermes-brc-observer.template.ts"
    for path in (app, target, template):
        if path.is_symlink() or path.parent.is_symlink():
            raise AuditError("observer_source_symlink")
    if (not app.is_file() or target.exists() or app.stat().st_size > 120000
            or not template.is_file() or not 1000 < template.stat().st_size < 20000):
        raise AuditError("observer_source_not_ready")
    before = app.read_text(encoding="utf-8")
    code = template.read_text(encoding="utf-8")
    if any(before.count(marker) != 1 for marker in (IMPORT_ANCHOR, START, SHUTDOWN)):
        raise AuditError("observer_upstream_marker_drift")
    if OBSERVER_IMPORT in before or "publishLiveObservation(" in before:
        raise AuditError("observer_already_patched")
    required = ("sanitizedLiveObservation", "export function observerEnabled",
                "export function publishLiveObservation", "strictParent",
                "fs.renameSync", "fs.fsyncSync", "getuid", "store.listDevices",
                "hub.list", "status.json" if False else "OBSERVER_FILE")
    if not all(marker in code for marker in required):
        raise AuditError("observer_template_guard_missing")
    updated = (before.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "\n" + OBSERVER_IMPORT)
              .replace(START, START + "\n" + TIMER)
              .replace(SHUTDOWN, OBSERVER_SHUTDOWN))
    if updated == before or updated.count("if (observer) clearInterval(observer)") != 1:
        raise AuditError("observer_patch_failed")
    # Only after EVERY source preflight and marker validation do we write.
    target.write_text(code, encoding="utf-8")
    app.write_text(updated, encoding="utf-8")
    return {"status": "DISPOSABLE_OBSERVER_PATCHED",
            "owner_opt_in_required": True, "production_activated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        value = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, UnicodeError, ValueError) as exc:
        print("H455_OBSERVER_PATCH=REFUSED")
        print("REASON=" + (str(exc) if isinstance(exc, AuditError) else type(exc).__name__))
        return 2
    print("H455_OBSERVER_PATCH=PASS")
    print("PRODUCTION_ACTIVATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
