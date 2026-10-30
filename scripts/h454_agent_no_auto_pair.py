"""Patch a disposable pinned BRC source for an already-paired Windows agent."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate

CLI = Path("packages/agent/src/cli.ts")
CLI_SHA256 = "6634171d89959b8b645d29e687fff7db7b8f2e61883352cd540d32391c5caa03"
IMPORT = "import { pairDevice, loadCredentials, clearCredentials, saveCredentials, type DeviceCredentials } from './transport/pairing.js';"
NO_SAVED = "  return pairDevice({ relayUrl: relayArg, name, deviceId, openBrowser: !flag('no-browser'), log: (m) => console.log(m) });"
UNAUTHORIZED = """    onUnauthorized: async () => {
      if (c.pairedAt === 'manual') return false;
      log('warn', 'Relay rejected our device token; re-pairing');
      clearCredentials();
      const fresh = await pairDevice({ relayUrl: c.relayUrl, name: c.name, deviceId: c.deviceId, openBrowser: !flag('no-browser'), log: (m) => console.log(m) });
      saveCredentials(fresh);
      start(fresh);
      return true;
    },"""


def patch_cli(source: str) -> str:
    replacements = (
        (IMPORT, "import { loadCredentials, clearCredentials, type DeviceCredentials } from './transport/pairing.js';"),
        (NO_SAVED, "  console.error('Existing credentials required; automatic pairing disabled.');\n  process.exit(2);"),
        (UNAUTHORIZED, "    onUnauthorized: async () => {\n"
         "      log('error', 'Device authorization refused; staged credentials retained.');\n"
         "      return true;\n    },"),
    )
    if (any(source.count(old) != 1 or new in source for old, new in replacements)
        or source.count("pairDevice(") != 2 or source.count("saveCredentials(") != 1
        or source.count("clearCredentials()") != 2):
        raise AuditError("unreviewed_auto_pair_source")
    for old, new in replacements:
        source = source.replace(old, new, 1)
    if "pairDevice" in source or "saveCredentials" in source or source.count("clearCredentials()") != 1:
        raise AuditError("auto_pair_patch_incomplete")
    return source


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    evaluate(root, sha=sha)
    target = root
    for part in CLI.parts:
        target = target / part
        if target.is_symlink():
            raise AuditError("unsafe_auto_pair_source")
    if not target.is_file() or target.stat().st_size > 100_000:
        raise AuditError("unsafe_auto_pair_source")
    raw = target.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CLI_SHA256:
        raise AuditError("unreviewed_auto_pair_digest")
    updated = patch_cli(raw.decode("utf-8")).encode("utf-8")
    target.write_bytes(updated)
    return {"status": "PATCHED_DISPOSABLE_SOURCE", "source_sha": sha,
            "unauthorized": "STOP_AND_RETAIN_CREDENTIALS",
            "missing_credentials": "FAIL_WITHOUT_PAIRING", "production_activated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        result = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc) if isinstance(exc, AuditError)
                          else type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
