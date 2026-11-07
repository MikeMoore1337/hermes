"""Prepare a pinned, WSS-only Windows agent in a disposable upstream checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate

TARGET = Path("packages/agent/src/transport/ws-client.ts")
SOURCE_SHA256 = "9fc6d76b90bfc0802f506fe9753c6d729eaf49eb0c1a936be2b179384750f96a"
IMPORT = "import WebSocket from 'ws';"
URL = "    this.wsUrl = WsClient.toWsUrl(opts.relayUrl);"
OPTIONS = "      handshakeTimeout: 15_000,"


def patch_source(source: str) -> str:
    replacements = (
        (IMPORT, IMPORT + "\nimport { readFileSync } from 'node:fs';\n"
         "const relayCA = readFileSync('/opt/hermes-brc/relay-ca.pem');\n"
         "// ws forwards Node TLS options, but its types omit servername.\n"
         "const relayTls = { ca: relayCA, servername: 'brc-agent.internal', rejectUnauthorized: true };"),
        (URL, URL + "\n    const target = new URL(this.wsUrl);\n"
         "    if (target.protocol !== 'wss:' || target.hostname !== 'host.docker.internal' ||\n"
         "        target.port !== '38184' || target.pathname !== '/ws' || target.username ||\n"
         "        target.password || target.search || target.hash) throw new Error('WSS_TARGET_REFUSED');"),
        (OPTIONS, "      ...relayTls,\n" + OPTIONS),
    )
    if any(source.count(old) != 1 or new in source for old, new in replacements):
        raise AuditError("unreviewed_wss_source")
    for old, new in replacements:
        source = source.replace(old, new, 1)
    return source


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    evaluate(root, sha=sha)
    target = root
    for part in TARGET.parts:
        target = target / part
        if target.is_symlink():
            raise AuditError("unsafe_wss_source")
    if not target.is_file() or target.stat().st_size > 100_000:
        raise AuditError("unsafe_wss_source")
    raw = target.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise AuditError("unreviewed_wss_digest")
    updated = patch_source(raw.decode("utf-8")).encode("utf-8")
    target.write_bytes(updated)
    return {"status": "PATCHED_DISPOSABLE_SOURCE", "source_sha": sha,
            "tls": "PER_CONNECTION_PINNED_CA_AND_NAME", "production_activated": False}


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
