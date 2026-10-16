"""Generate a narrowly scoped Caddy callback no-access-log config candidate.

This command never modifies Caddy, never reads OAuth secrets and never reloads
services. Review the resulting candidate and deploy with backup + rollback.
"""
from __future__ import annotations

import argparse
from pathlib import Path


HTTPS = "https://hermes.mikemoore.top:8444 {"
HTTP = "http://hermes.mikemoore.top {"
GUARD = "    log_skip /auth/github/callback*"


class CaddyGuardError(ValueError):
    pass


def render(source: str) -> str:
    if not isinstance(source, str):
        raise CaddyGuardError("Source must be text")
    if source.count(HTTPS) != 1 or source.count(HTTP) != 1:
        raise CaddyGuardError("Unexpected Hermes Caddy site block count")
    if source.count("    basic_auth {") != 1:
        raise CaddyGuardError("Missing Hermes Basic Auth security boundary")
    if source.count("    reverse_proxy 127.0.0.1:9133 {") != 1:
        raise CaddyGuardError("Unexpected Hermes reverse proxy target")
    if "log_skip" in source or "log_append" in source:
        raise CaddyGuardError("Existing log policy requires explicit review")
    if "https://hermes.mikemoore.top:8444 {" not in source:
        raise CaddyGuardError("Missing TLS site")
    for anchor in (HTTPS, HTTP):
        source = source.replace(anchor + "\n", anchor + "\n" + GUARD + "\n", 1)
    if source.count(GUARD) != 2:
        raise CaddyGuardError("Callback logging exclusions not inserted")
    return source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.candidate.resolve():
        parser.error("Never overwrite the existing production site")
    if args.candidate.exists():
        parser.error("Refuse to overwrite candidate")
    if args.source.stat().st_size > 8192:
        parser.error("Unexpectedly large Caddy site")
    content = render(args.source.read_text(encoding="utf-8"))
    with args.candidate.open("x", encoding="utf-8") as output:
        output.write(content)
    print("Candidate generated; production config NOT modified.")
    print("Review, caddy validate, backup, apply/reload, negative log probe and rollback manually.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
