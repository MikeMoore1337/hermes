"""Offline-only CLI for one H-12 SEO research packet (JSON or Markdown)."""
from __future__ import annotations

import argparse
import json
import sys

from marketing.seo_research import SeoResearchDenied, build_packet

MAX_STDIN_BYTES = 256 * 1024


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build one offline SEO evidence packet")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            raise SeoResearchDenied("input_too_large")
        payload = json.loads(raw)
        packet = build_packet(payload)
    except SeoResearchDenied as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}))
        return 2
    except (ValueError, TypeError, RecursionError):
        print(json.dumps({"status": "REJECTED", "reason": "input_invalid"}))
        return 2
    if args.format == "markdown":
        print(packet["markdown"], end="")
    else:
        print(json.dumps(packet, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
