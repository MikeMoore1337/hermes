#!/usr/bin/env python3
"""Validate a bounded development handoff from stdin; no network or writes."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integrations.task_handoff import HandoffRefused, MAX_PACKET_BYTES, validate_json


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_PACKET_BYTES + 1)
    try:
        result = validate_json(raw)
    except HandoffRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
