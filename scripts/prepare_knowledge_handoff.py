#!/usr/bin/env python3
"""Format a manually reviewed knowledge draft from standard input.

This program makes zero network calls and no filesystem writes.
Input: {"handoff": <I1 packet>, "facts": <reviewed short fields>}.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integrations.knowledge_handoff import DraftRefused, prepare_review_draft
from integrations.task_handoff import HandoffRefused, _pairs

MAX_INPUT = 12_288


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        print(json.dumps({"status": "REFUSED", "reason": "draft_input_oversize"}))
        return 2
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        if type(value) is not dict or set(value) != {"handoff", "facts"}:
            raise DraftRefused("draft_input_fields_invalid")
        result = prepare_review_draft(value["handoff"], value["facts"])
    except (UnicodeError, ValueError, HandoffRefused) as exc:
        reason = str(exc) if isinstance(exc, (DraftRefused, HandoffRefused)) else "draft_input_invalid"
        print(json.dumps({"status": "REFUSED", "reason": reason}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
