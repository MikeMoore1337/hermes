"""Offline JSON snapshot analysis with no collection or delivery capabilities."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from .core import InputError, analyze, changes

MAX_INPUT_BYTES = 65_536


def _load(path: Path) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_INPUT_BYTES:
        raise InputError("invalid input file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InputError("invalid JSON file") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Ops Watch assessor")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--previous", type=Path, help="Prior findings JSON list")
    args = parser.parse_args()
    try:
        snapshot = _load(args.snapshot)
        findings = analyze(snapshot, now=datetime.now(UTC))
        result: dict[str, object] = {"findings": findings}
        if args.previous:
            previous = _load(args.previous)
            if not isinstance(previous, list):
                raise InputError("previous findings must be an array")
            result["changes"] = changes(previous, findings)
    except (InputError, OSError, TypeError, ValueError) as exc:
        # Не повторять содержимое недоверенных файлов в диагностике.
        print(json.dumps({"status": "rejected", "reason": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
