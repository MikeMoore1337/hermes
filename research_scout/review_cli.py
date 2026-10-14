"""Explicit stdin-only offline citation report. Never fetches or publishes.

Intended for human-reviewed NCBI ESummary metadata; no model or provider,
no environment credentials and no arbitrary local filesystem path reads.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from typing import Any, BinaryIO, TextIO

from .citation_review import CitationInputError, review_batch

MAX_INPUT_BYTES = 65536


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in pairs:
        if key in clean:
            raise CitationInputError("duplicate_input_json_key")
        clean[key] = value
    return clean


def _deny_constants(_: str) -> Any:
    raise CitationInputError("invalid_nonfinite_json")


def review_payload(payload: bytes, *, now: datetime) -> dict[str, Any]:
    """Consume exactly one bounded JSON array with no implicit assumptions."""
    if type(payload) is not bytes or len(payload) > MAX_INPUT_BYTES:
        raise CitationInputError("input_size_invalid")
    try:
        records = json.loads(
            payload,
            object_pairs_hook=_object_no_duplicates,
            parse_constant=_deny_constants,
        )
    except CitationInputError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise CitationInputError("invalid_input_json") from exc
    return review_batch(records, now=now)


def main(
    argv: list[str] | None = None, *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    now: datetime | None = None,
) -> int:
    """No stdin read without explicit flag, no persistent writes or egress."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-stdin", action="store_true")
    args = parser.parse_args(argv)
    output_stream = output_stream if output_stream is not None else sys.stdout
    if not args.review_stdin:
        result = {"status": "REJECTED", "reason": "explicit_stdin_required"}
    else:
        incoming = input_stream if input_stream is not None else sys.stdin.buffer
        try:
            payload = incoming.read(MAX_INPUT_BYTES + 1)
            result = review_payload(payload, now=now if now is not None
                                    else datetime.now(UTC))
        except (OSError, CitationInputError) as exc:
            reason = str(exc) if isinstance(exc, CitationInputError) else "stdin_unavailable"
            result = {"status": "REJECTED", "reason": reason}
    output_stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    return 0 if result["status"] in ("NO_DATA", "HOLD", "MANUAL_REVIEW") else 2


if __name__ == "__main__":
    raise SystemExit(main())
