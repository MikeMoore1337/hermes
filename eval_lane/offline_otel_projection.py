"""H-25 / #192: offline-only, bounded, redacted OTLP/JSON-shaped fixtures.

This module is deliberately NOT a production exporter, instrumentor, collector,
network client or admission authority. It only projects synthetic envelopes.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
import sys
from typing import Any

SCHEMA = "hermes-h25-otel-synthetic-input-v1"
RESULT_SCHEMA = "hermes-h25-otel-synthetic-output-v1"
MAX_INPUT_BYTES = 16384
MAX_OUTPUT_BYTES = 65536
MAX_EVENTS = 32
MAX_DURATION_MS = 600000
MAX_OUTPUT_SIZE = 16384
MAX_ATTEMPTS = 3
SOURCE_SHA = re.compile(r"[a-f0-9]{40}\Z")
TOOLS = frozenset({"ops_watch", "qa_advisor", "research_scout", "other"})
ERRORS = frozenset({"none", "unknown", "timeout", "denied", "execution_error"})
BUDGET = frozenset({"within_limit", "exceeded", "unknown"})
COMPLETENESS = frozenset({"complete", "partial", "unknown"})
EVENT_KEYS = frozenset({
    "kind", "tool", "duration_ms", "error_kind", "attempt_count",
    "retry_count", "budget_state", "output_bytes_bounded",
    "trace_completeness",
})
INPUT_KEYS = frozenset({"schema", "visibility", "source_revision", "sample_stride", "events"})


class OfflineTelemetryDenied(ValueError):
    """Fixed refusal reason. Never echo the untrusted envelope."""


def _bounded_integer(value: Any, maximum: int, code: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OfflineTelemetryDenied(code)
    return value


def _event(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != EVENT_KEYS:
        raise OfflineTelemetryDenied("EVENT_SCHEMA_INVALID")
    kind, tool = value["kind"], value["tool"]
    if kind not in ("turn", "tool") or type(kind) is not str:
        raise OfflineTelemetryDenied("EVENT_KIND_INVALID")
    if (kind == "turn" and tool is not None) or (
        kind == "tool" and (type(tool) is not str or tool not in TOOLS)
    ):
        raise OfflineTelemetryDenied("EVENT_TOOL_INVALID")
    duration = value["duration_ms"]
    if duration is not None:
        _bounded_integer(duration, MAX_DURATION_MS, "EVENT_DURATION_INVALID")
    size = value["output_bytes_bounded"]
    if size is not None:
        _bounded_integer(size, MAX_OUTPUT_SIZE, "EVENT_SIZE_INVALID")
    attempts = _bounded_integer(value["attempt_count"], MAX_ATTEMPTS, "EVENT_ATTEMPTS_INVALID", 1)
    retries = _bounded_integer(value["retry_count"], MAX_ATTEMPTS - 1, "EVENT_RETRIES_INVALID")
    if retries != attempts - 1:
        raise OfflineTelemetryDenied("EVENT_ATTEMPTS_MISMATCH")
    for key, choices in (
        ("error_kind", ERRORS),
        ("budget_state", BUDGET),
        ("trace_completeness", COMPLETENESS),
    ):
        if type(value[key]) is not str or value[key] not in choices:
            raise OfflineTelemetryDenied("EVENT_ENUM_INVALID")
    return value


def _string_attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def _int_attr(key: str, value: int) -> dict[str, Any]:
    return {"key": key, "value": {"intValue": str(value)}}


def _ids(revision: str, index: int) -> tuple[str, str]:
    seed = ("hermes-h25-synthetic:" + revision + ":" + str(index)).encode("ascii")
    digest = sha256(seed).hexdigest()
    return digest[:32], digest[32:48]


def project(payload: Any) -> dict[str, Any]:
    """Pure no-I/O transformation. No identifiers or user-provided text emitted."""
    if type(payload) is not dict or set(payload) != INPUT_KEYS:
        raise OfflineTelemetryDenied("INPUT_SCHEMA_INVALID")
    if payload["schema"] != SCHEMA or payload["visibility"] != "PUBLIC_SYNTHETIC":
        raise OfflineTelemetryDenied("SYNTHETIC_SCOPE_REQUIRED")
    revision = payload["source_revision"]
    if type(revision) is not str or not SOURCE_SHA.fullmatch(revision):
        raise OfflineTelemetryDenied("REVISION_INVALID")
    stride = _bounded_integer(payload["sample_stride"], 16, "SAMPLING_INVALID", 1)
    events = payload["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise OfflineTelemetryDenied("EVENT_COUNT_INVALID")
    # Validate every item, including unsampled ones, before producing output.
    for event in events:
        _event(event)

    spans: list[dict[str, Any]] = []
    known_points: list[dict[str, Any]] = []
    unknown_durations = 0
    error_kinds: dict[str, int] = {}
    for index, event in enumerate(events):
        if index % stride:
            continue
        error = event["error_kind"]
        if error not in ("none", "unknown"):
            error_kinds[error] = error_kinds.get(error, 0) + 1
        duration = event["duration_ms"]
        if duration is None:
            unknown_durations += 1
            continue
        trace_id, span_id = _ids(revision, index)
        # Fixed, clearly synthetic epoch; never derive timestamps from host.
        start = 1700000000000000000 + index * 1000000000000
        end = start + duration * 1000000
        attrs = [
            _string_attr("hermes.event.kind", event["kind"]),
            _string_attr("hermes.tool.category", event["tool"] or "none"),
            _string_attr("hermes.error.kind", error),
            _string_attr("hermes.budget.state", event["budget_state"]),
            _string_attr("hermes.trace.completeness", event["trace_completeness"]),
            _int_attr("hermes.attempt.count", event["attempt_count"]),
            _int_attr("hermes.retry.count", event["retry_count"]),
        ]
        if event["output_bytes_bounded"] is not None:
            attrs.append(_int_attr("hermes.output.bytes.bounded", event["output_bytes_bounded"]))
        spans.append({
            "traceId": trace_id, "spanId": span_id,
            "name": "hermes.synthetic." + event["kind"],
            "kind": 1, "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(end), "attributes": attrs,
            "status": {"code": 2 if error not in ("none", "unknown") else 1},
        })
        known_points.append({
            "attributes": [_string_attr("hermes.event.kind", event["kind"])],
            "timeUnixNano": str(end), "asInt": str(duration),
        })

    resource = {
        "attributes": [
            _string_attr("service.name", "hermes-synthetic-offline"),
            _string_attr("hermes.source.revision", revision),
        ]
    }
    metrics: list[dict[str, Any]] = []
    if known_points:
        metrics.append({
            "name": "hermes.synthetic.duration",
            "unit": "ms", "gauge": {"dataPoints": known_points},
        })
    if error_kinds:
        metrics.append({
            "name": "hermes.synthetic.errors",
            "unit": "1", "gauge": {
                "dataPoints": [
                    {"attributes": [_string_attr("hermes.error.kind", kind)],
                     "timeUnixNano": "1700000000000000000", "asInt": str(count)}
                    for kind, count in sorted(error_kinds.items())
                ]
            },
        })
    result = {
        "schema": RESULT_SCHEMA, "status": "SYNTHETIC_NO_EXPORT",
        "otlp_json_candidate": {
            "resourceSpans": [{"resource": resource, "scopeSpans": [{
                "scope": {"name": "hermes.h25.offline.fixture.v1"},
                "spans": spans,
            }]}],
            "resourceMetrics": [{"resource": resource, "scopeMetrics": [{
                "scope": {"name": "hermes.h25.offline.fixture.v1"},
                "metrics": metrics,
            }]}],
        },
        "review": {
            "input_events": len(events), "sampled_events": len(range(0, len(events), stride)),
            "sampling_stride": stride, "unknown_duration_events": unknown_durations,
            "unknown_cost": True, "unknown_tokens": True,
            "collector_writes": 0, "network_calls": 0, "files_written": 0,
            "runtime_go": False, "independent_live_evidence": False,
            "retention": "MEMORY_ONLY", "drop_on_overflow": "REFUSE_WHOLE_BATCH",
        },
    }
    if len(json.dumps(result, separators=(",", ":")).encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise OfflineTelemetryDenied("OUTPUT_SIZE_LIMIT")
    return result


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OfflineTelemetryDenied("DUPLICATE_KEY")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="H-25 OFFLINE synthetic OTLP JSON review")
    parser.add_argument("--stdin", action="store_true", required=True)
    parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if not raw or len(raw) > MAX_INPUT_BYTES:
            raise OfflineTelemetryDenied("INPUT_SIZE_LIMIT")
        data = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                OfflineTelemetryDenied("NONFINITE_NUMBER")
            ),
        )
        result = project(data)
        code = 0
    except (OfflineTelemetryDenied, ValueError, TypeError, UnicodeError, OverflowError):
        result = {"schema": RESULT_SCHEMA, "status": "REFUSED",
                  "reason": "UNTRUSTED_OR_INVALID_SYNTHETIC_INPUT",
                  "collector_writes": 0, "network_calls": 0}
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
