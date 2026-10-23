"""H-25 #192: deterministic synthetic-only OpenTelemetry candidate tests."""
from __future__ import annotations

import copy
import json
import unittest

from eval_lane.offline_otel_projection import (
    OfflineTelemetryDenied, SCHEMA, MAX_EVENTS, project, _no_duplicate_keys,
)

REVISION = "a" * 40


def event(**changes):
    result = {
        "kind": "tool", "tool": "ops_watch",
        "duration_ms": 13, "error_kind": "none",
        "attempt_count": 1, "retry_count": 0,
        "budget_state": "within_limit",
        "output_bytes_bounded": 120,
        "trace_completeness": "complete",
    }
    result.update(changes)
    return result


def payload(*events, **changes):
    result = {
        "schema": SCHEMA, "visibility": "PUBLIC_SYNTHETIC",
        "source_revision": REVISION, "sample_stride": 1,
        "events": list(events or (event(),)),
    }
    result.update(changes)
    return result


class SyntheticOtelTests(unittest.TestCase):
    def test_known_duration_emits_structured_trace_and_gauge(self):
        result = project(payload(event()))
        otlp = result["otlp_json_candidate"]
        span = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertRegex(span["traceId"], r"^[a-f0-9]{32}$")
        self.assertRegex(span["spanId"], r"^[a-f0-9]{16}$")
        self.assertEqual("hermes.synthetic.tool", span["name"])
        self.assertEqual(1, span["status"]["code"])
        metric = otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
        self.assertEqual("hermes.synthetic.duration", metric["name"])
        self.assertEqual("ms", metric["unit"])
        self.assertEqual("13", metric["gauge"]["dataPoints"][0]["asInt"])
        self.assertEqual("SYNTHETIC_NO_EXPORT", result["status"])
        self.assertEqual(0, result["review"]["network_calls"])

    def test_unknown_duration_absent_not_zero(self):
        result = project(payload(event(duration_ms=None, error_kind="unknown",
                                       output_bytes_bounded=None, budget_state="unknown",
                                       trace_completeness="unknown")))
        self.assertEqual([], result["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"])
        self.assertEqual([], result["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"])
        self.assertEqual(1, result["review"]["unknown_duration_events"])
        self.assertTrue(result["review"]["unknown_cost"])
        self.assertTrue(result["review"]["unknown_tokens"])

    def test_zero_duration_is_valid_known_measurement(self):
        result = project(payload(event(duration_ms=0)))
        point = result["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0]
        self.assertEqual("0", point["asInt"])
        self.assertEqual(0, result["review"]["unknown_duration_events"])

    def test_error_type_is_strict_enum_and_does_not_echo_error_details(self):
        result = project(payload(event(error_kind="timeout", budget_state="exceeded")))
        span = result["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(2, span["status"]["code"])
        metrics = result["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        self.assertEqual("hermes.synthetic.errors", metrics[1]["name"])
        self.assertEqual("1", metrics[1]["gauge"]["dataPoints"][0]["asInt"])
        poison = payload(event(error_kind="timeout: TOKEN-SECRET"))
        with self.assertRaisesRegex(OfflineTelemetryDenied, "EVENT_ENUM_INVALID"):
            project(poison)

    def test_sampling_stride_is_deterministic(self):
        result = project(payload(*[event() for _ in range(5)], sample_stride=2))
        self.assertEqual(3, result["review"]["sampled_events"])
        self.assertEqual(3, len(result["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"]))

    def test_sampled_unknown_duration_does_not_fabricate_metric(self):
        result = project(payload(
            event(duration_ms=None),
            event(duration_ms=12),
            sample_stride=2,
        ))
        self.assertEqual(1, result["review"]["unknown_duration_events"])
        self.assertEqual([], result["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"])

    def test_redacted_payload_does_not_contain_secrets_or_content(self):
        result = project(payload(event(kind="turn", tool=None, output_bytes_bounded=None)))
        text = json.dumps(result)
        for marker in ("prompt", "response", "secret", "api_key", "user_id",
                       "file_path", "process_command", "credentials", "/home/"):
            self.assertNotIn(marker, text)
        self.assertFalse(result["review"]["runtime_go"])

    def test_unknown_tool_and_extra_fields_denied(self):
        for bad in (
            event(tool="read_file:/etc/passwd"),
            {**event(), "args": {"token": "not-for-export"}},
            event(kind="turn", tool="ops_watch"),
            event(kind="tool", tool=None),
        ):
            with self.subTest(bad=bad), self.assertRaises(OfflineTelemetryDenied):
                project(payload(bad))

    def test_invalid_resource_scope_and_revision_refused(self):
        for patch in (
            {"visibility": "PRIVATE"}, {"schema": "invalid"},
            {"source_revision": "secret-label"}, {"source_revision": REVISION.upper()},
            {"added": "injected"}, {"sample_stride": 0}, {"sample_stride": 17},
        ):
            with self.subTest(patch=patch), self.assertRaises(OfflineTelemetryDenied):
                project(payload(event(), **patch))

    def test_duration_size_budget_retries_limits(self):
        cases = (
            event(duration_ms=-1),
            event(duration_ms=600001),
            event(duration_ms=True),
            event(output_bytes_bounded=16385),
            event(output_bytes_bounded=False),
            event(attempt_count=4),
            event(retry_count=-1),
            event(attempt_count=3, retry_count=0),
            event(budget_state="paid"),
            event(trace_completeness="all"),
        )
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(OfflineTelemetryDenied):
                project(payload(bad))

    def test_deny_more_than_32_events_without_partial_output(self):
        with self.assertRaisesRegex(OfflineTelemetryDenied, "EVENT_COUNT_INVALID"):
            project(payload(*[event() for _ in range(MAX_EVENTS + 1)]))
        with self.assertRaisesRegex(OfflineTelemetryDenied, "EVENT_COUNT_INVALID"):
            project(payload(event(), events=[]))

    def test_all_unsampled_rows_validated_no_hidden_injection(self):
        data = payload(event(), event(tool="unexpected"), sample_stride=2)
        with self.assertRaisesRegex(OfflineTelemetryDenied, "EVENT_TOOL_INVALID"):
            project(data)

    def test_malformed_types_refused_without_coercion(self):
        for x in (None, "a string", [], 7, {"schema": SCHEMA}):
            with self.subTest(x=x), self.assertRaises(OfflineTelemetryDenied):
                project(x)
        with self.assertRaises(OfflineTelemetryDenied):
            project(payload(event(), sample_stride=True))
        with self.assertRaises(OfflineTelemetryDenied):
            project(payload(event(), events="not-events"))

    def test_json_duplicate_key_detection(self):
        with self.assertRaisesRegex(OfflineTelemetryDenied, "DUPLICATE_KEY"):
            json.loads('{"schema":"v1","schema":"private"}', object_pairs_hook=_no_duplicate_keys)

    def test_same_input_is_exactly_deterministic_and_memory_only(self):
        sample = payload(event(), event(error_kind="denied", duration_ms=50))
        saved = copy.deepcopy(sample)
        result = project(sample)
        self.assertEqual(result, project(sample))
        self.assertEqual(saved, sample)
        self.assertEqual("MEMORY_ONLY", result["review"]["retention"])
        self.assertEqual("REFUSE_WHOLE_BATCH", result["review"]["drop_on_overflow"])
        self.assertEqual(0, result["review"]["files_written"])
        self.assertFalse(result["review"]["independent_live_evidence"])

    def test_full_capacity_is_bounded_and_valid(self):
        result = project(payload(*[event() for _ in range(MAX_EVENTS)]))
        self.assertEqual(MAX_EVENTS, result["review"]["input_events"])
        self.assertEqual(MAX_EVENTS, result["review"]["sampled_events"])


if __name__ == "__main__":
    unittest.main()
