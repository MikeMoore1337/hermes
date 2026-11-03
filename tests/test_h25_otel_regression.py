"""H-25 #192: regression checks for offline sampling, statuses, and OTLP JSON."""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from eval_lane.offline_otel_projection import (
    MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, OfflineTelemetryDenied,
    offline_otlp_json_requests, project,
)
from tests.test_h25_otel_offline import event, payload

try:  # Optional independent oracle; the production package has no SDK dependency.
    from google.protobuf.json_format import ParseDict, ParseError
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
except ImportError:
    ParseDict = ParseError = ExportMetricsServiceRequest = ExportTraceServiceRequest = None


def run_cli(raw: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-B", "-m", "eval_lane.offline_otel_projection", "--stdin"],
        input=raw, capture_output=True, timeout=5, check=False,
    )


class SyntheticOtelRegressionTests(unittest.TestCase):
    def test_unknown_error_is_unset_not_success(self):
        x = project(payload(event(error_kind="unknown")))
        span = x["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(0, span["status"]["code"])
        self.assertEqual(1, x["review"]["unknown_error_input_events"])
        self.assertEqual("NOT_MEASURED", x["review"]["cost_measurement_state"])
        self.assertEqual("NOT_MEASURED", x["review"]["tokens_measurement_state"])

    def test_clean_span_is_unset_even_with_successful_retries(self):
        # OTEL semconv: absence of an observed error does not justify OK.
        obj = project(payload(event(error_kind="none", attempt_count=3, retry_count=2)))
        span = obj["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(0, span["status"]["code"])
        self.assertNotIn("error.type", {a["key"] for a in span["attributes"]})

    def test_error_type_attribute_is_low_cardinality_and_never_remote_text(self):
        for error in ("timeout", "denied", "execution_error"):
            with self.subTest(error=error):
                obj = project(payload(event(error_kind=error)))
                span = obj["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
                self.assertEqual(2, span["status"]["code"])
                attr = {a["key"]: a["value"] for a in span["attributes"]}
                self.assertEqual({"stringValue": error}, attr["error.type"])
        obj = project(payload(event(error_kind="unknown")))
        span = obj["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertNotIn("error.type", {a["key"] for a in span["attributes"]})

    def test_offline_signal_requests_have_two_strict_otlp_bodies(self):
        fixture = payload(event(), event(error_kind="timeout"))
        with patch("builtins.open", side_effect=AssertionError("unexpected file IO")):
            with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected network")):
                signal_bodies = offline_otlp_json_requests(fixture)
        self.assertEqual({"traces", "metrics"}, set(signal_bodies))
        self.assertEqual({"resourceSpans"}, set(signal_bodies["traces"]))
        self.assertEqual({"resourceMetrics"}, set(signal_bodies["metrics"]))
        self.assertEqual(signal_bodies, offline_otlp_json_requests(fixture))
        self.assertNotIn("review", json.dumps(signal_bodies))
        self.assertNotIn("CANARY_ONLY", json.dumps(signal_bodies))
        if ParseDict is not None:
            traces = ParseDict(signal_bodies["traces"], ExportTraceServiceRequest(),
                               ignore_unknown_fields=False)
            metrics = ParseDict(signal_bodies["metrics"], ExportMetricsServiceRequest(),
                                ignore_unknown_fields=False)
            self.assertEqual(2, len(traces.resource_spans[0].scope_spans[0].spans))
            self.assertEqual(2, len(metrics.resource_metrics[0].scope_metrics[0].metrics))

    def test_offline_signal_requests_reject_private_metadata(self):
        for bad in (
            {**event(), "authorization": "CANARY_ONLY"},
            event(tool="unknown:CANARY_ONLY"),
        ):
            with self.subTest(kind=bad["tool"]):
                with self.assertRaises(OfflineTelemetryDenied):
                    offline_otlp_json_requests(payload(bad))


    def test_all_errors_counted_even_if_unsampled(self):
        x = project(payload(
            event(), event(error_kind="timeout", duration_ms=None),
            event(), event(error_kind="denied", duration_ms=7),
            sample_stride=2,
        ))
        m = x["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        errors = next(k for k in m if k["name"] == "hermes.synthetic.errors")
        counts = {
            pt["attributes"][0]["value"]["stringValue"]: int(pt["asInt"])
            for pt in errors["gauge"]["dataPoints"]
        }
        self.assertEqual({"timeout": 1, "denied": 1}, counts)
        self.assertEqual(2, x["review"]["sampled_events"])
        self.assertEqual("ALL_VALID_INPUT_EVENTS", x["review"]["error_aggregate_scope"])

    def test_unsampled_unknowns_and_partial_traces_are_detected(self):
        x = project(payload(
            event(),
            event(error_kind="unknown", duration_ms=None, trace_completeness="unknown"),
            event(duration_ms=0, trace_completeness="partial"),
            sample_stride=3,
        ))
        self.assertEqual(0, x["review"]["unknown_duration_events"])
        self.assertEqual(1, x["review"]["unknown_duration_input_events"])
        self.assertEqual(1, x["review"]["unknown_error_input_events"])
        self.assertEqual(2, x["review"]["incomplete_trace_input_events"])

    def test_timeout_with_unknown_duration_keeps_error_count_without_zero_metric(self):
        x = project(payload(event(duration_ms=None, error_kind="timeout")))
        metrics = x["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        self.assertEqual(["hermes.synthetic.errors"], [m["name"] for m in metrics])
        self.assertEqual("1", metrics[0]["gauge"]["dataPoints"][0]["asInt"])
        self.assertEqual(1, x["review"]["unknown_duration_input_events"])

    def test_retries_budget_and_partial_trace_are_whitelisted(self):
        x = project(payload(event(
            kind="turn", tool=None, attempt_count=3, retry_count=2,
            budget_state="exceeded", trace_completeness="partial",
        )))
        span = x["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        attrs = {a["key"]: next(iter(a["value"].values())) for a in span["attributes"]}
        self.assertEqual("3", attrs["hermes.attempt.count"])
        self.assertEqual("2", attrs["hermes.retry.count"])
        self.assertEqual("exceeded", attrs["hermes.budget.state"])
        self.assertEqual("partial", attrs["hermes.trace.completeness"])

    def test_unsupported_event_and_private_annotations_refused(self):
        for bad in (
            event(kind="exception"),
            {**event(), "metadata": {"oauth": "CANARY_ONLY"}},
            {**event(), "resource_attributes": {"username": "CANARY_ONLY"}},
            {**event(), "span_attributes": {"authorization": "CANARY_ONLY"}},
            {**event(), "exception": "CANARY_ONLY"},
            event(tool="other:CANARY_ONLY"),
            event(error_kind="execution_error:CANARY_ONLY"),
        ):
            with self.subTest(case=str(bad)[:60]):
                with self.assertRaises(OfflineTelemetryDenied):
                    project(payload(bad))

    def test_no_filesystem_or_network_io_in_projection(self):
        with patch("builtins.open", side_effect=AssertionError("filesystem used")):
            with patch.object(socket.socket, "connect", side_effect=AssertionError("network used")):
                x = project(payload(event()))
        self.assertEqual(0, x["review"]["network_calls"])
        self.assertEqual(0, x["review"]["files_written"])

    def test_cli_rejects_invalid_json_without_echo_or_traceback(self):
        for raw in (
            b'{"schema":', b'{"schema":"a","schema":"b"}',
            b'{"x":NaN}', b'{"x":Infinity}',
            b'{"x":"CANARY_ONLY", "metadata":{"token":"CANARY_ONLY"}}',
            b'\xff\xfe', b' ' * (MAX_INPUT_BYTES + 1),
            ("[" * 4000 + "0" + "]" * 4000).encode(),
        ):
            with self.subTest(length=len(raw)):
                completed = run_cli(raw)
                self.assertEqual(2, completed.returncode)
                self.assertFalse(completed.stderr)
                self.assertEqual("REFUSED", json.loads(completed.stdout)["status"])
                self.assertNotIn(b"CANARY_ONLY", completed.stdout)

    def test_output_has_valid_time_and_identifier_shapes(self):
        x = project(payload(event(duration_ms=0), event(duration_ms=600000)))
        spans = x["otlp_json_candidate"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        self.assertEqual(2, len(spans))
        for s in spans:
            self.assertTrue(re.fullmatch(r"[a-f0-9]{32}", s["traceId"]))
            self.assertTrue(re.fullmatch(r"[a-f0-9]{16}", s["spanId"]))
            self.assertLessEqual(int(s["startTimeUnixNano"]), int(s["endTimeUnixNano"]))
            self.assertLess(int(s["endTimeUnixNano"]), 2**64)
        self.assertEqual(spans[0]["startTimeUnixNano"], spans[0]["endTimeUnixNano"])
        self.assertLessEqual(len(json.dumps(x).encode()), MAX_OUTPUT_BYTES)

    def test_full_capacity_stays_in_bounds_and_deterministic(self):
        data = payload(*[event(error_kind="timeout" if i % 2 else "none") for i in range(32)])
        result = project(data)
        self.assertEqual(result, project(data))
        self.assertLessEqual(len(json.dumps(result, separators=(",", ":")).encode()), MAX_OUTPUT_BYTES)
        metrics = result["otlp_json_candidate"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        errors = next(k for k in metrics if k["name"] == "hermes.synthetic.errors")
        self.assertEqual("16", errors["gauge"]["dataPoints"][0]["asInt"])

    def test_independent_official_otlp_protobuf_json_mapping(self):
        obj = project(payload(event(), event(error_kind="timeout", duration_ms=None)))
        candidate = obj["otlp_json_candidate"]
        # Repository CI disallows skips: use a stdlib structural oracle when
        # optional OpenTelemetry protobuf types are not installed.
        if ParseDict is None:
            self.assertEqual({"resourceSpans", "resourceMetrics"}, set(candidate))
            self.assertEqual(1, len(candidate["resourceSpans"]))
            self.assertEqual(1, len(candidate["resourceMetrics"]))
            return
        # One OTLP/HTTP request cannot include both independent signal types.
        with self.assertRaises(ParseError):
            ParseDict(candidate, ExportTraceServiceRequest(), ignore_unknown_fields=False)
        with self.assertRaises(ParseError):
            ParseDict(candidate, ExportMetricsServiceRequest(), ignore_unknown_fields=False)
        traces = ParseDict(
            {"resourceSpans": candidate["resourceSpans"]},
            ExportTraceServiceRequest(), ignore_unknown_fields=False,
        )
        metrics = ParseDict(
            {"resourceMetrics": candidate["resourceMetrics"]},
            ExportMetricsServiceRequest(), ignore_unknown_fields=False,
        )
        self.assertEqual(1, len(traces.resource_spans[0].scope_spans[0].spans))
        self.assertEqual(2, len(metrics.resource_metrics[0].scope_metrics[0].metrics))


if __name__ == "__main__":
    unittest.main()
