"""Offline H-15 Cloudflare Analytics preflight tests; no API calls or secrets."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from scripts import h15_cloudflare_analytics_probe as probe


NOW = datetime(2026, 10, 18, 19, 0, tzinfo=timezone.utc)


class Response:
    status = 200

    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, length):
        return self.payload[:length]


def metrics(value):
    return {"data": {"viewer": {"accounts": [{
        "aiInferenceAdaptiveGroups": [{"sum": {"totalNeurons": value}}]
    }]}}}


class AnalyticsReadProbeTests(unittest.TestCase):
    def test_strict_0600_credentials_and_account_scope(self):
        with TemporaryDirectory() as tmp:
            token = Path(tmp) / "token"
            account = Path(tmp) / "env"
            token.write_text("x" * 40 + "\n", encoding="ascii")
            token.chmod(0o600)
            account.write_text("CLOUDFLARE_ANALYTICS_ACCOUNT_ID=" + "a" * 32 + "\n")
            account.chmod(0o600)
            self.assertEqual(
                probe.load_credentials(token, account, uid=os.getuid()),
                ("x" * 40, "a" * 32))
            token.chmod(0o644)
            with self.assertRaises(probe.PreflightError):
                probe.load_credentials(token, account, uid=os.getuid())
            token.chmod(0o600)
            account.write_text("CLOUDFLARE_ANALYTICS_ACCOUNT_ID=" + "a" * 32 +
                               "\nLD_PRELOAD=bad\n")
            with self.assertRaises(probe.PreflightError):
                probe.load_credentials(token, account, uid=os.getuid())
            account.write_text("CLOUDFLARE_ANALYTICS_ACCOUNT_ID=" + "a" * 32)
            linked = Path(tmp) / "symlink"
            linked.symlink_to(token)
            with self.assertRaises(probe.PreflightError):
                probe.load_credentials(linked, account, uid=os.getuid())
            hardlink = Path(tmp) / "hardlink"
            os.link(token, hardlink)
            with self.assertRaises(probe.PreflightError):
                probe.load_credentials(token, account, uid=os.getuid())

    def test_one_bounded_graphql_query_previous_utc_day_advisory(self):
        calls = []
        def transport(req, timeout):
            calls.append(req)
            self.assertEqual(timeout, 7)
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.full_url, probe.ENDPOINT)
            payload = json.loads(req.data)
            self.assertIn("aiInferenceAdaptiveGroups", payload["query"])
            self.assertIn("totalNeurons", payload["query"])
            self.assertNotIn("mutation", payload["query"].lower())
            self.assertEqual(payload["variables"], {
                "accountTag": "b" * 32,
                "start": "2026-10-17T00:00:00Z",
                "end": "2026-10-18T00:00:00Z",
            })
            return Response(metrics(123.45))
        status, value = probe.inspect(token="safe_fictitious_token_" + "x" * 24,
                                      account="b" * 32, now=NOW, transport=transport)
        self.assertEqual((status, value), ("advisory_estimate", 123.45))
        self.assertEqual(len(calls), 1)

    def test_errors_fail_closed_without_exposing_data(self):
        for http_code, expected in ((401,"auth_required"), (403,"auth_required"),
                                    (429,"throttled"), (503,"unavailable")):
            with self.subTest(status=http_code):
                def denied(req, timeout):
                    raise HTTPError(probe.ENDPOINT, http_code, "SECRET", {}, None)
                status, value = probe.inspect(token="x" * 40,account="a" * 32,
                                              now=NOW,transport=denied)
                self.assertEqual((status,value),(expected,None))
        for sample, expected in (
            ({"errors":[{"message":"Bearer secret"}]}, "unsupported_or_denied"),
            ({"data":{"viewer":{"accounts":[]}}}, "unknown"),
            ({"data":{"viewer":{"accounts":[{"aiInferenceAdaptiveGroups":[]}]}}}, "no_confirmed_samples"),
            (metrics(-1), "unknown"),
            (metrics(float("nan")), "unknown"),
            (metrics(True), "unknown"),
        ):
            with self.subTest(sample=str(sample)[:25]):
                value, amount = probe.inspect(token="x"*40,account="a"*32,now=NOW,
                    transport=lambda req, timeout: Response(sample))
                self.assertEqual((value,amount),(expected,None))

    def test_opt_in_confidence_single_query_and_no_quota_allow(self):
        calls = []
        sample = metrics(23.427)
        sample["data"]["viewer"]["accounts"][0]["aiInferenceAdaptiveGroups"][0][
            "confidence"] = {"sum": {"totalNeurons": {
                "estimate": 23.427, "lower": 22.1, "upper": 24.8,
                "sampleSize": 120,
            }}}
        def transport(req, timeout):
            calls.append(req)
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(timeout, 7)
            self.assertEqual(req.full_url, probe.ENDPOINT)
            data = json.loads(req.data)
            self.assertIn("confidence(level: 0.95)", data["query"])
            self.assertIn("sum { totalNeurons { estimate lower upper sampleSize } }",
                          data["query"])
            self.assertEqual(data["variables"]["start"], "2026-10-17T00:00:00Z")
            self.assertEqual(data["variables"]["end"], "2026-10-18T00:00:00Z")
            self.assertNotIn("mutation", data["query"].lower())
            return Response(sample)
        result = probe.inspect_confidence(token="x"*40,account="a"*32,
                                          now=NOW,transport=transport)
        self.assertEqual(result, ("advisory_confidence", {
            "estimate":23.427, "lower":22.1, "upper":24.8, "sample_size":120,
        }))
        self.assertEqual(len(calls), 1)

    def test_confidence_unsupported_or_invalid_never_fabricated(self):
        def answer(sample):
            return probe.inspect_confidence(
                token="x"*40, account="a"*32, now=NOW,
                transport=lambda req, timeout: Response(sample))
        self.assertEqual(answer(metrics(23.4))[0], "unsupported_or_denied")
        sample = metrics(23.4)
        sample["errors"]=[{"message":"Token or account secret"}]
        self.assertEqual(answer(sample),("unsupported_or_denied",None))
        sample = metrics(23.4)
        row = sample["data"]["viewer"]["accounts"][0]["aiInferenceAdaptiveGroups"][0]
        row["confidence"]={"sum":{"totalNeurons":{
            "estimate":23.4,"lower":25.0,"upper":23.5,"sampleSize":120}}}
        self.assertEqual(answer(sample),("unknown",None))
        row["confidence"]["sum"]["totalNeurons"]={
            "estimate":23.4,"lower":22,"upper":25,"sampleSize":True}
        self.assertEqual(answer(sample),("unknown",None))
        row["confidence"]["sum"]["totalNeurons"]["sampleSize"]=10
        sample["data"]["viewer"]["accounts"][0]["aiInferenceAdaptiveGroups"].append(
            {"sum":{"totalNeurons":100}})
        self.assertEqual(answer(sample),("unknown",None))
        for http_code, expected in ((401,"auth_required"),(403,"auth_required"),
                                    (429,"throttled"),(500,"unavailable")):
            with self.subTest(http_code=http_code):
                def denied(req, timeout):
                    raise HTTPError(probe.ENDPOINT,http_code,
                                    "Confidential credential",{},None)
                self.assertEqual(probe.inspect_confidence(
                    token="x"*40,account="a"*32,now=NOW,transport=denied),
                    (expected,None))

    def test_optional_main_confidence_mode_is_explicit(self):
        from contextlib import redirect_stdout
        import io
        result = ("advisory_confidence", {
            "estimate":23.4,"lower":23,"upper":24,"sample_size":12,
        })
        output=io.StringIO()
        with patch.object(probe.os,"geteuid",return_value=0), \
             patch.object(probe,"load_credentials",return_value=("x"*40,"a"*32)), \
             patch.object(probe,"inspect_confidence",return_value=result) as check, \
             patch.object(probe,"inspect") as baseline, redirect_stdout(output):
            self.assertEqual(probe.main(["--confidence"]),0)
            check.assert_called_once()
            baseline.assert_not_called()
        self.assertIn("CLOUDFLARE_ANALYTICS_CONFIDENCE=advisory_confidence",
                      output.getvalue())
        self.assertIn("QUOTA_REMAINING=UNKNOWN",output.getvalue())
        self.assertNotIn("a"*32,output.getvalue())

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            probe.yesterday_window(datetime(2026,10,18))

    def test_main_without_credentials_does_not_make_a_request(self):
        import io
        from contextlib import redirect_stdout
        output = io.StringIO()
        with patch.object(probe.os, "geteuid", return_value=0), \
                patch.object(probe, "load_credentials", side_effect=probe.PreflightError), \
                patch.object(probe, "inspect") as inspect, redirect_stdout(output):
            self.assertEqual(probe.main(), 2)
            inspect.assert_not_called()
        self.assertEqual(output.getvalue().strip(),
                         "CLOUDFLARE_ANALYTICS=UNSAFE_OR_MISSING_CREDENTIALS")


if __name__ == "__main__":
    unittest.main()
