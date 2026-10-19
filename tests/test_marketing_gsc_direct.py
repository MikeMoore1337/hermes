"""H-24/#191 GSC standalone runtime: offline, deterministic, no real OAuth."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from marketing.gsc_direct import (
    API_ORIGIN, BASE_URL, DIMENSION_REPORTS, GscRuntimeError, SCOPE,
    _authorized_fetch, _google_rows, _sitemap_rows, _verify_credential_file,
    _write_private_json, collect, request_plan,
)


def fixture_fetch():
    calls = []
    def fetch(method, url, body):
        calls.append((method, url, body))
        if method == "GET":
            return {"sitemap": [{
                "path": "https://your-fitness-coach.ru/sitemap.xml",
                "errors": 0, "warnings": 0,
                "lastSubmitted": "2026-10-01T00:00:00Z",
                "lastDownloaded": "2026-10-16T00:32:20Z",
                "contents": [{"type": "web", "submitted": 29, "indexed": 0}],
            }]}
        dims = body["dimensions"]
        if dims == []:
            rows = [{"clicks": 0, "impressions": 16, "ctr": 0, "position": 22.1875}]
        elif dims == ["date"]:
            rows = [{"keys": ["2026-10-16"], "clicks": 0,
                     "impressions": 2, "ctr": 0, "position": 1}]
        elif dims == ["page"]:
            rows = [{"keys": ["https://your-fitness-coach.ru/calculators/1rm"],
                     "clicks": 0, "impressions": 10, "ctr": 0, "position": 21.1}]
        elif dims == ["query"]:
            rows = [{"keys": ["калькулятор на раз"],
                     "clicks": 0, "impressions": 1, "ctr": 0, "position": 44}]
        elif dims == ["country"]:
            rows = [{"keys": ["rus"], "clicks": 0,
                     "impressions": 8, "ctr": 0, "position": 38.5}]
        else:
            rows = [{"keys": ["DESKTOP"], "clicks": 0,
                     "impressions": 10, "ctr": 0, "position": 31.3}]
        return {"rows": rows, "responseAggregationType": "byProperty"}
    return fetch, calls


class GscRuntimeTests(unittest.TestCase):
    def test_report_date_timezone_and_final_only(self):
        start, end, calls = request_plan(as_of=date(2026, 10, 19))
        self.assertEqual((start, end), ("2026-09-21", "2026-10-18"))
        self.assertEqual(len(calls), 7)
        self.assertEqual([x[2]["dimensions"] for x in calls[:-1]],
                         [list(d) for d in DIMENSION_REPORTS])
        for method, url, body in calls[:-1]:
            self.assertEqual(method, "POST")
            self.assertTrue(url.startswith(API_ORIGIN + "/"))
            self.assertEqual(body["type"], "web")
            self.assertEqual(body["dataState"], "final")
            self.assertEqual(body["rowLimit"], 250)
            self.assertEqual(body["startRow"], 0)
        self.assertEqual(calls[-1][0], "GET")
        self.assertIsNone(calls[-1][2])

    def test_one_daily_snapshot_is_unverified_with_injected_transport(self):
        fetch, calls = fixture_fetch()
        result = collect(fetch, as_of=date(2026, 10, 19))
        self.assertEqual(len(calls), 7)
        self.assertEqual(result["request_count"], 7)
        self.assertEqual(result["report_count"], 7)
        self.assertEqual(result["data_latest_observed_date"], "2026-10-16")
        self.assertEqual(result["reports"]["site"]["rows"][0]["metrics"]["impressions"], 16)
        self.assertEqual(result["reports"]["query"]["rows"][0]["query"],
                         "калькулятор на раз")
        self.assertEqual(result["reports"]["country"]["rows"][0]["country"], "rus")
        self.assertEqual(result["reports"]["sitemaps"]["rows"][0]["submitted_url_count"], 29)
        self.assertNotIn("indexed", result["reports"]["sitemaps"]["rows"][0])
        self.assertFalse(result["provider_verified"])
        self.assertFalse(result["live_api_used_by_hermes"])
        self.assertFalse(result["reports"]["site"]["hermes_runtime_source_verified"])
        self.assertFalse(result["publication_allowed"])
        self.assertFalse(result["yfc_write_allowed"])
        self.assertEqual(result, collect(fixture_fetch()[0], as_of=date(2026, 10, 19)))

    def test_empty_rows_do_not_fake_zero_traffic_or_complete_date(self):
        def empty(method, url, body):
            return {} if method == "POST" else {"sitemap": []}
        result = collect(empty, as_of=date(2026, 10, 19))
        self.assertEqual(result["quality_status"], "NO_DATA")
        self.assertIsNone(result["data_latest_observed_date"])
        self.assertEqual(result["reports"]["site"]["quality_status"], "NO_DATA")
        self.assertEqual(result["reports"]["site"]["rows"], [])

    def test_error_fail_closed_never_store_partial_snapshot(self):
        def offline(method, url, body):
            raise TimeoutError("token=secret_value_123")
        with self.assertRaisesRegex(GscRuntimeError, "provider_unavailable") as error:
            collect(offline, as_of=date(2026, 10, 19))
        self.assertNotIn("secret_value_123", str(error.exception))

    def test_api_invalid_keys_missing_fields_and_duplicate_rows(self):
        for bad in (
            {"rows": [{"keys": ["x"], "impressions": 1}]},
            {"rows": [{"keys": [], "impressions": 1, "secret": "bad"}]},
            {"rows": "wrong"},
            {"rows": [{"clicks": -1, "impressions": 1}]},
            {"rows": [{"impressions": 1}] * 2},
        ):
            with self.subTest(bad=bad), self.assertRaises(GscRuntimeError):
                collect(lambda method, url, body: bad if method == "POST"
                        else {"sitemap": []}, as_of=date(2026, 10, 19))

    def test_provider_error_codes_are_safe(self):
        with self.assertRaisesRegex(GscRuntimeError, "analytics_response_invalid"):
            _google_rows([], ())
        with self.assertRaisesRegex(GscRuntimeError, "dimension_values_invalid"):
            _google_rows({"rows": [{"keys": ["x"]}]}, ())
        with self.assertRaisesRegex(GscRuntimeError, "sitemap_contents_invalid"):
            _sitemap_rows({"sitemap": [{"contents": "secret"}]})
        with self.assertRaisesRegex(GscRuntimeError, "sitemap_submitted_invalid"):
            _sitemap_rows({"sitemap": [{"contents": [{"submitted": -1}]}]})

    def test_sitemaps_never_accepts_deprecated_indexed(self):
        items = _sitemap_rows({"sitemap": [{
            "path": "https://your-fitness-coach.ru/sitemap.xml",
            "contents": [{"submitted": 29, "indexed": 0}],
        }]})
        self.assertEqual(items[0]["submitted"], 29)
        self.assertNotIn("indexed", items[0])

    def test_credentials_and_file_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "key.json"
            with self.assertRaisesRegex(GscRuntimeError, "credential_unavailable"):
                _verify_credential_file(p)
            p.write_text(json.dumps({
                "type": "service_account",
                "token_uri": "https://evil.example/token",
                "client_email": "fake@project.iam.gserviceaccount.com",
                "private_key": "not-a-key",
            }), encoding="utf-8")
            os.chmod(p, 0o600)
            with self.assertRaisesRegex(GscRuntimeError, "credential_type_invalid"):
                _verify_credential_file(p)
            os.chmod(p, 0o644)
            with self.assertRaisesRegex(GscRuntimeError, "credential_file_unsafe"):
                _verify_credential_file(p)
            p.unlink()
            p.symlink_to(Path(tmp) / "elsewhere")
            with self.assertRaisesRegex(GscRuntimeError, "credential_file_unsafe"):
                _verify_credential_file(p)

    def test_private_atomic_output_and_symlink_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "data.json"
            _write_private_json(p, {"status": "NO_DATA", "rows": []})
            self.assertEqual(json.loads(p.read_text())["status"], "NO_DATA")
            if os.name == "posix":
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            p.unlink()
            target = Path(tmp) / "target.json"
            target.write_text("DO_NOT_CHANGE")
            p.symlink_to(target)
            with self.assertRaisesRegex(GscRuntimeError, "output_symlink_denied"):
                _write_private_json(p, {"status": "malicious"})
            self.assertEqual(target.read_text(), "DO_NOT_CHANGE")

    def test_bounded_fixed_endpoint_and_token_validation(self):
        with self.assertRaisesRegex(GscRuntimeError, "token_invalid"):
            _authorized_fetch("")
        f = _authorized_fetch("test-only")
        with self.assertRaisesRegex(GscRuntimeError, "endpoint_not_allowed"):
            f("GET", "https://untrusted.example/", None)
        with self.assertRaisesRegex(GscRuntimeError, "endpoint_not_allowed"):
            f("POST", BASE_URL + "/sitemaps", {"path": "x"})

    def test_no_credentials_is_no_live_run(self):
        from marketing.gsc_direct import live_run
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(GscRuntimeError, "credential_unavailable"):
                live_run(credentials_path=Path(tmp) / "missing.json",
                         output_path=Path(tmp) / "out.json")
            self.assertFalse((Path(tmp) / "out.json").exists())

    def test_cli_dry_run_no_credentials_no_external_requests(self):
        proc = subprocess.run(
            [sys.executable, "-m", "scripts.hermes_gsc_collect", "--dry-run"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "DRY_RUN_NO_NETWORK")
        self.assertFalse(result["credentials_accessed"])
        self.assertFalse(result["publication_allowed"])
        self.assertEqual(result["requests_per_run"], 7)

    def test_cli_missing_secret_returns_safe_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run([
                sys.executable, "-m", "scripts.hermes_gsc_collect",
                "--credentials", str(Path(tmp) / "absent.json"),
                "--output", str(Path(tmp) / "latest.json"),
            ], capture_output=True, timeout=10, check=False)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout)["reason"], "credential_unavailable")
            self.assertNotIn(tmp, p.stdout.decode())


    def test_official_google_double_and_int64_json_wire_formats(self):
        from marketing.gsc_direct import _gsc_timestamp
        base_fetch, _ = fixture_fetch()
        def google_wire(method, url, body):
            value = copy.deepcopy(base_fetch(method, url, body))
            if method == "POST":
                for row in value["rows"]:
                    row["clicks"] = 0.0
                    row["impressions"] = float(row["impressions"])
            else:
                sitemap = value["sitemap"][0]
                sitemap["contents"][0]["submitted"] = "29"
                sitemap["errors"] = "0"
                sitemap["warnings"] = "0"
                sitemap["lastSubmitted"] = "2026-10-01T03:00:00+03:00"
            return value
        result = collect(google_wire, as_of=date(2026, 10, 19))
        site = result["reports"]["site"]["rows"][0]
        self.assertEqual(site["metrics"]["impressions"], 16)
        self.assertIs(type(site["metrics"]["impressions"]), int)
        sitemap = result["reports"]["sitemaps"]["rows"][0]
        self.assertEqual(sitemap["submitted_url_count"], 29)
        self.assertEqual(sitemap["errors"], 0)
        self.assertEqual(sitemap["warnings"], 0)
        self.assertEqual(sitemap["last_submitted"],
                         "2026-10-01T00:00:00.000000Z")
        self.assertEqual(_gsc_timestamp("2026-10-16T00:32:20Z"),
                         "2026-10-16T00:32:20.000000Z")

    def test_google_wire_types_fail_closed(self):
        from marketing.gsc_direct import _gsc_long, _gsc_timestamp
        for invalid in (True, -1, 1.2, "1.2", "-1", "99999999999999999999",
                        "", None, "1e2"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(GscRuntimeError):
                    _gsc_long(invalid)
        for invalid in ("2026-10-01", "2026-10-01T03:00:00",
                        "2026-99-01T02:00:00Z", "123<script>alert(1)</script>",
                        "2026-10-01T00:00:00+99:99", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(GscRuntimeError):
                    _gsc_timestamp(invalid)
        for invalid in (-1.0, float("nan"), 2.5, 1e30, True, "2.0"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(GscRuntimeError, "analytics_count_invalid"):
                    _google_rows({"rows": [{"impressions": invalid}]}, ())
        self.assertEqual(_google_rows({"rows": [{"impressions": 4.0}]}, ()),
                         [{"impressions": 4}])


if __name__ == "__main__":
    unittest.main()
