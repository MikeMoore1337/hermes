"""Offline #295 Cloudflare advisory history; never a remaining quota."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
import os
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from control_center import cloudflare_analytics_history as h
from control_center.provider_registry import registry

NOW = datetime(2026, 10, 18, 20, tzinfo=timezone.utc)
CI = {"estimate": 23.427, "lower": 23.427,
      "upper": 23.427, "sample_size": 2}


class CloudflareAdvisoryHistoryTests(unittest.TestCase):
    def test_tiny_sample_never_claims_exactness(self):
        row = h.observation("2026-10-17", CI, now=NOW)
        self.assertEqual(row["quality"], "very_small_sample")
        self.assertEqual(row["sample_size"], 2)
        self.assertNotIn("remaining", row)
        self.assertNotIn("billable", row)
        for broken in (
            {"estimate": 23.427, "lower": 25, "upper": 30, "sample_size": 2},
            {"estimate": 23.427, "lower": 20, "upper": 30, "sample_size": True},
            {"estimate": float("nan"), "lower": 20, "upper": 30, "sample_size": 2},
        ):
            with self.subTest(broken=broken), self.assertRaises(h.AdvisoryError):
                h.observation("2026-10-17", broken, now=NOW)
        with self.assertRaises(h.AdvisoryError):
            h.observation("2026-10-18", CI, now=NOW)

    def test_atomic_root_group_inherited_and_read_only_registry(self):
        with TemporaryDirectory() as folder:
            root=Path(folder)
            root.chmod(0o750)
            archive=root/"analytics.json"
            with patch("grp.getgrnam",
                       return_value=SimpleNamespace(gr_gid=os.getegid())), \
                    patch.object(os,"chown",side_effect=AssertionError("no chown")):
                row=h.observation("2026-10-17",CI,now=NOW)
                h.append(row,path=archive,now=NOW)
                h.append(row,path=archive,now=NOW)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o640)
            snap=h.read(archive,now=NOW)
            self.assertEqual(snap["status"],"historical_estimate")
            self.assertEqual(len(snap["days"]),1)
            view=registry(
                codex_path=root/"codex",desktop_path=root/"desktop",
                cloudflare_path=root/"billing",github_path=root/"github",
                analytics_path=archive,now=NOW)["providers"][0]
            self.assertEqual(view["status"],"unknown")
            self.assertEqual(view["source_kind"],"unknown")
            self.assertIsNone(view["windows"][0]["used"])
            self.assertIsNone(view["windows"][0]["remaining"])
            self.assertIsNone(view["windows"][0]["remaining_percent"])
            self.assertEqual(view["analytics_status"],"historical_estimate")
            self.assertEqual(view["analytics_history"][0]["sample_size"],2)

    def test_unknown_if_file_tampered_and_never_writable_to_untrusted_dir(self):
        with TemporaryDirectory() as folder:
            root=Path(folder)
            archive=root/"analytics.json"
            archive.write_text('{"fake_current_quota":10000}')
            self.assertEqual(h.read(archive,now=NOW)["status"],"unknown")
            root.chmod(0o777)
            with patch("grp.getgrnam",
                       return_value=SimpleNamespace(gr_gid=os.getegid())):
                with self.assertRaises(h.AdvisoryError):
                    h.append(h.observation("2026-10-17",CI,now=NOW),
                             path=archive,now=NOW)
            self.assertEqual(archive.read_text(),'{"fake_current_quota":10000}')

    def test_corruption_and_old_data_fail_closed(self):
        with TemporaryDirectory() as folder:
            root=Path(folder)
            archive=root/"data.json"
            archive.symlink_to(root/"missing")
            self.assertEqual(h.read(archive,now=NOW)["status"],"unknown")
            self.assertRaises(h.AdvisoryError, h.append,
                h.observation("2026-10-17",CI,now=NOW),path=archive,now=NOW,
                group="hermes-control")
            self.assertRaises(h.AdvisoryError, h.observation,
                "2026-09-01",CI,now=NOW)
            archive.unlink()
            archive.write_text(json.dumps({
                "schema":1,"source":h.SOURCE,
                "observed_at":"2026-10-18T20:00:00Z",
                "days":[{**h.observation("2026-10-17",CI,now=NOW),
                         "quality":"adaptive_estimate"}],
            }))
            self.assertEqual(h.read(archive,now=NOW)["status"],"unknown")

    def test_collector_refuses_unsafe_context_before_network(self):
        import io
        from contextlib import redirect_stdout
        from scripts import h15_cloudflare_analytics_collect as collect
        output=io.StringIO()
        with patch.object(collect.os,"geteuid",return_value=1000), \
                patch.object(collect.probe,"inspect_confidence") as query, \
                redirect_stdout(output):
            self.assertEqual(collect.main(),2)
            query.assert_not_called()
        self.assertIn("ROOT_REQUIRED",output.getvalue())


if __name__ == "__main__":
    unittest.main()
