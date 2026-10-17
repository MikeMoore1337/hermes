"""Offline synthetic contract tests for #272. Never start Codex or perform inference."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from control_center.codex_analytics import collect, read, project_from_cwd, _union_seconds


UTC = dt.timezone.utc
ID = "019acd30-197e-7000-8000-000000000001"


def item(kind, payload, at="2026-10-18T00:00:00Z"):
    return json.dumps({"timestamp": at, "type": kind, "payload": payload},
                      ensure_ascii=False) + "\n"


def usage(input_tokens, output_tokens, cached=None, at="2026-10-18T00:00:00Z"):
    total = {"input_tokens": input_tokens, "output_tokens": output_tokens,
             "total_tokens": input_tokens + output_tokens}
    if cached is not None:
        total["cached_input_tokens"] = cached
    return item("event_msg", {"type": "token_count", "info": {
        "total_token_usage": total, "last_token_usage": total}}, at)


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "codex"
        self.folder = self.home / "sessions/2026/10/18"
        self.folder.mkdir(parents=True)
        self.file = self.folder / f"rollout-2026-10-18T00-00-00-{ID}.jsonl"
        self.db = Path(self.tmp.name) / "private" / "analytics.sqlite3"
        self.now = dt.datetime(2026, 10, 18, 0, 30, tzinfo=UTC)

    def write(self, *events):
        self.file.write_text("".join(events), encoding="utf-8")

    def inspect(self):
        return read(self.db, period="24h", now=self.now)

    def test_empty_no_fake_zeros(self):
        empty = self.inspect()
        self.assertIsNone(empty["tokens"]["total"])
        self.assertIsNone(empty["actual_spend_usd"])
        self.assertEqual(empty["quality"], "unknown")
        self.assertEqual(collect(self.home, self.db, now=self.now)["scanned_files"], 0)
        self.assertIsNone(self.inspect()["tokens"]["total"])

    def test_cumulative_not_sum_and_repeated_last_snapshot(self):
        self.write(item("session_meta", {"id": ID, "cwd": "/srv/hermes"}),
                   item("turn_context", {"model": "gpt-5.3-codex", "effort": "high"}),
                   usage(100, 20, 40), usage(180, 30, 80), usage(180, 30, 80))
        collect(self.home, self.db, now=self.now)
        result = self.inspect()
        self.assertEqual(result["tokens"],
                         {"input": 180, "output": 30, "cached_input": 80, "total": 210})
        self.assertEqual(result["sessions"], 1)
        self.assertEqual(result["models"][0]["name"], "gpt-5.3-codex")
        self.assertEqual(result["projects"][0]["name"], "Hermes")
        self.assertEqual(result["pricing_coverage"], 1.0)
        self.assertIsNotNone(result["api_equivalent_usd"])
        self.assertIsNone(result["actual_spend_usd"])
        collect(self.home, self.db, now=self.now)
        self.assertEqual(self.inspect()["tokens"]["total"], 210)

    def test_backfill_partial_jsonl_and_invalid_line(self):
        self.write(usage(10, 2, 3), "garbage\n", usage(20, 4, 6),
                   '{"timestamp":"2026-10-18T00:00:00Z","type":"event_msg"')
        result = collect(self.home, self.db, now=self.now)
        self.assertEqual(result["incomplete_files"], 1)
        self.assertEqual(self.inspect()["tokens"]["total"], 24)
        with self.file.open("a", encoding="utf-8") as f:
            f.write('}\n')
            f.write(usage(35, 7, 10))
        collect(self.home, self.db, now=self.now)
        self.assertEqual(self.inspect()["tokens"]["total"], 42)
        self.assertIsNone(self.inspect()["actual_spend_usd"])

    def test_broken_negative_unknown_usage_does_not_corrupt(self):
        self.write(usage(20, 2, 5), usage(-10, 3, 6),
                   item("event_msg", {"type": "token_count", "info": {
                       "total_token_usage": {"input_tokens": "no", "output_tokens": 4}}}),
                   usage(20, 2, 5), usage(30, 5, 8))
        collect(self.home, self.db, now=self.now)
        result = self.inspect()
        self.assertEqual(result["tokens"]["total"], 35)
        self.assertGreaterEqual(result["invalid_events"], 2)

    def test_missing_cached_and_model_are_partial(self):
        self.write(usage(40, 3))
        collect(self.home, self.db, now=self.now)
        result = self.inspect()
        self.assertEqual(result["quality"], "partial")
        self.assertIsNone(result["tokens"]["cached_input"])
        self.assertIsNone(result["api_equivalent_usd"])
        self.assertEqual(result["models"][0]["name"], "unattributed")

    def test_prompt_and_private_path_not_persisted(self):
        self.write(item("session_meta", {"id": ID, "cwd": "/secret/hermes",
                                        "private_value": "ABSOLUTELY_PRIVATE"}),
                   item("response_item", {"content": "ABSOLUTELY_PRIVATE"}),
                   item("event_msg", {"type": "user_message",
                                      "message": "ABSOLUTELY_PRIVATE"}),
                   usage(3, 1, 1))
        collect(self.home, self.db, now=self.now)
        data = json.dumps(self.inspect())
        self.assertNotIn("ABSOLUTELY_PRIVATE", data)
        self.assertNotIn("/secret/", data)
        self.assertNotIn("auth.json", data)
        self.assertNotIn(b"ABSOLUTELY_PRIVATE", self.db.read_bytes())

    def test_symlinks_denied(self):
        other = Path(self.tmp.name) / "outside"
        other.write_text(usage(999, 10, 4))
        self.file.symlink_to(other)
        collect(self.home, self.db, now=self.now)
        self.assertIsNone(self.inspect()["tokens"]["total"])
        self.db.unlink()
        self.db.symlink_to(other)
        with self.assertRaises(ValueError):
            collect(self.home, self.db, now=self.now)

    def test_activity_union_and_different_timezone(self):
        a = dt.datetime(2026, 10, 18, tzinfo=UTC)
        b = a + dt.timedelta(minutes=10)
        c = a + dt.timedelta(minutes=20)
        self.assertEqual(_union_seconds([(a, b), (a+dt.timedelta(minutes=5), c)]),
                         20*60)
        self.write(item("event_msg", {"type": "task_started"}, "2026-10-18T03:00:00+03:00"),
                   item("event_msg", {"type": "task_complete"}, "2026-10-18T03:03:00+03:00"))
        collect(self.home, self.db, now=self.now)
        self.assertEqual(self.inspect()["duration_seconds"], 180)
        self.assertEqual(self.inspect()["completed_turns"], 1)

    def test_retention_and_no_idle_inference(self):
        self.write(usage(300, 50, 100, "2026-01-01T00:00:00Z"))
        collect(self.home, self.db, now=self.now)
        result = read(self.db, period="all", now=self.now)
        self.assertIsNone(result["tokens"]["total"])
        self.assertEqual(result["quality"], "unknown")

    def test_cached_tokens_cannot_exceed_input(self):
        self.write(usage(10, 2, 99), usage(30, 7, 9))
        collect(self.home, self.db, now=self.now)
        result = self.inspect()
        self.assertEqual(result["tokens"]["total"], 37)
        self.assertGreaterEqual(result["invalid_events"], 1)
        self.assertEqual(result["metric_quality"]["tokens"], "partial")

    def test_session_directory_symlink_is_denied(self):
        outside = Path(self.tmp.name) / "other_sessions"
        outside.mkdir()
        (self.home / "sessions").rename(self.home / "real_sessions")
        (self.home / "sessions").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "sessions_symlink_denied"):
            collect(self.home, self.db, now=self.now)

    def test_project_only_allowlisted_metadata(self):
        self.assertEqual(project_from_cwd("/work/your-fitness-coach"), "Your Fitness Coach")
        self.assertEqual(project_from_cwd("/home/John/unrelated"), "unattributed")
        self.assertEqual(project_from_cwd(None), "unattributed")


if __name__ == "__main__":
    unittest.main()
