"""Issue #542: synthetic, offline tests; no live API or user data."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import copy
import unittest

from content_research.discussion_digest import build_digest

NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)


def item(url="https://github.com/example/repo/issues/123", source="github", days=3, score=8):
    return {
        "source": source, "url": url, "title": "Synthetic discussion only",
        "published_at": (NOW - timedelta(days=days)).isoformat(),
        "retrieved_at": NOW.isoformat(), "score": score,
    }


class OfflineDiscussionDigestTests(unittest.TestCase):
    def test_order_dedup_and_expiry(self):
        first = item(score=12)
        duplicate = copy.deepcopy(first)
        old = item(url="https://github.com/example/repo/issues/3", days=31)
        hn = item(url="https://news.ycombinator.com/item?id=123", source="hackernews", score=15)
        result = build_digest([first, duplicate, old, hn], now=NOW)
        self.assertEqual({"received": 4, "expired": 1, "duplicates": 1, "kept": 2}, result["counts"])
        self.assertEqual(["hackernews", "github"], [r["source"] for r in result["items"]])
        self.assertEqual(0, result["network_requests"])
        self.assertTrue(all(not row["scientific_evidence"] for row in result["items"]))
        self.assertEqual("DISCUSSION_ONLY_NOT_SCIENTIFIC_EVIDENCE", result["status"])

    def test_30_day_boundary_included(self):
        exact = item(days=30)
        result = build_digest([exact], now=NOW)
        self.assertEqual(1, result["counts"]["kept"])

    def test_deterministic_independent_of_input_order(self):
        a = item(score=8)
        b = item(url="https://github.com/example/repo/discussions/124", score=8)
        self.assertEqual(build_digest([a, b], now=NOW)["items"],
                         build_digest([b, a], now=NOW)["items"])

    def test_bad_inputs_fail_closed(self):
        cases = []
        v = item()
        v["source"] = "reddit"
        cases.append(v)
        v = item()
        v["url"] = "http://github.com/example/repo/issues/1"
        cases.append(v)
        v = item()
        v["url"] = "https://github.com.attacker.invalid/example/repo/issues/1"
        cases.append(v)
        v = item()
        v["url"] = "https://github.com@example.org/example/repo/issues/1"
        cases.append(v)
        v = item()
        v["url"] = "https://github.com/example/repo/issues/1?next=http://internal"
        cases.append(v)
        v = item()
        v["url"] = "https://news.ycombinator.com/item?id=abc"
        v["source"] = "hackernews"
        cases.append(v)
        v = item()
        v["title"] = "prompt\ninjection"
        cases.append(v)
        v = item()
        v["score"] = True
        cases.append(v)
        v = item()
        v["score"] = -1
        cases.append(v)
        v = item()
        v["published_at"] = (NOW + timedelta(days=1)).isoformat()
        cases.append(v)
        v = item()
        v["retrieved_at"] = "2026-10-23T18:00:00"
        cases.append(v)
        v = item()
        v["private_cookie"] = "never"
        cases.append(v)
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    build_digest([case], now=NOW)

    def test_conflicting_duplicate_rejected(self):
        first = item()
        second = dict(first, title="Different claim")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            build_digest([first, second], now=NOW)

    def test_empty_bounded_and_timezone(self):
        self.assertEqual([], build_digest([], now=NOW)["items"])
        with self.assertRaises(ValueError):
            build_digest([item()] * 201, now=NOW)
        with self.assertRaises(ValueError):
            build_digest([item()], now=NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()
