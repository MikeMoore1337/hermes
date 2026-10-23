"""Issue #542: no-network contract tests of the one-shot public HN search."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import unittest
from unittest.mock import patch

from content_research.hn_public_probe import (
    MAX_BYTES, PublicSearchError, main, normalize_results, run,
)

NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)


def response(*rows: dict) -> bytes:
    return json.dumps({"hits": list(rows)}).encode("utf-8")


def story(identifier: str = "123", **changes) -> dict:
    row = {
        "objectID": identifier,
        "title": "Synthetic AI agents project discussion",
        "points": 11,
        "created_at_i": int((NOW - timedelta(days=3)).timestamp()),
        "url": "https://www.example.com/article",
    }
    row.update(changes)
    return row


class PublicHNProbeTests(unittest.TestCase):
    def test_valid_one_shot_fixture(self):
        count = []
        def transport(query, cutoff):
            count.append((query, cutoff))
            return response(story("123"), story("124", points=18))
        result = run("ai-agents", now=NOW, transport=transport)
        self.assertEqual(1, len(count))
        self.assertEqual("AI agents", count[0][0])
        self.assertEqual(2, result["observed_count"])
        self.assertEqual(10, result["minimum_points"])
        self.assertEqual(0, result["network_requests"])
        self.assertEqual("SAMPLE_ONLY_NOT_FULL_30_DAY_COVERAGE", result["completeness"])
        self.assertEqual(["124", "123"],
                         [x["url"].split("=")[-1] for x in result["items"]])
        self.assertTrue(all(not x["scientific_evidence"] for x in result["items"]))

    def test_invalid_topic_denies_transport(self):
        called = []
        with self.assertRaisesRegex(PublicSearchError, "topic_not_allowed"):
            run("all-internet", now=NOW, transport=lambda *args: called.append(args))
        self.assertEqual([], called)

    def test_schema_limits(self):
        for bad in (b"<html>bad", b'{"hits":{}}', b'{"hits":' + b"[" + b"{}," * 13 + b"{}]}",
                    b"a" * (MAX_BYTES + 1)):
            with self.subTest(size=len(bad)):
                with self.assertRaises(PublicSearchError):
                    normalize_results(bad, now=NOW)

    def test_unsafe_data_dropped_without_runtime_effect(self):
        rejected = [
            story("yes"),
            story("999", title="evil\ncommand"),
            story("100", points=True),
            story("105", points=9),
            story("101", points=-8),
            story("102", created_at_i=int((NOW + timedelta(days=1)).timestamp())),
            story("103", created_at_i=int((NOW - timedelta(days=31)).timestamp())),
            story("104", title=""),
        ]
        result = normalize_results(response(story("123"), *rejected), now=NOW)
        self.assertEqual(1, len(result))
        self.assertEqual("https://news.ycombinator.com/item?id=123", result[0]["url"])
        self.assertNotIn("www.example.com", json.dumps(result))

    def test_existing_research_scout_deliberately_excludes_hn_discussions(self):
        from research_scout.core import EvidenceError, safe_source_url
        with self.assertRaises(EvidenceError):
            safe_source_url("https://news.ycombinator.com/item?id=123")
        result = run("ai-agents", now=NOW,
                     transport=lambda *_: response(story("123")))
        self.assertEqual("https://news.ycombinator.com/item?id=123",
                         result["items"][0]["url"])
        self.assertFalse(result["items"][0]["scientific_evidence"])

    def test_no_execute_never_fetches(self):
        with patch("content_research.hn_public_probe._fetch", side_effect=AssertionError("network")):
            self.assertEqual(0, main(["--topic", "ai-agents"]))
        self.assertEqual(0, run("python-qa", now=NOW,
                                transport=lambda *_: response())["network_requests"])

    def test_boundary_included_and_no_explicit_url_fetch(self):
        recent = story("100", created_at_i=int((NOW - timedelta(days=30)).timestamp()))
        data = response(recent)
        self.assertEqual(1, len(normalize_results(data, now=NOW)))
        with patch("content_research.hn_public_probe._fetch", return_value=data) as mocked:
            self.assertEqual(1, run("fitness-tech", now=NOW)["network_requests"])
            mocked.assert_called_once()


if __name__ == "__main__":
    unittest.main()
