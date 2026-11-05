"""Opt-in Engineering Control sweep: no implicit network or cross-project effects."""
from __future__ import annotations

from datetime import UTC, datetime
import io
import json
from unittest.mock import patch
import unittest

from qa_advisor import engineering_once as one
from qa_advisor.engineering_feed import EngineeringFeedRefused

NOW = datetime(2026, 11, 5, 15, 0, tzinfo=UTC)
REPO = "MikeMoore1337/hermes"
STAMP = NOW.isoformat().replace("+00:00", "Z")


def output(module):
    schemas = {
        "release_guard": "hermes-releaseguard-precheck-v1",
        "merge_control": "hermes-mergecontrol-review-v1",
        "opensource_radar": "hermes-ossradar-review-v1",
        "deppilot": "hermes-deppilot-plan-v1",
    }
    statuses = {
        "release_guard": "INCONCLUSIVE",
        "merge_control": "REVIEW_REQUIRED",
        "opensource_radar": "HOLD_FOR_REVIEW",
        "deppilot": "REVIEW_REQUIRED",
    }
    value = {
        "schema": schemas[module], "status": statuses[module],
        "checked_at": STAMP, "reasons": [], "recommendation_only": True,
    }
    if module == "deppilot":
        value.update(changes_written=False, production_authorized=False)
    elif module == "opensource_radar":
        value.update(owner_approval="NOT_GRANTED", install_authorized=False)
    else:
        value.update(owner_approval="NOT_GRANTED", execution_authorized=False)
        value["deploy_authorized" if module == "release_guard" else "merge_authorized"] = False
    return value


class SweepTests(unittest.TestCase):
    def test_default_is_inert(self):
        with patch.object(one, "collect", side_effect=AssertionError("unexpected network")):
            with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(one.main([]), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "NOT_EXECUTED"})

    def test_hermes_read_only_two_sources(self):
        with patch.object(one, "release_snapshot", return_value=output("release_guard")) as release:
            with patch.object(one, "merge_snapshot", return_value=output("merge_control")) as merge:
                result = one.collect(repo=REPO, now=NOW)
        self.assertEqual(result["sources"]["release_guard"]["status"], "INCONCLUSIVE")
        self.assertEqual(result["sources"]["merge_control"]["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["sources"]["deppilot"]["status"], "NOT_AVAILABLE")
        self.assertEqual(result["sources"]["opensource_radar"]["status"], "NOT_AVAILABLE")
        self.assertFalse(result["execution_authorized"])
        release.assert_called_once()
        merge.assert_called_once()

    def test_partial_api_failure_preserves_other_source(self):
        with patch.object(one, "release_snapshot",
                          side_effect=one.SourceUnavailable("github_network_unavailable")):
            with patch.object(one, "merge_snapshot", return_value=output("merge_control")):
                feed = one.collect(repo=REPO, now=NOW)
        self.assertEqual(feed["sources"]["release_guard"]["status"], "NOT_AVAILABLE")
        self.assertEqual(feed["sources"]["merge_control"]["status"], "REVIEW_REQUIRED")

    def test_all_failed_is_no_write_refusal(self):
        with patch.object(one, "release_snapshot",
                          side_effect=one.SourceUnavailable("network_unavailable")):
            with patch.object(one, "merge_snapshot",
                              side_effect=one.SourceUnavailable("network_unavailable")):
                with self.assertRaisesRegex(EngineeringFeedRefused, "no_available_source_results"):
                    one.collect(repo=REPO, now=NOW)

    def test_invalid_arguments_block_before_network(self):
        with patch.object(one, "release_snapshot") as release:
            for args in (
                {"repo": "other/private"},
                {"repo": REPO, "lockfile": __import__("pathlib").Path("uv.lock")},
                {"repo": REPO, "runtime": "3.14.0"},
                {"repo": REPO, "source_repo": "https://evil.example/candidate"},
            ):
                with self.subTest(args=args), self.assertRaises(EngineeringFeedRefused):
                    one.collect(now=NOW, **args)
            release.assert_not_called()

    def test_opt_in_radar_and_selected_packages(self):
        with patch.object(one, "release_snapshot", return_value=output("release_guard")):
            with patch.object(one, "merge_snapshot", return_value=output("merge_control")):
                with patch.object(one, "radar_snapshot", return_value=output("opensource_radar")):
                    with patch.object(one, "_file", return_value=b"minimal-lock"):
                        with patch.object(one, "candidates_for", return_value=output("deppilot")) as candidate:
                            fed = one.collect(repo=REPO, now=NOW, source_repo="pypa/sampleproject",
                                              lockfile=__import__("pathlib").Path("uv.lock"),
                                              runtime="3.14.0", packages=["pytest"])
        self.assertEqual(sum(x["status"] != "NOT_AVAILABLE" for x in fed["sources"].values()), 4)
        self.assertFalse(fed["execution_authorized"])
        candidate.assert_called_once()

    def test_explicit_save_is_only_write_path(self):
        feed = {
            "schema": "hermes-engineering-inbox-v1",
            "observed_at": STAMP,
            "scope": "SANITIZED_READONLY_ENGINEERING",
            "owner_approval": "NOT_GRANTED",
            "execution_authorized": False,
            "sources": {},
        }
        with patch.object(one, "collect", return_value=feed):
            with patch.object(one, "save") as saved:
                with patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(one.main(["--execute"]), 0)
                saved.assert_not_called()
                with patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(one.main(["--execute", "--save"]), 0)
                saved.assert_called_once_with(feed)


if __name__ == "__main__":
    unittest.main()
