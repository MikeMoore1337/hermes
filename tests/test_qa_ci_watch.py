"""H-04: scheduler service is read-only and stays independent from editorial YFC."""
from __future__ import annotations

import io
import unittest
from pathlib import Path
from unittest.mock import patch

from qa_advisor import watch_once

ROOT=Path(__file__).resolve().parents[1]


class MainCIScheduleTests(unittest.TestCase):
    def test_execute_is_explicit_and_no_implicit_network(self):
        with patch.object(watch_once,"inspect_once") as net:
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(watch_once.main([]),0)
            self.assertIn("NOT_EXECUTED",out.getvalue())
            net.assert_not_called()

    def test_success_stores_only_a_minimal_signal(self):
        expected={"status":"SUCCESS","run_id":999,"head_sha":"a"*40}
        with patch.object(watch_once,"inspect_once",return_value=expected) as reader:
            with patch.object(watch_once,"store",return_value="STORED_SAFE_CI_SIGNAL") as writer:
                with patch("sys.stdout",new_callable=io.StringIO) as out:
                    self.assertEqual(watch_once.main(["--execute"]),0)
                reader.assert_called_once_with()
                self.assertEqual(writer.call_count,1)
                sent=writer.call_args.args[0]
                self.assertEqual(set(sent),{"schema","repo","workflow","status","run_id","head_sha","observed_at"})
                self.assertIn('"outbound_notifications": 0',out.getvalue())

    def test_observe_feed_uses_one_read_without_new_authority(self):
        result = {"status": "SUCCESS", "run_id": 999, "head_sha": "a"*40}
        report = {"schema": "hermes-gh-observe-inbox-v1", "events": []}
        with patch.object(watch_once, "inspect_once", return_value=result):
            with patch.object(watch_once, "store", return_value="STORED_SAFE_CI_SIGNAL"):
                with patch.object(watch_once.observe_feed, "poll", return_value=report) as poll:
                    with patch.object(watch_once.observe_feed, "save",
                                      return_value="STORED_SAFE_GITHUB_OBSERVATIONS") as save:
                        with patch("sys.stdout", new_callable=io.StringIO) as out:
                            self.assertEqual(watch_once.main(["--execute", "--observe-feed"]), 0)
        self.assertEqual(poll.call_count, 1)
        save.assert_called_once_with(report)
        self.assertEqual(__import__("json").loads(out.getvalue())["github_observe_feed"], "STORED")

    def test_observer_network_failure_preserves_original_ci_result(self):
        from qa_advisor.github_public import GithubPublicError
        ci = {"status": "FAILURE", "run_id": 999, "head_sha": "a"*40}
        with patch.object(watch_once, "inspect_once", return_value=ci):
            with patch.object(watch_once, "store", return_value="STORED_SAFE_CI_SIGNAL") as store:
                with patch.object(watch_once.observe_feed, "poll",
                                  side_effect=GithubPublicError("github_forbidden_or_rate_limited")):
                    with patch("sys.stdout", new_callable=io.StringIO) as out:
                        self.assertEqual(watch_once.main(["--execute", "--observe-feed"]), 0)
        store.assert_called_once()
        result = __import__("json").loads(out.getvalue())
        self.assertEqual(result["signal"], "FAILURE")
        self.assertEqual(result["github_observe_feed"], "UNAVAILABLE")
        self.assertEqual(result["outbound_notifications"], 0)

    def test_auth_or_network_failure_no_db_and_no_sender(self):
        from qa_advisor.github_public import GithubPublicError
        with patch.object(watch_once,"inspect_once",
                          side_effect=GithubPublicError("github_forbidden_or_rate_limited")):
            with patch.object(watch_once,"store") as writer:
                with patch("sys.stdout",new_callable=io.StringIO) as out:
                    self.assertEqual(watch_once.main(["--execute"]),2)
            writer.assert_not_called()
        self.assertIn("UNKNOWN",out.getvalue())

    def test_service_has_no_extra_capabilities_secrets_or_news_write(self):
        service=(ROOT/"deploy/hermes-qa-watch.service").read_text()
        for required in (
            "CapabilityBoundingSet=\n", "NoNewPrivileges=yes",
            "ProtectSystem=strict","ProtectHome=yes",
            "ReadWritePaths=/var/lib/hermes-qa-watch",
            "ReadOnlyPaths=/etc/hermes-agent/github-actions-read.token",
            "StateDirectoryMode=0700", "User=root",
            "InaccessiblePaths=/var/lib/hermes /var/lib/hermes-agent ",
            "ExecStart=/usr/bin/python3 -m qa_advisor.watch_once --execute",
            "MemoryMax=96M", "TimeoutStartSec=40s",
        ):
            with self.subTest(required=required):
                self.assertIn(required,service)
        for forbidden in ("EnvironmentFile=", "Restart=always",
                          "hermes-discovery.service", "telegram_sender",
                          "CAP_DAC_READ_SEARCH","docker "):
            self.assertNotIn(forbidden,service)

    def test_timer_is_bounded_and_does_not_catch_up(self):
        timer=(ROOT/"deploy/hermes-qa-watch.timer").read_text()
        for expected in ("OnActiveSec=2min","OnUnitActiveSec=15min",
                         "Persistent=false","Unit=hermes-qa-watch.service"):
            self.assertIn(expected,timer)
        self.assertNotIn("OnCalendar=",timer)


if __name__=="__main__":
    unittest.main()
