"""#809 - bounded automatic Engineering Control on the existing QA timer."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from qa_advisor import engineering_auto as auto
from qa_advisor import watch_once as watch

NOW = datetime(2026, 11, 5, 18, 0, tzinfo=UTC)


def report(*, statuses=None):
    defaults = {
        "release_guard": "READY_FOR_OWNER_REVIEW",
        "merge_control": "REVIEW_REQUIRED",
        "deppilot": "INCONCLUSIVE",
        "opensource_radar": "NEEDS_REVIEW",
    }
    defaults.update(statuses or {})
    return {
        "schema": "hermes-engineering-inbox-v1",
        "owner_approval": "NOT_GRANTED",
        "execution_authorized": False,
        "sources": {key: {"status": val, "checked_at": NOW.isoformat(),
                          "reason_count": 0} for key, val in defaults.items()},
    }


def unlimited_budget(_instant):
    return nullcontext(True)


class AutoEngineeringTests(unittest.TestCase):
    def test_auto_lockfile_matches_installed_control_center_layout(self):
        self.assertEqual(auto.LOCKFILE, Path(
            "/opt/hermes-control-center/current/control_center/frontend/package-lock.json"
        ))
        self.assertEqual(auto.PACKAGES, ("react",))

    def test_fixed_four_module_sources_and_no_approval(self):
        calls = []

        def collector(**kwargs):
            calls.append(kwargs)
            return report()

        saved = []
        result = auto.refresh(
            now=NOW, collector=collector,
            saver=lambda value: saved.append(value) or "STORED_SANITIZED_ENGINEERING",
            time_limit=nullcontext, budget=unlimited_budget,
            lockfile=Path("/isolated/approved/package-lock.json"),
        )
        self.assertEqual(result, "STORED")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["repo"], "MikeMoore1337/hermes")
        self.assertEqual(calls[0]["source_repo"], "NousResearch/hermes-agent")
        self.assertEqual(calls[0]["runtime"], "22.0.0")
        self.assertEqual(calls[0]["packages"], ["react"])
        self.assertEqual(calls[0]["lockfile"], Path("/isolated/approved/package-lock.json"))
        self.assertEqual(calls[0]["now"], NOW)
        self.assertEqual(saved, [report()])
        self.assertFalse(saved[0]["execution_authorized"])
        self.assertEqual(saved[0]["owner_approval"], "NOT_GRANTED")

    def test_partial_results_never_false_green(self):
        state = report(statuses={"deppilot": "NOT_AVAILABLE"})
        result = auto.refresh(
            now=NOW, collector=lambda **_: state,
            saver=lambda _: "STORED_SANITIZED_ENGINEERING",
            time_limit=nullcontext, budget=unlimited_budget,
        )
        self.assertEqual(result, "PARTIAL")

    def test_durable_budget_enforces_45_minutes_even_after_restart(self):
        if os.name != "posix":
            self.skipTest("POSIX-only production lease")
        calls, writes = [], []
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            lease = lambda instant: auto.reserve_budget(instant, directory=directory)
            for minutes, expected in (
                (0, "STORED"), (15, "SKIPPED_COOLDOWN"),
                (30, "SKIPPED_COOLDOWN"), (45, "STORED"),
            ):
                result = auto.refresh(
                    now=NOW + timedelta(minutes=minutes),
                    collector=lambda **kwargs: calls.append(kwargs) or report(),
                    saver=lambda r: writes.append(r) or "STORED_SANITIZED_ENGINEERING",
                    time_limit=nullcontext, budget=lease,
                    reader_factory=lambda: object(),
                )
                self.assertEqual(result, expected)
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(writes), 2)
            self.assertEqual(calls[0]["max_open_prs"], 3)
            marker = directory / auto.AUTO_BUDGET_FILE
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_failed_attempt_still_consumes_public_api_budget(self):
        if os.name != "posix":
            self.skipTest("POSIX-only production lease")
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            lease = lambda instant: auto.reserve_budget(instant, directory=directory)

            def failed(**kwargs):
                calls.append(kwargs)
                raise RuntimeError("synthetic public network failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic"):
                auto.refresh(now=NOW, collector=failed, time_limit=nullcontext, budget=unlimited_budget,
                             budget=lease)
            self.assertEqual(
                auto.refresh(now=NOW + timedelta(minutes=15), collector=failed,
                             time_limit=nullcontext, budget=lease),
                "SKIPPED_COOLDOWN",
            )
            self.assertEqual(len(calls), 1)

    def test_invalid_or_unsafe_budget_file_fails_closed(self):
        if os.name != "posix":
            self.skipTest("POSIX-only production lease")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            marker = directory / auto.AUTO_BUDGET_FILE
            marker.write_text("untrusted", encoding="ascii")
            marker.chmod(0o600)
            with self.assertRaisesRegex(auto.AutoUnavailable, "engineering_budget_unsafe"):
                with auto.reserve_budget(NOW, directory=directory):
                    self.fail("invalid marker must not grant an API request")
            marker.write_text("1700000000\\n", encoding="ascii")
            marker.chmod(0o644)
            with self.assertRaisesRegex(auto.AutoUnavailable, "engineering_budget_unsafe"):
                with auto.reserve_budget(NOW, directory=directory):
                    self.fail("loose permissions must never grant an API request")

    def test_concurrent_run_does_not_obtain_budget(self):
        if os.name != "posix":
            self.skipTest("POSIX-only production lease")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            marker = directory / auto.AUTO_BUDGET_FILE
            fd = os.open(marker, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                auto.fcntl.flock(fd, auto.fcntl.LOCK_EX)
                with auto.reserve_budget(NOW, directory=directory) as granted:
                    self.assertFalse(granted)
            finally:
                auto.fcntl.flock(fd, auto.fcntl.LOCK_UN)
                os.close(fd)

    def test_deadline_covers_persistence_not_only_github_reads(self):
        inside = []
        @contextmanager
        def deadline_scope():
            inside.append("open")
            try:
                yield
            finally:
                inside.append("closed")
        def guarded_save(value):
            self.assertEqual(inside, ["open"])
            return "STORED_SANITIZED_ENGINEERING"

        result = auto.refresh(
            now=NOW, collector=lambda **_: report(),
            saver=guarded_save, budget=unlimited_budget,
            time_limit=deadline_scope,
        )
        self.assertEqual(result, "STORED")
        self.assertEqual(inside, ["open", "closed"])

    def test_bounded_public_github_client_refuses_excess_requests(self):
        class Reader:
            def __init__(self):
                self.calls = 0

            def get(self, path):
                self.calls += 1
                return {"schema": "synthetic"}

        inner = Reader()
        scoped = auto.BudgetedGithub(reader=inner)
        for _ in range(auto.MAX_AUTO_GITHUB_GET):
            self.assertEqual(scoped.get("/repos/MikeMoore1337/hermes"), {
                "schema": "synthetic",
            })
        self.assertEqual(inner.calls, auto.MAX_AUTO_GITHUB_GET)
        with self.assertRaisesRegex(auto.SourceUnavailable, "automatic_github_budget_exceeded"):
            scoped.get("/repos/MikeMoore1337/hermes")
        self.assertEqual(inner.calls, auto.MAX_AUTO_GITHUB_GET)

    def test_auto_requires_shared_bounded_source_and_three_pr_window(self):
        calls = []

        def collector(**kwargs):
            calls.append(kwargs)
            return report()

        auto.refresh(
            now=NOW, collector=collector,
            saver=lambda _: "STORED_SANITIZED_ENGINEERING",
            time_limit=nullcontext, budget=unlimited_budget,
            reader_factory=lambda: "bounded-injected",
        )
        self.assertEqual(calls[0]["github_client"], "bounded-injected")
        self.assertEqual(calls[0]["max_open_prs"], 3)
        self.assertLessEqual(auto.MAX_AUTO_GITHUB_GET, 26)
        self.assertEqual(auto.AUTO_EVERY_TICKS, 3)

    def test_no_persistence_when_collector_times_out(self):
        writes = []

        @contextmanager
        def expired():
            raise auto.AutoUnavailable("engineering_deadline_exceeded")
            yield

        with self.assertRaises(auto.AutoUnavailable):
            auto.refresh(
                now=NOW, collector=lambda **_: report(),
                saver=lambda value: writes.append(value),
                time_limit=expired, budget=unlimited_budget,
            )
        self.assertEqual(writes, [])

    def test_no_persistence_on_refused_result(self):
        with self.assertRaisesRegex(auto.AutoUnavailable, "sanitized_save_unavailable"):
            auto.refresh(
                now=NOW, collector=lambda **_: report(),
                saver=lambda _: "REFUSED",
                time_limit=nullcontext, budget=unlimited_budget,
            )

    def test_reject_naive_timestamp(self):
        with self.assertRaisesRegex(auto.AutoUnavailable, "clock_invalid"):
            auto.refresh(now=datetime(2026, 11, 5),
                         collector=lambda **_: report(), time_limit=nullcontext)

    def test_deadline_restores_signal_handler(self):
        if os.name != "posix":
            self.skipTest("SIGALRM is only supported on Linux")
        original = signal.getsignal(signal.SIGALRM)
        with auto.deadline(2):
            left, interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(left, 0)
            self.assertEqual(interval, 0)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), original)

    def test_deadline_refuses_to_steal_existing_alarm(self):
        if os.name != "posix":
            self.skipTest("SIGALRM is only supported on Linux")
        previous = signal.getsignal(signal.SIGALRM)
        try:
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.setitimer(signal.ITIMER_REAL, 8)
            with self.assertRaisesRegex(auto.AutoUnavailable, "existing_alarm_refused"):
                with auto.deadline():
                    pass
            remaining, interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(remaining, 0)
            self.assertEqual(interval, 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    @staticmethod
    def _watch_call(argv, *, refreshed=None):
        with patch.object(watch, "inspect_once", return_value={"status": "UNKNOWN"}):
            with patch.object(watch, "from_ci", return_value={}):
                with patch.object(watch, "store", return_value="STORED_SAFE_CI_SIGNAL"):
                    with patch.object(watch.observe_feed, "poll", return_value={}):
                        with patch.object(watch.observe_feed, "save", return_value="STORED"):
                            with patch.object(watch.project_feed, "poll", return_value={}):
                                with patch.object(watch.project_feed, "save", return_value="STORED"):
                                    with patch.object(auto, "refresh", side_effect=refreshed) as refresh:
                                        output = io.StringIO()
                                        with patch("sys.stdout", output):
                                            code = watch.main(argv)
        return code, json.loads(output.getvalue()), refresh

    def test_watch_default_is_inert_even_with_auto_flag(self):
        code, result, calls = self._watch_call(
            ["--engineering-auto"],
            refreshed=AssertionError("must not invoke without --execute"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(result, {"status": "NOT_EXECUTED"})
        calls.assert_not_called()

    def test_watch_legacy_mode_does_not_call_engineering(self):
        code, result, calls = self._watch_call(
            ["--execute"],
            refreshed=AssertionError("must not call engineering"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "STORED")
        self.assertEqual(result["github_projects_feed"], "STORED")
        self.assertNotIn("engineering_control", result)
        calls.assert_not_called()

    def test_watch_opt_in_after_existing_watchers(self):
        code, result, calls = self._watch_call(
            ["--execute", "--engineering-auto"],
            refreshed=["PARTIAL"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["engineering_control"], "PARTIAL")
        self.assertEqual(result["github_observe_feed"], "STORED")
        self.assertEqual(result["github_projects_feed"], "STORED")
        self.assertEqual(result["outbound_notifications"], 0)
        calls.assert_called_once_with()

    def test_engineering_failure_does_not_damage_existing_ci_status(self):
        code, result, calls = self._watch_call(
            ["--execute", "--engineering-auto"],
            refreshed=auto.AutoUnavailable("engineering_deadline_exceeded"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "STORED")
        self.assertEqual(result["github_observe_feed"], "STORED")
        self.assertEqual(result["github_projects_feed"], "STORED")
        self.assertEqual(result["engineering_control"], "UNAVAILABLE")
        calls.assert_called_once()

    def test_existing_qa_unit_reused_not_extra_schedule(self):
        root = Path(__file__).resolve().parents[1]
        content = (root / "deploy" / "hermes-qa-watch.service").read_text(encoding="utf-8")
        timer = (root / "deploy" / "hermes-qa-watch.timer").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/bin/python3 -m qa_advisor.watch_once --execute --engineering-auto", content)
        self.assertIn("TimeoutStartSec=75s", content)
        self.assertIn("MemoryMax=96M", content)
        self.assertIn("CPUQuota=10%", content)
        self.assertIn("OnUnitActiveSec=15min", timer)
        self.assertNotIn("OnUnitActiveSec=1min", timer)


if __name__ == "__main__":
    unittest.main()
