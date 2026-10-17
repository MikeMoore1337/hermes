"""Offline, synthetic regression checks for safe v0.22.2 staging."""
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from scripts import h01_stage_image as stage
from scripts.host_capacity import HostFacts


def facts(
    *, load: float = 0.5, available: int = 2500, swap: int = 0,
    disk: int = 12000, news: bool = False,
) -> HostFacts:
    return HostFacts(
        available_mib=available, swap_used_mib=swap, load1=load,
        disk_free_mib=disk, news_phase_active=news,
    )


class StagingAdmissionTests(unittest.TestCase):
    def test_default_is_readonly_and_requires_explicit_execution(self) -> None:
        with patch.object(stage, "execute") as execute:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(stage.main([]), 0)
        execute.assert_not_called()
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "PREVIEW_ONLY")
        self.assertIn("@sha256:", payload["image"])
        self.assertEqual(payload["max_load1"], 1.3)

    def test_peak_load_fails_closed_above_1_30(self) -> None:
        self.assertEqual(stage.blockers(facts(load=1.30), units_healthy=True), [])
        self.assertIn("host_load_exceeded",
                      stage.blockers(facts(load=1.31), units_healthy=True))
        self.assertIn("host_load_exceeded",
                      stage.blockers(facts(load=2.72), units_healthy=True))

    def test_other_resource_and_service_failures(self) -> None:
        failures = stage.blockers(
            facts(available=1300, swap=1030, disk=3000, news=True),
            units_healthy=False,
        )
        self.assertEqual(
            failures,
            ["required_service_unhealthy", "news_job_in_progress",
             "available_memory_low", "swap_pressure", "disk_space_low"],
        )

    @patch.object(stage.os, "geteuid", return_value=0)
    @patch.object(stage.sys, "platform", "linux")
    def test_busy_host_never_launches_docker(self, _uid: Mock) -> None:
        spawn = Mock()
        result = stage.execute(
            facts=lambda: facts(load=2.72),
            healthy=lambda: True,
            present=lambda: False,
            spawn=spawn,
        )
        self.assertEqual(result["status"], "BLOCKED_PRECHECK")
        spawn.assert_not_called()

    @patch.object(stage.os, "geteuid", return_value=0)
    @patch.object(stage.sys, "platform", "linux")
    def test_already_pinned_image_skips_pull(self, _uid: Mock) -> None:
        spawn = Mock()
        result = stage.execute(
            facts=lambda: facts(), healthy=lambda: True,
            present=lambda: True, spawn=spawn,
        )
        self.assertEqual(result["status"], "PINNED_IMAGE_PRESENT")
        spawn.assert_not_called()

    @patch.object(stage.os, "geteuid", return_value=0)
    @patch.object(stage.sys, "platform", "linux")
    def test_mid_pull_load_spike_stops_without_retries(self, _uid: Mock) -> None:
        process = Mock()
        process.poll.return_value = None
        process.pid = 100001
        samples = iter([facts(), facts(load=2.72)])
        with patch.object(stage, "_stop_process_group") as stop:
            result = stage.execute(
                clock=lambda: 10.0,
                sleep=lambda _: None,
                facts=lambda: next(samples),
                healthy=lambda: True,
                present=lambda: False,
                spawn=lambda *args, **kwargs: process,
            )
        self.assertEqual(result["status"], "PULL_STOPPED_BY_GUARD")
        self.assertEqual(result["reason"], "host_load_exceeded")
        self.assertTrue(result["daemon_may_still_be_extracting"])
        stop.assert_called_with(process)

    @patch.object(stage.os, "geteuid", return_value=0)
    @patch.object(stage.sys, "platform", "linux")
    def test_completed_pull_requires_digest_observation(self, _uid: Mock) -> None:
        process = Mock(returncode=0)
        process.poll.return_value = 0
        result = stage.execute(
            facts=lambda: facts(), healthy=lambda: True,
            present=lambda: False, spawn=lambda *a, **kw: process,
        )
        self.assertEqual(result["status"], "IMAGE_IDENTITY_UNVERIFIED")

    @patch.object(stage.os, "geteuid", return_value=0)
    @patch.object(stage.sys, "platform", "linux")
    def test_exact_pull_argv_has_no_fallback_or_activation(self, _uid: Mock) -> None:
        process = Mock(returncode=0)
        process.poll.return_value = 0
        seen: dict[str, object] = {}
        reads = iter([False, True])

        def spawn(argv, **kwargs):
            seen.update(argv=argv, kwargs=kwargs)
            return process

        result = stage.execute(
            facts=lambda: facts(), healthy=lambda: True,
            present=lambda: next(reads), spawn=spawn,
        )
        self.assertEqual(result["status"], "PINNED_IMAGE_READY_OFFLINE_ONLY")
        argv = seen["argv"]
        self.assertEqual(argv[-1], stage.PINNED_IMAGE)
        self.assertEqual(argv[-3:-1], ["--platform", "linux/amd64"])
        self.assertNotIn("latest", " ".join(argv))
        self.assertNotIn("gateway", " ".join(argv))
        self.assertTrue(seen["kwargs"]["start_new_session"])


if __name__ == "__main__":
    unittest.main()
