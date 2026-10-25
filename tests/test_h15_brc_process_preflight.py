"""#445: fail-closed PID1/cgroup Windows BRC sandbox admission contracts."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import h15_brc_process_preflight as gate


def healthy() -> dict:
    return {
        "uid": 65534,
        "pids_current": 40, "pids_max": 96,
        "memory_current": 160 * 1024 * 1024,
        "memory_max": 512 * 1024 * 1024,
        "tmp_free_bytes": 40 * 1024 * 1024,
        "pid1_zombies": 0,
    }


class ProcessPreflightTests(unittest.TestCase):
    def test_healthy_is_observation_not_host_change_permission(self):
        value = gate.evaluate(healthy())
        self.assertEqual(value["status"], "CAPACITY_OBSERVED_NOT_AUTHORIZED")
        self.assertEqual(value["pids_available"], 56)
        self.assertEqual(value["actions_executed"], 0)
        self.assertFalse(value["host_repair_verified"])
        self.assertFalse(value["reboot_verified"])
        self.assertFalse(value["reconnect_verified"])

    def test_actual_exhaustion_and_pid1_zombies_are_distinct(self):
        value = gate.evaluate({
            **healthy(), "pids_current": 90, "pid1_zombies": 24
        })
        self.assertEqual(value["status"], "HOLD")
        self.assertEqual(value["pids_available"], 6)
        self.assertEqual(value["reasons"], [
            "PID_HEADROOM_LOW", "PID1_ZOMBIES_NOT_REAPED"
        ])

    def test_exact_pid_boundary_and_zombie_gate(self):
        snap = {**healthy(), "pids_current": 72}
        self.assertEqual(gate.evaluate(snap)["status"], "CAPACITY_OBSERVED_NOT_AUTHORIZED")
        snap["pids_current"] += 1
        self.assertEqual(gate.evaluate(snap)["reasons"], ["PID_HEADROOM_LOW"])
        snap["pids_current"] -= 1
        snap["pid1_zombies"] = 1
        self.assertEqual(gate.evaluate(snap)["reasons"], ["PID1_ZOMBIES_NOT_REAPED"])

    def test_multiple_resource_failures_report_without_secrets(self):
        snap = {
            **healthy(), "pids_current": 96, "pid1_zombies": 23,
            "tmp_free_bytes": 0,
            "memory_current": 512 * 1024 * 1024
        }
        result = gate.evaluate(snap)
        self.assertEqual(result["reasons"], [
            "PID_HEADROOM_LOW", "PID1_ZOMBIES_NOT_REAPED",
            "TMP_HEADROOM_LOW", "MEMORY_HEADROOM_LOW"
        ])
        self.assertNotIn("argv", result)
        self.assertNotIn("token", result)

    def test_invalid_types_keys_and_overcommitted_limits_denied(self):
        for mutation in (
            {"uid": True}, {"pids_current": -1}, {"pids_current": 97},
            {"pids_max": 0}, {"pids_max": 8192},
            {"memory_current": "1000"}, {"memory_current": 1024**3},
            {"memory_max": 0}, {"tmp_free_bytes": -1},
            {"pid1_zombies": "unknown"}, {"uid": 1000},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(gate.ProcessPreflightDenied):
                    gate.evaluate({**healthy(), **mutation})
        with self.assertRaisesRegex(gate.ProcessPreflightDenied, "MEASUREMENT_INVALID"):
            gate.evaluate({**healthy(), "secret": "payload"})

    def test_untrusted_numeric_cgroup_is_denied(self):
        for content in ("max", "2e3", " 0 ", "+96", "-2", "9" * 17, "inf", "1\n2"):
            with self.subTest(content=content):
                with self.assertRaises(gate.ProcessPreflightDenied):
                    gate._number(content)
        self.assertEqual(gate._number("96"), 96)

    def test_collect_uses_only_status_and_cgroup_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cg = root / "cg"
            proc = root / "proc"
            cg.mkdir()
            proc.mkdir()
            for k, val in {
                "pids.current": "70", "pids.max": "96",
                "memory.current": str(160*1024*1024),
                "memory.max": str(512*1024*1024),
            }.items():
                (cg / k).write_text(val, encoding="ascii")
            for pid, state, parent in [(10,"Z (zombie)",1), (11,"S (sleeping)",1),
                                        (12,"Z (zombie)",2)]:
                entry = proc / str(pid)
                entry.mkdir()
                (entry / "status").write_text(
                    f"Name:\tchild\nState:\t{state}\nPPid:\t{parent}\n"
                    "Uid:\t65534\t65534\t65534\t65534\n"
                )
            fake_stat = SimpleNamespace(f_bavail=2048, f_frsize=4096)
            with patch.object(gate.os, "geteuid", return_value=65534), \
                patch.object(gate.os, "statvfs", return_value=fake_stat):
                sample = gate.collect(cgroup=cg, proc=proc, tmp="/tmp")
            self.assertEqual(sample["pid1_zombies"], 1)
            self.assertEqual(sample["tmp_free_bytes"], 8388608)
            self.assertEqual(sample["pids_current"], 70)

    def test_too_many_process_dirs_refuse_clean_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            for pid in range(3):
                (proc / str(pid)).mkdir()
            with patch.object(gate, "MAX_PID_DIRS", 2):
                with self.assertRaisesRegex(
                    gate.ProcessPreflightDenied, "PROCESS_SNAPSHOT_UNAVAILABLE"
                ):
                    gate._count_pid1_zombies(proc)

    def test_pid1_zombie_requires_actual_parent_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            for pid, status in [
                (1, "Name: test\nState:\tS (sleeping)\nPPid:\t0\n"),
                (10, "Name: test\nState:\tZ (zombie)\nPPid:\t1\n"),
                (11, "Name: test\nState:\tZ (zombie)\nPPid:\t10\n"),
            ]:
                p = proc / str(pid)
                p.mkdir()
                (p / "status").write_text(status)
            self.assertEqual(gate._count_pid1_zombies(proc), 1)

    def test_no_host_actions_and_no_secret_in_cli_failure(self):
        output = io.StringIO()
        with patch.object(gate, "collect",
                          side_effect=OSError("C:\\private\\owner-token")), \
             contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 2)
        response = json.loads(output.getvalue())
        self.assertEqual(response["status"], "HOLD")
        self.assertEqual(response["reasons"], ["OBSERVATION_UNAVAILABLE"])
        self.assertEqual(response["actions_executed"], 0)
        self.assertNotIn("owner-token", output.getvalue())

    def test_cli_measured_degraded_is_exit_two(self):
        output = io.StringIO()
        with patch.object(gate, "collect",
                          return_value={**healthy(), "pid1_zombies": 1}), \
             contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 2)
        self.assertEqual(json.loads(output.getvalue())["reasons"],
                         ["PID1_ZOMBIES_NOT_REAPED"])

    def test_cli_healthy_is_zero_but_not_authorization(self):
        output = io.StringIO()
        with patch.object(gate, "collect", return_value=healthy()), \
             contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 0)
        response = json.loads(output.getvalue())
        self.assertEqual(response["status"], "CAPACITY_OBSERVED_NOT_AUTHORIZED")
        self.assertFalse(response["host_repair_verified"])


if __name__ == "__main__":
    unittest.main()
