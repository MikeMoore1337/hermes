"""Hermes #349: offline-only observed kernel controls, not model permission."""
from __future__ import annotations

from pathlib import Path
import json
import os
import tempfile
import unittest

from eval_lane.isolation_probe import inspect_offline_controls

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy" / "hermes-skill-evals-offline.service.example"
TIMEOUT_SECONDS = 30


class OfflineOSProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc" / "self"
        self.proc.mkdir(parents=True)
        self.cg = self.root / "sys" / "fs" / "cgroup"
        self.scope = self.cg / "slice" / "eval-worker"
        self.scope.mkdir(parents=True)
        self.net = self.root / "sys" / "class" / "net"
        (self.net / "lo").mkdir(parents=True)
        self.status = self.proc / "status"
        self.status.write_text(
            "Name:\teval-worker\nNoNewPrivs:\t1\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t0000000000000000\n"
            "Seccomp:\t2\n", encoding="ascii")
        (self.proc / "cgroup").write_text(
            "0::/slice/eval-worker\n", encoding="ascii")
        (self.scope / "memory.max").write_text(str(768 * 1024**2) + "\n")
        (self.scope / "cpu.max").write_text("45000 100000\n")
        (self.scope / "pids.max").write_text("32\n")

    def run_probe(self, **override):
        return inspect_offline_controls(
            proc=self.root / "proc",
            cgroup=self.cg,
            interfaces=self.net,
            effective_uid=override.pop("effective_uid", 10001),
            **override,
        )

    def test_all_expected_observed_controls_can_pass_offline_only(self):
        evidence = self.run_probe()
        self.assertEqual(evidence["status"], "OFFLINE_OS_CONTROLS_OBSERVED")
        self.assertTrue(all(evidence["checks"].values()))
        self.assertEqual(evidence["actual_outbound_deny_test"], "NOT_PERFORMED")
        self.assertEqual(evidence["provider_cost_cap"], "NOT_VERIFIED")
        self.assertFalse(evidence["live_model_execution_allowed"])

    def test_observed_limits_fail_closed_on_each_violation(self):
        violations = (
            (self.scope / "memory.max", "max"),
            (self.scope / "memory.max", str(1024 * 1024 * 1024)),
            (self.scope / "pids.max", "max"),
            (self.scope / "pids.max", "64"),
            (self.scope / "cpu.max", "max 100000"),
            (self.scope / "cpu.max", "50000 100000"),
            (self.scope / "cpu.max", "0 100000"),
        )
        for i, (file, value) in enumerate(violations):
            with self.subTest(i=i, value=value):
                before = file.read_text()
                file.write_text(value + "\n")
                try:
                    check = self.run_probe()
                    self.assertEqual(check["status"], "NO_GO")
                    self.assertFalse(check["checks"]["private_cgroup_limits"])
                finally:
                    file.write_text(before)

    def test_capability_privilege_and_seccomp_fail_closed(self):
        for original, change, field in (
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0", "no_new_privileges"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001",
             "no_effective_capabilities"),
            ("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001",
             "no_bounding_capabilities"),
            ("Seccomp:\t2", "Seccomp:\t0", "seccomp_filter"),
        ):
            with self.subTest(field=field):
                before = self.status.read_text()
                self.status.write_text(before.replace(original, change))
                try:
                    evidence = self.run_probe()
                    self.assertEqual(evidence["status"], "NO_GO")
                    self.assertFalse(evidence["checks"][field])
                finally:
                    self.status.write_text(before)

    def test_unisolated_network_or_root_forbids_positive_result(self):
        (self.net / "eth0").mkdir()
        evidence = self.run_probe()
        self.assertFalse(evidence["checks"]["only_loopback_interface"])
        self.assertEqual(evidence["status"], "NO_GO")
        self.assertEqual(self.run_probe(effective_uid=0)["status"], "NO_GO")

    def test_incomplete_cgroup_and_symlink_do_not_pass(self):
        self.assertTrue(self.run_probe()["checks"]["private_cgroup_limits"])
        (self.scope / "memory.max").unlink()
        (self.scope / "memory.max").symlink_to("/dev/null")
        self.assertEqual(self.run_probe()["status"], "NO_GO")
        (self.scope / "memory.max").unlink()
        (self.proc / "cgroup").write_text("0::/../other\n")
        self.assertEqual(self.run_probe()["status"], "NO_GO")

    def test_offline_systemd_sample_requires_static_os_guards(self):
        text = UNIT.read_text(encoding="utf-8")
        required = (
            "PrivateNetwork=yes", "IPAddressDeny=any",
            "RestrictAddressFamilies=AF_UNIX", "User=hermes-evals",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=",
            "AmbientCapabilities=", "CPUQuota=45%", "MemoryMax=768M",
            "TasksMax=32", "ProtectHome=yes", "ProtectSystem=strict",
            "ExecStart=/usr/bin/python3 -m eval_lane.isolation_probe",
            "ConditionPathExists=/etc/hermes-skill-evals/owner-offline-probe-opt-in",
        )
        for literal in required:
            with self.subTest(key=literal):
                self.assertIn(literal, text)
        self.assertNotIn("WantedBy=", text)
        self.assertNotIn("ExecStart=/bin/sh", text)
        self.assertNotIn("EnvironmentFile=", text)


if __name__ == "__main__":
    unittest.main()
