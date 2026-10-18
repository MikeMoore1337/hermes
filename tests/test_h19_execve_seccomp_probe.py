"""Unit contracts for H-19 real Linux seccomp probe. No Docker in unit tests."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h19_execve_seccomp_probe as seccomp
from scripts.verify_v0222_immutable import IMAGE_DIGEST


def sample():
    return {
        "schema": seccomp.SCHEMA,
        "arch": "linux/amd64",
        "baseline_shell": "EXECUTED",
        "no_new_privs": True,
        "filter_installed": True,
        "kernel_seccomp_mode": 2,
        "guarded_subprocess_shell": "BLOCKED_EPERM",
        "guarded_direct_execve": "BLOCKED_EPERM",
        "guarded_execveat": "BLOCKED_EPERM",
        "guarded_x32_execve": "BLOCKED_EPERM",
        "model_executed": False,
        "real_agent_tools_executed": False,
        "full_os_enforcement_verified": False,
        "h01_resident_allowed": False,
    }


def runner(*, report=None, digest=IMAGE_DIGEST, returncode=0):
    payload = json.dumps(report or sample()).encode()
    identity = (json.dumps(["docker.io/nousresearch/hermes-agent@" + digest])
                + "|amd64").encode()
    return Mock(side_effect=[
        Mock(returncode=0, stdout=identity),
        Mock(returncode=returncode, stdout=payload),
    ])


class ExecveSeccompProbeTests(unittest.TestCase):
    def test_expected_receipt_passes_only_process_local_boundary(self):
        result = seccomp.validate(sample())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["evidence_kind"], "real_process_local_seccomp_in_disposable_container")
        self.assertTrue(result["shell_executed_before_filter"])
        self.assertTrue(result["shell_execve_blocked_after_filter"])
        self.assertEqual(result["full_agent_os_enforcement"], "UNVERIFIED")
        self.assertEqual(result["live_model"], "NOT_RUN")
        self.assertFalse(result["h01_resident_allowed"])

    def test_per_syscall_mutation_fails_closed(self):
        for key in ("baseline_shell", "guarded_subprocess_shell",
                    "guarded_direct_execve", "guarded_execveat", "guarded_x32_execve"):
            altered = sample()
            altered[key] = "UNVERIFIED"
            with self.subTest(key=key):
                self.assertEqual(seccomp.validate(altered)["status"], "FAIL")
        for key in ("no_new_privs", "filter_installed"):
            altered = sample()
            altered[key] = False
            self.assertEqual(seccomp.validate(altered)["status"], "FAIL")
        altered = sample()
        altered["kernel_seccomp_mode"] = 1
        self.assertEqual(seccomp.validate(altered)["status"], "FAIL")

    def test_invalid_schema_and_false_runtime_or_model_go_are_denied(self):
        for item in ("model_executed", "real_agent_tools_executed",
                     "full_os_enforcement_verified", "h01_resident_allowed"):
            altered = sample()
            altered[item] = True
            with self.subTest(item=item), self.assertRaises(seccomp.EvidenceDenied):
                seccomp.validate(altered)
        for item in ("schema", "arch", "guarded_direct_execve"):
            altered = sample()
            altered[item] = {"forged": True}
            with self.subTest(item=item), self.assertRaises(seccomp.EvidenceDenied):
                seccomp.validate(altered)
        for change in ({"unexpected": "PASS"}, {"model_executed": 0}):
            with self.assertRaises(seccomp.EvidenceDenied):
                seccomp.validate({**sample(), **change})

    def test_report_runner_pins_immutable_image_no_egress(self):
        fn = runner()
        code, result = seccomp.run(runner=fn)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(fn.call_count, 2)
        inspect, exec_cmd = [c.args[0] for c in fn.call_args_list]
        self.assertIn(seccomp.IMAGE, inspect)
        self.assertIn(seccomp.IMAGE, exec_cmd)
        self.assertEqual(exec_cmd[-1], seccomp.PROBE)
        for opt in ("--pull=never", "--read-only", "--cap-drop",
                    "--network", "none", "--user", "65534:65534",
                    "--security-opt", "no-new-privileges"):
            self.assertIn(opt, exec_cmd)
        for bad in ("--privileged", "--volume", "--mount", "--env-file",
                    "--network=host", "--publish"):
            self.assertNotIn(bad, exec_cmd)

    def test_image_mismatch_and_probe_failure_do_not_produce_pass(self):
        code, receipt = seccomp.run(runner=runner(digest="sha256:" + "0" * 64))
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "INFRA_FAILURE")
        self.assertFalse(receipt["h01_resident_allowed"])
        code, receipt = seccomp.run(runner=runner(returncode=1))
        self.assertEqual(code, 2)
        self.assertEqual(receipt["full_agent_os_enforcement"], "UNVERIFIED")
        bad_receipt = sample()
        bad_receipt["guarded_direct_execve"] = "EXECUTED"
        code, receipt = seccomp.run(runner=runner(report=bad_receipt))
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "FAIL")

    def test_default_invocation_never_runs_docker(self):
        with patch.object(seccomp, "run") as run, patch(
            "sys.stdout", new_callable=io.StringIO
        ) as output:
            self.assertEqual(seccomp.main([]), 0)
            run.assert_not_called()
            self.assertIn("NOT_RUN", output.getvalue())

    def test_security_probe_does_not_write_or_call_network(self):
        text = seccomp.PROBE
        self.assertIn("PR", "PR")  # smoke: the pinned BPF source is parsed below
        self.assertIn("0x40000000", text)  # reject x32 ABI bypass
        self.assertIn("0xC000003E", text)  # fixed x86-64 AUDIT_ARCH
        self.assertIn("0x00050001", text)  # EPERM return
        self.assertIn("H19_SAFE_EXEC_BASELINE", text)
        self.assertNotIn("shell=True", text)
        self.assertNotIn("https://", text)
        self.assertNotIn("socket.connect", text)


if __name__ == "__main__":
    unittest.main()
