"""H454: no-production owner enrollment tests (pure mocks + temp files).

Never contacts Docker, BRC, original project roots, SQLite, systemd or owner TTY.
The actual protected device token is never printed or written into this repo.
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import os
import stat
import unittest
from unittest import mock

from scripts import h454_native_hermes_enrollment as op


class OriginalHermesNativeEnrollmentTests(unittest.TestCase):
    def test_root_read_only_plan_does_not_run_enrollment(self):
        candidate = SimpleNamespace(roots=(("hermes", "/srv/synthetic-hermes"),))
        with mock.patch.object(op.os, "geteuid", return_value=0), \
             mock.patch.object(op.socket, "gethostname",
                               return_value="vps1777112993"), \
             mock.patch.object(op, "_source_gate") as source, \
             mock.patch.object(op, "_service_gate",
                               return_value=(object(), candidate, "f" * 64)) as service, \
             mock.patch.object(op, "_runtime_gate") as runtime, \
             mock.patch.object(op, "_compiled_gate") as compiled, \
             mock.patch.object(op, "_docker_post") as post, \
             mock.patch.object(op, "_write_device") as write:
            result = op.plan()
        self.assertEqual(result["status"], "H454_HERMES_NATIVE_ENROLL_PLAN_PASS")
        self.assertEqual(result["manifest_sha256"], "f" * 64)
        self.assertEqual(result["roots_checked"], 1)
        self.assertFalse(result["mutations"])
        self.assertFalse(result["device_paired"])
        self.assertFalse(result["service_started"])
        source.assert_called_once()
        service.assert_called_once()
        runtime.assert_called_once()
        compiled.assert_called_once()
        post.assert_not_called()
        write.assert_not_called()

    def test_wrong_host_and_nonroot_never_inspect_live_relay(self):
        for uid, hostname in ((1000, "vps1777112993"), (0, "wrong-vps")):
            with self.subTest(uid=uid, host=hostname), \
                 mock.patch.object(op.os, "geteuid", return_value=uid), \
                 mock.patch.object(op.socket, "gethostname",
                                   return_value=hostname), \
                 mock.patch.object(op, "_runtime_gate") as runtime:
                with self.assertRaisesRegex(op.EnrollmentHold,
                                            "^ORIGINAL_ROOT_REQUIRED$"):
                    op.plan()
                runtime.assert_not_called()

    def test_write_service_owned_config_exact_bytes_no_overwrite(self):
        with TemporaryDirectory(prefix="h454-hermes-native-device-") as tmp:
            path = Path(tmp)
            os.chmod(path, 0o700)
            payload = b'{"synthetic":"never-an-actual-bearer"}'
            with mock.patch.object(op.os, "fchown") as chown:
                op._write_device(path, os.geteuid(), os.getegid(), payload)
            chown.assert_called_once()
            deployed = path / "device.json"
            self.assertEqual(deployed.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(deployed.stat().st_mode), 0o600)
            self.assertEqual(deployed.stat().st_nlink, 1)
            self.assertFalse((path / op.TMP_NAME).exists())
            with self.assertRaisesRegex(op.EnrollmentHold,
                                        "^DEVICE_FILE_ALREADY_PRESENT$"):
                op._write_device(path, os.geteuid(), os.getegid(), b"foreign")
            self.assertEqual(deployed.read_bytes(), payload)

    def test_interrupted_temp_file_refuses_without_overwriting(self):
        with TemporaryDirectory(prefix="h454-hermes-native-collision-") as tmp:
            path = Path(tmp)
            (path / op.TMP_NAME).write_bytes(b"interrupted")
            with self.assertRaisesRegex(op.EnrollmentHold,
                                        "^DEVICE_FILE_ALREADY_PRESENT$"):
                op._write_device(path, os.geteuid(), os.getegid(),
                                 b'{"not":"authorized"}')
            self.assertFalse((path / "device.json").exists())
            self.assertEqual((path / op.TMP_NAME).read_bytes(), b"interrupted")

    def test_docker_exec_private_loopback_no_secret_in_argv(self):
        token = "brc_dev_" + "A" * 60
        body = json.dumps({
            "device_code": "opaque-test-code",
            "name": op.NAME["hermes-vps"], "platform": "linux",
        }).encode("ascii")
        response = json.dumps({
            "status": 200,
            "body": json.dumps({"device_token": token}),
        }).encode("ascii")
        with mock.patch.object(op, "_runtime_gate") as runtime, \
             mock.patch.object(op.subprocess, "run",
                               return_value=SimpleNamespace(
                                   returncode=0, stdout=response)) as run:
            status, result = op._docker_post("/device/poll", body)
        self.assertEqual(status, 200)
        self.assertIn(token.encode(), result)
        command = run.call_args.args[0]
        self.assertEqual(command, [
            "/usr/bin/docker", "exec", "--interactive", "--user",
            "65534:65534", op.RELAY, "node", "--input-type=module", "-",
        ])
        self.assertNotIn("opaque-test-code", " ".join(command))
        self.assertNotIn(token, " ".join(command))
        self.assertIn(b"opaque-test-code", run.call_args.kwargs["input"])
        self.assertEqual(runtime.call_count, 2)

    def test_docker_exec_denies_any_caller_device_id_override(self):
        extra = {
            "device_code": "opaque-code",
            "name": op.NAME["hermes-vps"],
            "platform": "linux",
            "device_id": "h454-linux-hermes-" + "a" * 32,
        }
        with mock.patch.object(op, "_runtime_gate") as runtime, \
             mock.patch.object(op.subprocess, "run") as run:
            with self.assertRaisesRegex(op.EnrollmentHold,
                                        "^FOREIGN_PAIR_REQUEST$"):
                op._docker_post("/device/poll",
                                json.dumps(extra).encode("ascii"))
            runtime.assert_called_once()
            run.assert_not_called()

    def test_docker_exec_rejects_oversized_or_unexpected_reply(self):
        start_body = json.dumps({
            "client_name": op.NAME["hermes-vps"],
        }).encode("ascii")
        for result in (
            SimpleNamespace(returncode=1, stdout=b""),
            SimpleNamespace(returncode=0, stdout=b"not-json"),
            SimpleNamespace(returncode=0, stdout=b'{"status":599,"body":""}'),
            SimpleNamespace(returncode=0, stdout=b'{"status":200,"body":"'
                            + b"X" * 5000 + b'"}'),
        ):
            with self.subTest(stdout_len=len(result.stdout)), \
                 mock.patch.object(op, "_runtime_gate"), \
                 mock.patch.object(op.subprocess, "run", return_value=result):
                with self.assertRaises(op.EnrollmentHold):
                    op._docker_post("/device/start", start_body)

    def test_enrollment_does_not_activate_service_or_print_token(self):
        manifest_sha = "f" * 64
        report = {"status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
                  "manifest_sha256": manifest_sha}
        code = "ABCD-EFGH"
        pending = SimpleNamespace(target="hermes-vps", user_code=code)
        device_id = "h454-linux-hermes-" + "a" * 32
        token = "brc_dev_" + "A" * 64
        paired = SimpleNamespace(target="hermes-vps", device_id=device_id,
                                 token=token,
                                 ws_url="wss://hermes.mikemoore.top/ws")
        candidate = SimpleNamespace(roots=(("hermes", "/test/host-project"),))
        service = SimpleNamespace(pw_uid=972, pw_gid=968)
        with mock.patch.object(op, "plan", return_value=report) as plan, \
             mock.patch.object(op, "_tty_confirm") as tty, \
             mock.patch.object(op, "_service_gate",
                               return_value=(service, candidate, manifest_sha)), \
             mock.patch.object(op, "native_start", return_value=pending) as start, \
             mock.patch.object(op, "_approve_pending") as approve, \
             mock.patch.object(op, "native_poll", return_value=paired) as poll, \
             mock.patch.object(op, "_parse_config") as parse, \
             mock.patch.object(op, "_write_device") as write, \
             mock.patch.object(op.subprocess, "run",
                               return_value=SimpleNamespace(
                                   stdout=b"inactive\n", returncode=3)) as run:
            reply = op.enroll()
        self.assertEqual(reply["status"],
                         "H454_HERMES_NATIVE_OWNER_DEVICE_PAIRED_SERVICE_OFF")
        self.assertEqual(plan.call_count, 3)
        self.assertEqual(tty.call_count, 2)
        self.assertEqual(tty.call_args_list[0].args[0],
                         "H454 ENROLL READ ONLY HERMES VPS " + manifest_sha)
        self.assertEqual(tty.call_args_list[1].args[0],
                         "PAIR H454 hermes-vps " + code)
        approve.assert_called_once_with(code)
        start.assert_called_once()
        poll.assert_called_once()
        self.assertEqual(write.call_count, 1)
        saved = json.loads(write.call_args.args[3])
        self.assertEqual(saved["token"], token)
        self.assertEqual(saved["device_id"], device_id)
        self.assertEqual(saved["target"], "hermes-vps")
        self.assertEqual(saved["release_sha"], op.RELEASE)
        self.assertEqual(saved["roots"], [
            {"project": "hermes", "path": "/test/host-project"}
        ])
        self.assertEqual(saved["schema"], op.CONFIG_SCHEMA)
        parse.assert_called_once()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0],
                         ["/usr/bin/systemctl", "is-active",
                          "hermes-commander-native.service"])

    def test_host_drift_blocks_before_creating_device_code(self):
        first = {"status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
                 "manifest_sha256": "a" * 64}
        changed = dict(first, manifest_sha256="b" * 64)
        with mock.patch.object(op, "plan", side_effect=[first, changed]), \
             mock.patch.object(op, "_tty_confirm"), \
             mock.patch.object(op, "native_start") as start, \
             mock.patch.object(op, "_approve_pending") as approve, \
             mock.patch.object(op, "_write_device") as write:
            with self.assertRaisesRegex(op.EnrollmentHold,
                                        "^HOST_DRIFT_AFTER_APPROVAL$"):
                op.enroll()
            start.assert_not_called()
            approve.assert_not_called()
            write.assert_not_called()

    def test_missing_execute_never_issues_code_or_starts_service(self):
        with mock.patch.object(op, "plan") as plan, \
             mock.patch.object(op, "enroll") as enroll:
            self.assertEqual(op.main(["enroll"]), 2)
            self.assertEqual(op.main(["plan", "--execute"]), 2)
        plan.assert_not_called()
        enroll.assert_not_called()


if __name__ == "__main__":
    unittest.main()
