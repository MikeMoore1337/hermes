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

    def test_immutable_owner_release_sources_exact_git_blobs(self):
        # The existing deploy runner creates a root-owned 0755 release,
        # then chmod -R a-w makes it 0555. No owner-host permission changes.
        checkout = Path(op.__file__).resolve().parents[1]
        native = checkout / "tests" / "fixtures" / "installed-native-release"
        pinned = checkout / "tests" / "fixtures" / "h454-native-private-tls-30db.py.txt"
        runtime = checkout / "tests" / "fixtures" / "h454-native-linux-runtime-b6e4383.py.txt"
        def read(path, **_kwargs):
            if path == native / "device_fabric/native_private_tls.py":
                return pinned.read_bytes()
            if path == checkout / "scripts/h454_native_linux_runtime.py":
                return runtime.read_bytes()
            return path.read_bytes()
        with mock.patch.object(op, "SOURCE", checkout), \
             mock.patch.object(op, "NATIVE", native), \
             mock.patch.object(op, "_dir") as directory, \
             mock.patch.object(op, "_read", side_effect=read):
            op._source_gate()
        self.assertEqual(directory.call_args_list, [
            mock.call(checkout, owner=0, mode=0o555),
            mock.call(native, owner=0, mode=0o755),
        ])

    def test_installed_native_tls_drift_is_rejected(self):
        checkout = Path(op.__file__).resolve().parents[1]
        native = checkout / "tests" / "fixtures" / "installed-native-release"
        pinned = checkout / "tests" / "fixtures" / "h454-native-private-tls-30db.py.txt"
        runtime = checkout / "tests" / "fixtures" / "h454-native-linux-runtime-b6e4383.py.txt"
        def read(path, **_kwargs):
            if path == native / "device_fabric/native_private_tls.py":
                return pinned.read_bytes() + b"\n# drift"
            if path == checkout / "scripts/h454_native_linux_runtime.py":
                return runtime.read_bytes()
            return path.read_bytes()
        with mock.patch.object(op, "SOURCE", checkout), \
             mock.patch.object(op, "NATIVE", native), \
             mock.patch.object(op, "_dir"), \
             mock.patch.object(op, "_read", side_effect=read), \
             self.assertRaisesRegex(op.EnrollmentHold, "NATIVE_PRIVATE_SOURCE_DRIFT"):
            op._source_gate()

    def test_updated_runtime_is_rejected_by_historical_source_pin(self):
        checkout = Path(op.__file__).resolve().parents[1]
        with mock.patch.object(op, "SOURCE", checkout), \
             mock.patch.object(op, "_dir"), \
             mock.patch.object(op, "_read", side_effect=lambda path, **_kwargs: path.read_bytes()), \
             self.assertRaisesRegex(op.EnrollmentHold, "TRUSTED_SOURCE_DRIFT"):
            op._source_gate()

    def test_old_enrollment_client_is_rejected_by_source_pin(self):
        checkout = Path(op.__file__).resolve().parents[1]

        def read(path, **kwargs):
            data = path.read_bytes()
            if path.name == "native_brc_enrollment.py":
                old = data.replace(b'"hermes.mikemoore.top", "mcp.mikemoore.top"',
                                   b'"hermes.mikemoore.top"')
                self.assertNotEqual(old, data)
                return old
            return data

        with mock.patch.object(op, "SOURCE", checkout), \
             mock.patch.object(op, "NATIVE", checkout), \
             mock.patch.object(op, "_dir"), \
             mock.patch.object(op, "_read", side_effect=read), \
             self.assertRaisesRegex(op.EnrollmentHold, "TRUSTED_SOURCE_DRIFT"):
            op._source_gate()

    def test_immutable_owner_directory_fail_closed_on_drift(self):
        class SyntheticPath:
            def __init__(self, *, owner=0, mode=0o555, parents=()):
                self.owner, self.mode, self.parents = owner, mode, parents

            def is_absolute(self):
                return True

            def lstat(self):
                return SimpleNamespace(st_uid=self.owner,
                                       st_mode=stat.S_IFDIR | self.mode)

        safe_parent = SyntheticPath(owner=0, mode=0o755)
        readonly = SyntheticPath(mode=0o555, parents=(safe_parent,))
        op._dir(readonly, owner=0, mode=0o555)
        for bad in (
            SyntheticPath(mode=0o755, parents=(safe_parent,)),
            SyntheticPath(owner=1000, mode=0o555, parents=(safe_parent,)),
            SyntheticPath(mode=0o555, parents=(
                SyntheticPath(owner=0, mode=0o777),)),
            SyntheticPath(mode=0o555, parents=(
                SyntheticPath(owner=1000, mode=0o755),)),
        ):
            with self.subTest(mode=bad.mode, owner=bad.owner):
                with self.assertRaises(op.EnrollmentHold):
                    op._dir(bad, owner=0, mode=0o555)

    def test_read_only_plan_reports_only_fixed_failure_stage(self):
        import io
        for failed_stage in ("SOURCE", "SERVICE", "RUNTIME", "COMPILED_BRC"):
            with self.subTest(stage=failed_stage), \
                 mock.patch.object(op.os, "geteuid", return_value=0), \
                 mock.patch.object(op.socket, "gethostname",
                                   return_value="vps1777112993"), \
                 mock.patch.object(op, "_source_gate") as source, \
                 mock.patch.object(op, "_service_gate",
                                   return_value=(object(),
                                     SimpleNamespace(roots=(("hermes", "/synthetic"),)),
                                     "a" * 64)) as service, \
                 mock.patch.object(op, "_runtime_gate") as runtime, \
                 mock.patch.object(op, "_compiled_gate") as compiled, \
                 mock.patch.object(op, "_docker_post") as post, \
                 mock.patch.object(op, "_write_device") as write, \
                 mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                stages = {
                    "SOURCE": source,
                    "SERVICE": service,
                    "RUNTIME": runtime,
                    "COMPILED_BRC": compiled,
                }
                stages[failed_stage].side_effect = RuntimeError(
                    "synthetic-sensitive-path-and-token-never-print")
                self.assertEqual(op.main(["plan"]), 2)
                output = stdout.getvalue()
                self.assertNotIn("synthetic-sensitive", output)
                result = json.loads(output)
                self.assertEqual(result["status"],
                                 "H454_HERMES_NATIVE_ENROLLMENT_HOLD")
                self.assertEqual(result["failed_stage"], failed_stage)
                self.assertTrue(result["no_auto_retry"])
                post.assert_not_called()
                write.assert_not_called()

    def _h15_bridge_fixtures(self):
        other_id = "d" * 64
        bridge_id = "c" * 64
        bridge = {
            "Id": bridge_id,
            "Internal": True,
            "Driver": "bridge",
            "Containers": {
                op.RELAY: {"Name": "hermes-brc-relay",
                           "IPv4Address": op.IP + "/28"},
                other_id: {"Name": op.H15_PEER_NAME.lstrip("/"),
                           "IPv4Address": op.H15_PEER_CIDR},
            },
        }
        peer = {
            "Id": other_id,
            "Name": op.H15_PEER_NAME,
            "Image": op.H15_PEER_IMAGE,
            "State": {"Running": True},
            "Config": {"Labels": {"com.hermes.scope": op.H15_PEER_SCOPE}},
            "HostConfig": {
                "NetworkMode": op.NETWORK,
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "PortBindings": {},
                "PublishAllPorts": False,
            },
            "NetworkSettings": {
                "Networks": {
                    op.NETWORK: {"IPAddress": op.H15_PEER_IP,
                                 "NetworkID": bridge_id}
                },
                "Ports": {},
            },
            "Mounts": [{"Destination": "/workspace"}],
        }
        return bridge, peer, other_id

    def test_h15_exact_second_peer_admitted_without_docker_mutation(self):
        bridge, peer, peer_id = self._h15_bridge_fixtures()
        with mock.patch.object(op, "_docker_inspect",
                               return_value=peer) as inspect:
            op._bridge_peers_gate(bridge)
        inspect.assert_called_once_with(peer_id)

        bridge["Containers"].pop(peer_id)
        with mock.patch.object(op, "_docker_inspect") as inspect:
            op._bridge_peers_gate(bridge)
        inspect.assert_not_called()

    def test_h15_peer_rejects_unknown_or_weakened_profile(self):
        from copy import deepcopy
        clean, peer, peer_id = self._h15_bridge_fixtures()
        cases = (
            ("foreign_peer", lambda b, p:
                b["Containers"].update({"e" * 64: {"Name": "outsider"}})),
            ("unexpected_name", lambda b, p:
                b["Containers"][peer_id].update(Name="outsider")),
            ("unexpected_endpoint", lambda b, p:
                b["Containers"][peer_id].update(IPv4Address="172.29.251.4/28")),
            ("unexpected_image", lambda b, p:
                p.update(Image="sha256:" + "a" * 64)),
            ("unexpected_label", lambda b, p:
                p["Config"]["Labels"].update({"com.hermes.scope": "foreign"})),
            ("not_running", lambda b, p:
                p["State"].update(Running=False)),
            ("foreign_id", lambda b, p: p.update(Id="a" * 64)),
            ("host_network", lambda b, p:
                p["HostConfig"].update(NetworkMode="host")),
            ("privileged", lambda b, p:
                p["HostConfig"].update(Privileged=True)),
            ("writable_root", lambda b, p:
                p["HostConfig"].update(ReadonlyRootfs=False)),
            ("extra_caps", lambda b, p:
                p["HostConfig"].update(CapDrop=[])),
            ("missing_nnp", lambda b, p:
                p["HostConfig"].update(SecurityOpt=[])),
            ("public_ports", lambda b, p:
                p["HostConfig"].update(PortBindings={"80/tcp": [{}]})),
            ("foreign_bridge", lambda b, p:
                p["NetworkSettings"]["Networks"][op.NETWORK].update(
                    NetworkID="b" * 64)),
            ("foreign_ip", lambda b, p:
                p["NetworkSettings"]["Networks"][op.NETWORK].update(
                    IPAddress="172.29.251.4")),
            ("docker_socket", lambda b, p:
                p.update(Mounts=[{"Destination": "/var/run/docker.sock"}])),
        )
        for label, change in cases:
            with self.subTest(case=label):
                bridge = deepcopy(clean)
                candidate = deepcopy(peer)
                change(bridge, candidate)
                with mock.patch.object(op, "_docker_inspect",
                                       return_value=candidate):
                    with self.assertRaisesRegex(
                            op.EnrollmentHold,
                            "^FOREIGN_BRIDGE_PEER_OR_ADDRESS$"):
                        op._bridge_peers_gate(bridge)

    def test_runtime_with_h15_second_peer_checks_health_and_no_post(self):
        bridge, peer, peer_id = self._h15_bridge_fixtures()
        relay = {
            "Id": op.RELAY, "Image": op.RELAY_IMAGE,
            "Name": "/hermes-brc-relay",
            "State": {"Running": True},
            "NetworkSettings": {
                "Networks": {
                    op.NETWORK: {"IPAddress": op.IP,
                                 "NetworkID": bridge["Id"]}
                },
                "Ports": {},
            },
            "HostConfig": {"PortBindings": {}, "PublishAllPorts": False},
            "Mounts": [],
            "Config": {"Env": ["HOST=0.0.0.0", "PORT=3000",
                               "PUBLIC_URL=" + op.RELAY_PUBLIC_URL]},
        }
        wss = {
            "Id": op.WSS, "Image": op.WSS_IMAGE,
            "State": {"Running": True},
            "HostConfig": {"NetworkMode": "container:" + op.RELAY},
        }
        entries = {
            "hermes-brc-relay": relay,
            "hermes-h454-wss-proxy": wss,
            op.NETWORK: bridge,
            peer_id: peer,
        }
        with mock.patch.object(op, "_docker_inspect",
                               side_effect=entries.__getitem__) as inspect, \
             mock.patch.object(op.http.client, "HTTPConnection") as connection, \
             mock.patch.object(op, "_docker_post") as post:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "ok": True, "publicUrl": op.RELAY_PUBLIC_URL,
            }).encode("ascii")
            op._runtime_gate()
        self.assertEqual(inspect.call_count, 4)
        connection.assert_called_once_with(op.IP, 3000, timeout=4)
        post.assert_not_called()

        with mock.patch.object(op, "_docker_inspect",
                               side_effect=entries.__getitem__), \
             mock.patch.object(op.http.client, "HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "ok": True, "publicUrl": "https://foreign.example",
            }).encode("ascii")
            with self.assertRaisesRegex(
                    op.EnrollmentHold, "^RELAY_PUBLIC_ORIGIN_CHANGED$"):
                op._runtime_gate()

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
                                 ws_url=op.ENROLLMENT_WS_URL)
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
        self.assertEqual(saved["url"], op.NATIVE_WS_URL)
        self.assertEqual(saved["device_id"], device_id)
        poll.assert_called_once_with(
            pending, post=op._docker_post,
            expected_ws_url=op.ENROLLMENT_WS_URL)
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

    def test_real_pairing_client_accepts_operator_relay_origin(self):
        manifest_sha = "f" * 64
        report = {"status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
                  "manifest_sha256": manifest_sha}
        service = SimpleNamespace(pw_uid=972, pw_gid=968)
        candidate = SimpleNamespace(roots=(("hermes", "/synthetic"),))
        calls = []

        def post(path, body):
            calls.append((path, json.loads(body)))
            if path == "/device/start":
                return 200, json.dumps({
                    "device_code": "a" * 48, "user_code": "ABCD-2345",
                    "verification_uri": "https://example.test/verify",
                    "verification_uri_complete": "https://example.test/verify",
                    "expires_in": 900, "interval": 3,
                }).encode()
            return 200, json.dumps({
                "device_id": "h454-linux-hermes-" + "a" * 32,
                "device_token": "brc_dev_" + "z" * 64,
                "token_type": "bearer", "ws_url": op.ENROLLMENT_WS_URL,
            }).encode()

        with mock.patch.object(op, "plan", return_value=report), \
             mock.patch.object(op, "_tty_confirm"), \
             mock.patch.object(op, "_service_gate", return_value=(service, candidate, manifest_sha)), \
             mock.patch.object(op, "_docker_post", side_effect=post), \
             mock.patch.object(op, "_approve_pending"), \
             mock.patch.object(op, "_parse_config"), \
             mock.patch.object(op, "_write_device") as write, \
             mock.patch.object(op.subprocess, "run", return_value=SimpleNamespace(stdout=b"inactive\n")):
            result = op.enroll()
        self.assertTrue(result["device_paired"])
        self.assertEqual([path for path, _ in calls], ["/device/start", "/device/poll"])
        self.assertNotIn("device_id", calls[1][1])
        self.assertEqual(json.loads(write.call_args.args[3])["url"], op.NATIVE_WS_URL)

    def test_host_drift_blocks_before_creating_device_code(self):
        first = {"status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
                 "manifest_sha256": "a" * 64}
        changed = dict(first, manifest_sha256="b" * 64)
        with mock.patch.object(op, "plan", side_effect=[first, changed]), \
             mock.patch.object(op, "_tty_confirm"), \
             mock.patch.object(op, "native_start") as start, \
             mock.patch.object(op, "_approve_pending") as approve, \
             mock.patch.object(op, "_write_device") as write:
            with self.assertRaises(op.EnrollmentStageHold) as hold:
                op.enroll()
            self.assertEqual(hold.exception.stage, "PLAN_BEFORE_CODE")
            start.assert_not_called()
            approve.assert_not_called()
            write.assert_not_called()

    def test_enroll_reports_fixed_stage_without_exception_or_token(self):
        from io import StringIO
        phase_cases = (
            ("INITIAL_PLAN", "plan"),
            ("TARGET_TTY", "_tty_confirm"),
            ("SERVICE_BEFORE_CODE", "_service_gate"),
            ("ISSUE_CODE", "native_start"),
            ("OWNER_CAS", "_approve_pending"),
            ("TOKEN_POLL", "native_poll"),
            ("CONFIG_VALIDATION", "_parse_config"),
            ("DEVICE_WRITE", "_write_device"),
        )
        report = {"status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
                  "manifest_sha256": "f" * 64}
        pending = SimpleNamespace(target="hermes-vps", user_code="ABCD-EFGH")
        paired = SimpleNamespace(
            target="hermes-vps", device_id="h454-linux-hermes-" + "a" * 32,
            token="brc_dev_" + "Z" * 64, ws_url=op.ENROLLMENT_WS_URL)
        service = SimpleNamespace(pw_uid=972, pw_gid=968)
        candidate = SimpleNamespace(roots=(("hermes", "/synthetic"),))
        for stage, failing in phase_cases:
            with self.subTest(stage=stage), \
                 mock.patch.object(op, "plan", return_value=report) as plan, \
                 mock.patch.object(op, "_tty_confirm") as tty, \
                 mock.patch.object(op, "_service_gate",
                                   return_value=(service, candidate, "f" * 64)) as svc, \
                 mock.patch.object(op, "native_start",
                                   return_value=pending) as start, \
                 mock.patch.object(op, "_approve_pending") as cas, \
                 mock.patch.object(op, "native_poll",
                                   return_value=paired) as poll, \
                 mock.patch.object(op, "_parse_config") as parse, \
                 mock.patch.object(op, "_write_device") as write, \
                 mock.patch.object(op.subprocess, "run",
                    return_value=SimpleNamespace(stdout=b"inactive\n")) as process, \
                 mock.patch("sys.stdout", new_callable=StringIO) as output:
                providers = {
                    "plan": plan, "_tty_confirm": tty,
                    "_service_gate": svc, "native_start": start,
                    "_approve_pending": cas, "native_poll": poll,
                    "_parse_config": parse, "_write_device": write,
                }
                providers[failing].side_effect = ValueError(
                    "SECRET_brс_dev_PRIVATE-NEVER-PRINT")
                self.assertEqual(op.main(["enroll", "--execute"]), 2)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"],
                                 "H454_HERMES_NATIVE_ENROLLMENT_HOLD")
                self.assertEqual(result["failed_stage"], stage)
                self.assertTrue(result["no_auto_retry"])
                self.assertFalse(result["service_started"])
                self.assertNotIn("SECRET", output.getvalue())
                if stage in ("INITIAL_PLAN", "TARGET_TTY", "SERVICE_BEFORE_CODE"):
                    cas.assert_not_called()
                    poll.assert_not_called()
                    write.assert_not_called()
                if stage == "OWNER_CAS":
                    poll.assert_not_called()
                if stage == "TOKEN_POLL":
                    write.assert_not_called()

    def test_native_enrollment_url_uses_public_relay_but_private_native_wss(self):
        self.assertEqual(op.RELAY_PUBLIC_URL, "https://mcp.mikemoore.top")
        self.assertEqual(op.ENROLLMENT_WS_URL,
                         "wss://mcp.mikemoore.top/ws")
        self.assertEqual(op.NATIVE_WS_URL,
                         "wss://hermes.mikemoore.top/ws")

    def test_missing_execute_never_issues_code_or_starts_service(self):
        with mock.patch.object(op, "plan") as plan, \
             mock.patch.object(op, "enroll") as enroll:
            self.assertEqual(op.main(["enroll"]), 2)
            self.assertEqual(op.main(["plan", "--execute"]), 2)
        plan.assert_not_called()
        enroll.assert_not_called()


if __name__ == "__main__":
    unittest.main()
