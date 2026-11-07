"""H454 Stage 2 dormant paired relay/WSS transaction: negative contracts."""
from contextlib import nullcontext, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native3_paired_transaction as tx

REL = "a" * 40
SOURCE = "b" * 40
ARCHIVE = "c" * 64
IMAGE = "sha256:" + "d" * 64
RUNTIME = "sha256:" + "e" * 64
OLD_RELAY_ID = "f" * 64
OLD_PROXY_ID = "1" * 64
PINS = b'{"synthetic":"no-secrets"}\n'


def relay():
    return {
        "Id": OLD_RELAY_ID, "Name": "/hermes-brc-relay",
        "Image": tx.stage1.FORK_IMAGE,
        "Config": {"User": "979:975",
                   "Labels": {"com.hermes.scope": "h15-brc-owner-relay"}},
        "State": {"Running": True},
    }


def proxy():
    return {
        "Id": OLD_PROXY_ID, "Name": "/hermes-h454-wss-proxy",
        "Image": tx.stage1.LEGACY_IMAGE,
        "Config": {"User": "65534:65534",
                   "Labels": {"com.hermes.h454.role": "wss-proxy"}},
        "State": {"Running": True},
        "HostConfig": {"NetworkMode": "container:" + OLD_RELAY_ID},
    }


def fake_approval(**changes):
    from hashlib import sha256
    result = {
        "schema": 1,
        "decision": "OWNER_APPROVED_H454_NATIVE3_JOINT_RELAY_WSS_CUTOVER",
        "scope": "EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE",
        "release_sha": REL, "candidate_sha": SOURCE,
        "ci_config_image_id": IMAGE, "archive_sha256": ARCHIVE,
        "runtime_image_id": RUNTIME,
        "previous_relay_image": tx.stage1.FORK_IMAGE,
        "previous_proxy_image": tx.stage1.LEGACY_IMAGE,
        "previous_relay_id": OLD_RELAY_ID,
        "previous_proxy_id": OLD_PROXY_ID,
        "previous_pins_sha256": sha256(PINS).hexdigest(),
        "relay_checkpoint": tx.PAIR_RELAY,
        "proxy_checkpoint": tx.PAIR_PROXY,
    }
    result.update(changes)
    return result


class TransactionTests(unittest.TestCase):
    def test_plan_reuses_existing_read_only_admission(self):
        result = {"status": "PAIR_PREFLIGHT_PASS_NO_MUTATIONS",
                  "changed": False}
        with patch.object(tx.admission, "plan", return_value=result) as gate, \
             patch.object(tx, "cutover") as changed:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = tx.main(["plan", "--release-sha", REL,
                                "--bundle-dir", "/fake", "--image", IMAGE,
                                "--archive-sha", ARCHIVE,
                                "--candidate-sha", SOURCE])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue()), result)
        gate.assert_called_once()
        changed.assert_not_called()

    def test_cutover_requires_explicit_execute_and_plan_refuses_execute(self):
        argv = ["--release-sha", REL, "--bundle-dir", "/fake",
                "--image", IMAGE, "--archive-sha", ARCHIVE,
                "--candidate-sha", SOURCE]
        for args in (["cutover", *argv], ["plan", *argv, "--execute"]):
            with self.subTest(args=args), patch.object(tx, "cutover") as cut:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(tx.main(args), 2)
                cut.assert_not_called()

    def test_untrusted_runtime_exception_does_not_leak_secret(self):
        with patch.object(tx.admission, "plan",
                          side_effect=RuntimeError("SECRET_NEVER_LOG")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(tx.main([
                    "plan", "--release-sha", REL,
                    "--bundle-dir", "/fake", "--image", IMAGE,
                    "--archive-sha", ARCHIVE,
                    "--candidate-sha", SOURCE]), 2)
        self.assertNotIn("SECRET_NEVER_LOG", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "REFUSED")

    def test_exact_root_owned_approval_rejects_any_identity_drift(self):
        with tempfile.TemporaryDirectory(prefix="h454-approval-") as scratch:
            approval = Path(scratch) / "approval.json"
            with patch.object(tx, "APPROVAL", approval), \
                 patch.object(tx.stage1, "protected"):
                for modification in (
                    {"previous_relay_id": "0" * 64},
                    {"previous_proxy_id": "0" * 64},
                    {"runtime_image_id": IMAGE},
                    {"scope": "ALL_FOLDERS"},
                    {"relay_checkpoint": "legacy"},
                    {"decision": "OWNER_APPROVED"},
                    {"schema": True},
                ):
                    with self.subTest(modification=modification):
                        approval.write_text(json.dumps(fake_approval(**modification)))
                        with self.assertRaises(tx.TransactionDenied):
                            self.approve()
                approval.write_text(json.dumps(fake_approval()))
                self.approve()

    @staticmethod
    def approve():
        tx.approval_record(
            release_sha=REL, candidate_sha=SOURCE,
            image=IMAGE, archive_sha=ARCHIVE, runtime=RUNTIME,
            relay=relay(), proxy=proxy(), raw_pins=PINS)

    def test_duplicate_approval_keys_refused_not_overridden(self):
        data = json.dumps(fake_approval())
        data = data.replace('"schema": 1,', '"schema": 1, "schema": 1,')
        with tempfile.TemporaryDirectory(prefix="h454-approval-") as scratch:
            path = Path(scratch) / "approval.json"
            path.write_text(data)
            with patch.object(tx, "APPROVAL", path), \
                 patch.object(tx.stage1, "protected"):
                with self.assertRaisesRegex(
                        tx.TransactionDenied, "APPROVAL_DUPLICATE_KEY"):
                    self.approve()

    def test_docker_discovery_error_is_not_absence(self):
        with patch.object(tx.stage1, "docker",
                          side_effect=tx.stage1.Hold("DOCKER_OPERATION_FAILED")):
            with self.assertRaises(tx.stage1.Hold):
                tx.strict_container(tx.PAIR_RELAY)

    def test_docker_discovery_checks_an_exact_name(self):
        with patch.object(tx.stage1, "docker", return_value="") as docker, \
             patch.object(tx.stage1, "inspect") as inspect:
            self.assertIsNone(tx.strict_container(tx.PAIR_PROXY))
        self.assertIn("name=^/" + tx.PAIR_PROXY + "$",
                      docker.call_args.args)
        inspect.assert_not_called()
        with patch.object(tx.stage1, "docker", return_value="foreign"), \
             patch.object(tx.stage1, "inspect") as inspect:
            with self.assertRaisesRegex(
                    tx.TransactionDenied, "CONTAINER_DISCOVERY_AMBIGUOUS"):
                tx.strict_container(tx.PAIR_PROXY)
            inspect.assert_not_called()

    def test_no_arbitrary_container_lookup(self):
        with patch.object(tx.stage1, "docker") as docker:
            with self.assertRaisesRegex(
                    tx.TransactionDenied, "UNKNOWN_CONTAINER_NAME"):
                tx.strict_container("hermes-control-center")
            docker.assert_not_called()

    def test_relay_recipe_keeps_mount_and_os_restrictions(self):
        command = tx.candidate_relay_args(RUNTIME, "979:975")
        self.assertEqual(command[-1], RUNTIME)
        self.assertEqual(command.count("--mount"), 2)
        self.assertIn(
            "type=bind,src=" + str(tx.candidate.PINNED_REGISTRY_SOURCE)
            + ",dst=" + tx.candidate.REGISTRY_TARGET + ",readonly",
            command)
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--publish", command)
        with self.assertRaisesRegex(
                tx.TransactionDenied, "OLD_RELAY_USER_CHANGED"):
            tx.candidate_relay_args(RUNTIME, "0:0")

    def test_foreign_relay_candidate_must_not_be_deleted(self):
        new = {
            "Id": "9" * 64, "Image": RUNTIME,
            "Config": {"User": "root", "Labels": {}},
            "HostConfig": {
                "ReadonlyRootfs": True, "Privileged": False,
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                "NetworkMode": "hermes-brc-internal",
            },
        }
        with patch.object(tx, "strict_container", side_effect=[
            None, new]), patch.object(tx.stage1, "docker") as docker:
            with self.assertRaises(tx.TransactionDenied):
                tx.restore_pair(
                    relay=relay(), proxy=proxy(), original=PINS,
                    image=RUNTIME, relay_id=new["Id"], proxy_id="",
                    baseline=2, wss=SimpleNamespace())
            docker.assert_not_called()

    def test_unknown_created_container_requires_manual_recovery(self):
        record = {
            "Id": "9" * 64, "Image": RUNTIME,
        }
        with patch.object(tx, "strict_container", side_effect=[None, record]), \
             patch.object(tx.stage1, "docker") as docker:
            with self.assertRaisesRegex(
                    tx.TransactionDenied, "AMBIGUOUS_RELAY_MANUAL_RECOVERY"):
                tx.restore_pair(
                    relay=relay(), proxy=proxy(), original=PINS,
                    image=RUNTIME, relay_id="", proxy_id="",
                    baseline=2, wss=SimpleNamespace())
            docker.assert_not_called()

    def test_approval_is_not_written_or_synthesized_by_cutover(self):
        import inspect
        text = inspect.getsource(tx.cutover)
        self.assertIn("approval_record(", text)
        self.assertNotIn("APPROVAL.write", text)
        self.assertNotIn("subprocess.Popen", text)


    def simulate_cutover(self, *, fail_on_stop=False):
        """No Docker/host mutation: synthetic transaction with real pin marker IO."""
        from contextlib import ExitStack
        from unittest.mock import Mock
        source_pins = {
            "relay_name": tx.legacy.NAME,
            "sidecar_name": tx.stage1.PROXY,
            "relay_image": tx.stage1.FORK_IMAGE,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "relay_id": OLD_RELAY_ID,
            "sidecar_id": OLD_PROXY_ID,
            "tls_directory": "/synthetic/tls",
        }
        new_relay_id, new_proxy_id = "2" * 64, "3" * 64
        created = {"Id": new_relay_id, "Image": RUNTIME}
        record = {
            "status": "PREFLIGHT_PASS", "bundle_verified": True,
            "changes_performed": False, "deployment_approved": False,
            "current_image": tx.stage1.FORK_IMAGE,
            "candidate_image": RUNTIME,
        }
        events = []
        fake_wss = SimpleNamespace(
            _pins=lambda _: source_pins,
            _snapshot=lambda *args: (created, proxy()),
            _namespace=lambda *args: None,
            reconcile=lambda *args: "READY",
        )
        def fake_docker(*args):
            events.append(args)
            if fail_on_stop and args[:2] == ("stop", "--time"):
                raise tx.stage1.Hold("SYNTHETIC_STOP_FAILED")
            if args[:2] == ("run", "-d"):
                return new_relay_id
            return ""
        with tempfile.TemporaryDirectory(prefix="h454-simulated-") as scratch:
            root = Path(scratch)
            with ExitStack() as stack:
                def mock(module, name, value):
                    return stack.enter_context(patch.object(
                        module, name, value))
                mock(tx.os, "geteuid", lambda: 0)
                mock(tx.admission, "verify_installed_source", Mock())
                mock(tx.legacy, "lock", lambda: nullcontext())
                mock(tx.stage1, "protected", Mock())
                mock(tx.legacy, "check_files", Mock())
                mock(tx.candidate, "admit", Mock(return_value=record))
                mock(tx.stage1, "load_existing_wss", Mock(return_value=fake_wss))
                mock(tx.admission, "verify_pair", Mock(return_value=(relay(), proxy())))
                mock(tx.admission, "check_free_checkpoints", Mock())
                mock(tx.legacy, "devices", Mock(return_value=2))
                mock(tx.stage1, "locked_pins", lambda: nullcontext(PINS))
                mock(tx, "strict_container", Mock(side_effect=[
                    relay(), proxy(), created]))
                mock(tx, "approval_record", Mock())
                mock(tx.legacy, "snapshot", Mock(return_value=root / "db"))
                mock(tx.stage1, "PIN_ROOT", root)
                mock(tx, "PENDING", root / "native3-pair.pending")
                mock(tx, "ORIGINAL_PINS", root / "native3-original-pins.json")
                mock(tx.stage1, "docker", fake_docker)
                mock(tx.stage1, "create_sidecar", Mock(return_value=new_proxy_id))
                mock(tx, "updated_pins", Mock(return_value=b"synthetic-new-pins"))
                mock(tx.stage1, "replace_pins", Mock())
                mock(tx.stage1, "PINS",
                     SimpleNamespace(read_bytes=lambda: b"synthetic-new-pins"))
                mock(tx.legacy, "healthy", Mock(return_value=True))
                mock(tx.stage1, "compare_auth", Mock())
                mock(tx.candidate, "inspect", Mock(return_value=created))
                mock(tx.candidate, "current_gate", Mock(return_value=RUNTIME))
                restored = mock(tx, "restore_pair", Mock())
                if fail_on_stop:
                    with self.assertRaisesRegex(
                            tx.TransactionDenied,
                            "PAIR_CUTOVER_FAILED_ORIGINAL_RESTORED"):
                        tx.cutover(
                            release_sha=REL, bundle=root,
                            image=IMAGE, archive_sha=ARCHIVE,
                            candidate_sha=SOURCE)
                    restored.assert_called_once()
                else:
                    outcome = tx.cutover(
                        release_sha=REL, bundle=root,
                        image=IMAGE, archive_sha=ARCHIVE,
                        candidate_sha=SOURCE)
                    self.assertEqual(
                        outcome["status"],
                        "SWITCHED_PENDING_CHATGPT_CODEX_LIVE_ACCEPTANCE")
                    self.assertFalse(outcome["client_e2e_verified"])
                    restored.assert_not_called()
                    self.assertFalse(tx.PENDING.exists())
                    self.assertTrue(tx.ORIGINAL_PINS.exists())
        return events

    def test_synthetic_joint_cutover_orders_proxy_before_relay(self):
        events = self.simulate_cutover()
        stops = [args[-1] for args in events if args and args[0] == "stop"]
        self.assertEqual(stops, [OLD_PROXY_ID, OLD_RELAY_ID])
        self.assertIn(("start", "3" * 64), events)
        self.assertTrue(any(args[:2] == ("run", "-d") for args in events))

    def test_failed_first_stop_invokes_pair_rollback(self):
        events = self.simulate_cutover(fail_on_stop=True)
        self.assertEqual(events[0][-1], OLD_PROXY_ID)
        self.assertFalse(any(args[0] == "rm" for args in events))

    def test_name_takeover_cannot_redirect_mutating_docker_calls(self):
        # After admission, another Docker admin may reassign the names.
        # A name-addressed stop/update/rename would hit these foreign IDs.
        swapped = {
            tx.stage1.PROXY: "8" * 64,
            tx.legacy.NAME: "9" * 64,
        }
        events = self.simulate_cutover()
        actions = [x for x in events if x and x[0] in (
            "stop", "update", "rename")]
        self.assertTrue(actions)
        pinned = {OLD_RELAY_ID, OLD_PROXY_ID, "2" * 64, "3" * 64}
        for action in actions:
            if action[0] == "stop":
                target = action[-1]
            elif action[0] == "update":
                target = action[-1]
            else:
                target = action[1]
            # This resolves the Docker identifier after hostile name reuse.
            resolved = swapped.get(target, target)
            self.assertEqual(target, resolved)
            self.assertIn(resolved, pinned)
            self.assertNotIn(resolved, set(swapped.values()))

    def test_rollback_addresses_verified_ids_after_checkpoint_rename(self):
        source = __import__("inspect").getsource(tx.restore_pair)
        # Prevent a regression to 'docker rename checkpoint_name ...'
        # or start/update by a reassigned container name.
        self.assertIn('docker("rename", original_obj["Id"]', source)
        self.assertIn('docker("start", current["Id"])', source)
        self.assertIn('"unless-stopped", current["Id"]', source)

    def test_pending_marker_rejects_duplicate_keys_and_untrusted_scope(self):
        valid = {
            "schema": 1, "release_sha": REL, "candidate_sha": SOURCE,
            "runtime_image": RUNTIME, "relay_id": OLD_RELAY_ID,
            "proxy_id": OLD_PROXY_ID, "pins_sha256": "4" * 64,
            "baseline": 2, "new_relay_id": "", "new_proxy_id": "",
        }
        with tempfile.TemporaryDirectory(prefix="h454-pending-test-") as tmp:
            path = Path(tmp) / "pending"
            with patch.object(tx, "PENDING", path), \
                 patch.object(tx.stage1, "protected"):
                path.write_text(json.dumps(valid))
                self.assertEqual(tx.pending_read(), valid)
                path.write_text(json.dumps(dict(valid, baseline=0)))
                with self.assertRaisesRegex(
                        tx.TransactionDenied, "PENDING_RECEIPT_INVALID"):
                    tx.pending_read()
                path.write_text(json.dumps(valid).replace(
                    '"schema": 1,', '"schema": 1, "schema": 1,'))
                with self.assertRaisesRegex(
                        tx.TransactionDenied, "PENDING_DUPLICATE_KEY"):
                    tx.pending_read()

    def test_recovery_requires_exact_immutable_candidate_bundle(self):
        with patch.object(tx.candidate, "verify", return_value={
            "owner_agents_paired": True, "production_mcp_enabled": False}), \
             patch.object(tx.candidate, "candidate_runtime_image") as inspected:
            with self.assertRaisesRegex(
                    tx.TransactionDenied, "RECOVERY_BUNDLE_OUT_OF_SCOPE"):
                tx.verified_candidate_for_recovery(
                    Path("/synthetic"), IMAGE, ARCHIVE, SOURCE)
            inspected.assert_not_called()



    def test_pair_rollback_restores_both_original_names_and_pins(self):
        old_r = relay()
        old_p = proxy()
        old_r["State"]["Running"] = False
        old_p["State"]["Running"] = False
        new_r = {"Id": "2" * 64, "Image": RUNTIME}
        new_p = {"Id": "3" * 64, "Image": tx.stage1.LEGACY_IMAGE}
        original = json.dumps({
            "relay_image": tx.stage1.FORK_IMAGE,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "tls_directory": "/synthetic/tls",
        }).encode()
        state = {
            tx.legacy.NAME: new_r, tx.stage1.PROXY: new_p,
            tx.PAIR_RELAY: old_r, tx.PAIR_PROXY: old_p,
        }
        events = []
        def docker(*args):
            events.append(args)
            if args[0] == "rm":
                item = next(k for k, v in state.items()
                            if v["Id"] == args[-1])
                del state[item]
            elif args[0] == "rename":
                original_name = next(name for name, item in state.items()
                                     if item["Id"] == args[1])
                state[args[2]] = state.pop(original_name)
            elif args[0] == "start":
                name = next(name for name, item in state.items()
                            if item["Id"] == args[1])
                state[name]["State"]["Running"] = True
            return ""
        with tempfile.TemporaryDirectory(prefix="h454-pair-rollback-") as tmp:
            marker = Path(tmp) / "pending"
            marker.write_text("synthetic pending")
            fake_wss = SimpleNamespace(
                _pins=lambda _: {"tls_directory": "/synthetic/tls"},
                _snapshot=lambda *args: (old_r, old_p))
            with patch.object(tx, "strict_container", side_effect=state.get), \
                 patch.object(tx, "owned_candidate") as identity_gate, \
                 patch.object(tx.stage1, "docker", side_effect=docker), \
                 patch.object(tx.stage1, "PINS",
                              SimpleNamespace(read_bytes=lambda: b"changed")), \
                 patch.object(tx.stage1, "replace_pins") as restore_pins, \
                 patch.object(tx.stage1, "protected"), \
                 patch.object(tx.stage1, "sync_pin_directory"), \
                 patch.object(tx, "PENDING", marker), \
                 patch.object(tx.legacy, "healthy", return_value=True):
                tx.restore_pair(
                    relay=old_r, proxy=old_p, original=original,
                    image=RUNTIME, relay_id=new_r["Id"],
                    proxy_id=new_p["Id"], baseline=2, wss=fake_wss)
            self.assertEqual(state[tx.legacy.NAME]["Id"], OLD_RELAY_ID)
            self.assertEqual(state[tx.stage1.PROXY]["Id"], OLD_PROXY_ID)
            self.assertNotIn(tx.PAIR_RELAY, state)
            self.assertNotIn(tx.PAIR_PROXY, state)
            self.assertEqual(identity_gate.call_count, 2)
            restore_pins.assert_called_once_with(original)
            self.assertFalse(marker.exists())
            self.assertEqual(
                [args[-1] for args in events if args[0] == "rm"],
                ["3" * 64, "2" * 64])

    def test_proxy_rollback_identity_rejects_foreign_secret_mount(self):
        original_labels = {
            "com.hermes.h454.role": "wss-proxy",
            "com.hermes.h454.request": "5" * 64,
        }
        directory = "/synthetic/tls"
        mount = [
            {"Type": "bind", "RW": False,
             "Source": str(tx.stage1.PIN_ROOT / "proxy.mjs"),
             "Destination": "/run/h454-wss/proxy.mjs"},
            {"Type": "bind", "RW": False,
             "Source": directory + "/relay.key",
             "Destination": "/run/h454-wss/relay.key"},
            {"Type": "bind", "RW": False,
             "Source": directory + "/relay.crt",
             "Destination": "/run/h454-wss/relay.crt"},
        ]
        item = {
            "Id": "3" * 64, "Image": tx.stage1.LEGACY_IMAGE,
            "Config": {"User": "65534:65534", "Labels": original_labels},
            "HostConfig": {
                "Privileged": False, "ReadonlyRootfs": True,
                "CapDrop": ["ALL"], "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "NetworkMode": "container:" + "2" * 64,
                "PidsLimit": 32, "Memory": 128 * 1024 * 1024,
            },
            "Mounts": mount,
        }
        old = {"Config": {"Labels": original_labels}}
        kwargs = dict(relay_id="2" * 64, old_proxy=old,
                      old_pins={"tls_directory": directory})
        tx.owned_candidate(item, item["Id"], item["Image"], "proxy", **kwargs)
        item["Mounts"] = [dict(m) for m in mount]
        item["Mounts"][1]["Source"] = "/etc/shadow"
        with self.assertRaisesRegex(
                tx.TransactionDenied, "FOREIGN_CANDIDATE_PROXY"):
            tx.owned_candidate(item, item["Id"], item["Image"], "proxy",
                               **kwargs)



if __name__ == "__main__":
    unittest.main()
