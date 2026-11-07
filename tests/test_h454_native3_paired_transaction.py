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


if __name__ == "__main__":
    unittest.main()
