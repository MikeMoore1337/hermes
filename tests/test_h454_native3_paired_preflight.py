"""H454: strictly read-only joint relay + WSS pair preflight contract."""
import io
import json
import os
from contextlib import nullcontext, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import h454_native3_paired_preflight as pair

RELEASE = "a" * 40
SOURCE = "b" * 40
ARCHIVE = "c" * 64
IMAGE = "sha256:" + "d" * 64
RUNTIME = "sha256:" + "e" * 64
RELAY_ID = "f" * 64
PROXY_ID = "1" * 64


def relay():
    return {"Name": "/hermes-brc-relay", "Id": RELAY_ID,
            "Image": pair.stage1.FORK_IMAGE, "State": {"Running": True},
            "Config": {"User": "979:975"}}


def proxy():
    return {"Name": "/hermes-h454-wss-proxy", "Id": PROXY_ID,
            "Image": pair.stage1.LEGACY_IMAGE,
            "HostConfig": {"NetworkMode": "container:" + RELAY_ID},
            "State": {"Running": True}}


def pins():
    return {
        "relay_name": pair.legacy.NAME, "sidecar_name": pair.stage1.PROXY,
        "relay_image": pair.stage1.FORK_IMAGE,
        "sidecar_image": pair.stage1.LEGACY_IMAGE,
        "relay_id": RELAY_ID, "sidecar_id": PROXY_ID,
        "tls_directory": "/synthetic/non-secret",
    }


def fake_wss(pins_document=None, relay_record=None, proxy_record=None):
    p = pins() if pins_document is None else pins_document
    r = relay() if relay_record is None else relay_record
    s = proxy() if proxy_record is None else proxy_record
    return SimpleNamespace(
        _pins=lambda raw: p,
        _snapshot=lambda *args: (r, s),
        _namespace=lambda *args: None,
        _directory=lambda *args: os.open(os.devnull, os.O_RDONLY),
        _read_file=lambda *args: b"synthetic-ca",
        _tls=lambda *args: None,
    )


def approved():
    return {
        "status": "PREFLIGHT_PASS",
        "bundle_verified": True,
        "changes_performed": False,
        "deployment_approved": False,
        "current_image": pair.stage1.FORK_IMAGE,
        "candidate_image": RUNTIME,
    }


class PairedPreflightTests(TestCase):
    def check_plan(self, wss=None, admitted=None, checkpoint=None):
        with patch.object(pair.os, "geteuid", return_value=0), \
             patch.object(pair, "verify_installed_source"), \
             patch.object(pair.legacy, "lock", return_value=nullcontext()), \
             patch.object(pair.stage1, "protected"), \
             patch.object(pair.legacy, "check_files"), \
             patch.object(pair.candidate, "admit",
                          return_value=approved() if admitted is None else admitted) as gate, \
             patch.object(pair.stage1, "load_existing_wss",
                          return_value=fake_wss() if wss is None else wss), \
             patch.object(pair.stage1, "locked_pins",
                          return_value=nullcontext(b"synthetic-pins")), \
             patch.object(pair.stage1, "PENDING", SimpleNamespace(
                 exists=lambda: False, is_symlink=lambda: False)), \
             patch.object(pair, "PAIR_PENDING", SimpleNamespace(
                 exists=lambda: False, is_symlink=lambda: False)), \
             patch.object(pair.candidate, "registry_mount_source",
                          return_value=str(pair.candidate.PINNED_REGISTRY_SOURCE)), \
             patch.object(pair.legacy, "devices", return_value=2), \
             patch.object(pair.legacy, "docker") as mutating_legacy_docker, \
             patch.object(pair.stage1, "docker",
                          return_value=checkpoint or "") as docker_listing:
            try:
                result = pair.plan(release_sha=RELEASE, bundle=Path("/verified"),
                                   image=IMAGE, archive_sha=ARCHIVE,
                                   candidate_sha=SOURCE)
                # Require both successful Docker queries only if plan passes.
                # Early failure must make no checkpoint-availability claim.
                self.assertEqual(docker_listing.call_count, 2)
                self.assertEqual(
                    [c.args[4] for c in docker_listing.call_args_list],
                    ["name=^/" + pair.RELAY_CHECKPOINT + "$",
                     "name=^/" + pair.PROXY_CHECKPOINT + "$"],
                )
                return result
            finally:
                mutating_legacy_docker.assert_not_called()
                gate.assert_called_once_with(Path("/verified"), IMAGE, ARCHIVE, SOURCE)


    def test_safe_pair_plan_accepts_pinned_live_topology_without_mutation(self):
        result = self.check_plan()
        self.assertEqual(result["status"], "PAIR_PREFLIGHT_PASS_NO_MUTATIONS")
        self.assertEqual(result["candidate_runtime_image_id"], RUNTIME)
        self.assertEqual(result["previous_relay_image"], pair.stage1.FORK_IMAGE)
        self.assertEqual(result["previous_proxy_image"], pair.stage1.LEGACY_IMAGE)
        self.assertEqual(result["baseline_devices"], 2)
        self.assertTrue(result["wss_pinned_pair_valid"])
        self.assertTrue(result["rollback_slots_available"])
        self.assertFalse(result["changes_performed"])
        self.assertFalse(result["deployment_approved"])

    def test_failed_cutover_retained_pins_block_fresh_plan_before_oci(self):
        # Real owner incident retains this file after a successful rollback.
        # A misleading PASS would invite a second unsafe cutover attempt.
        with TemporaryDirectory(prefix="h454-postrollback-") as scratch:
            retained = Path(scratch) / "native3-original-pins.json"
            retained.write_bytes(b"synthetic-owner-pin-evidence\n")
            with patch.object(pair, "ORIGINAL_PINS", retained), \
                 patch.object(pair.os, "geteuid", return_value=0), \
                 patch.object(pair, "verify_installed_source"), \
                 patch.object(pair.legacy, "lock", return_value=nullcontext()), \
                 patch.object(pair.stage1, "protected"), \
                 patch.object(pair.legacy, "check_files"), \
                 patch.object(pair.candidate, "admit") as candidate_image, \
                 patch.object(pair.stage1, "docker") as docker:
                with self.assertRaisesRegex(
                        pair.PairDenied, "^PREVIOUS_TRANSACTION_NOT_CLEARED$"):
                    pair.plan(release_sha=RELEASE, bundle=Path("/verified"),
                              image=IMAGE, archive_sha=ARCHIVE,
                              candidate_sha=SOURCE)
                candidate_image.assert_not_called()
                docker.assert_not_called()
            self.assertEqual(retained.read_bytes(),
                             b"synthetic-owner-pin-evidence\n")

    def test_dangling_original_pin_symlink_is_an_explicit_hold(self):
        with TemporaryDirectory(prefix="h454-symlink-") as scratch:
            retained = Path(scratch) / "native3-original-pins.json"
            retained.symlink_to(Path(scratch) / "missing-target")
            with patch.object(pair, "ORIGINAL_PINS", retained):
                with self.assertRaisesRegex(
                        pair.PairDenied, "^PREVIOUS_TRANSACTION_NOT_CLEARED$"):
                    pair.require_no_previous_transaction()
            self.assertTrue(retained.is_symlink())

    def test_clean_preflight_has_no_retained_snapshot_and_matches_transaction(self):
        from scripts import h454_native3_paired_transaction as tx
        self.assertEqual(pair.ORIGINAL_PINS, tx.ORIGINAL_PINS)
        with TemporaryDirectory(prefix="h454-clean-") as scratch:
            missing = Path(scratch) / "native3-original-pins.json"
            with patch.object(pair, "ORIGINAL_PINS", missing):
                pair.require_no_previous_transaction()
                self.assertFalse(missing.exists())

    def test_untrusted_owner_pair_images_are_denied(self):
        for key,value in (
            ("relay_image", "sha256:" + "2" * 64),
            ("sidecar_image", "sha256:" + "3" * 64),
            ("relay_name", "foreign"),
            ("sidecar_name", "other-sidecar"),
        ):
            p = pins()
            p[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    pair.PairDenied, "PAIR_IDENTITY_CHANGED"):
                self.check_plan(wss=fake_wss(pins_document=p))

    def test_live_sidecar_must_share_original_relay_namespace(self):
        p = proxy()
        p["HostConfig"]["NetworkMode"] = "container:" + ("0" * 64)
        with self.assertRaisesRegex(pair.PairDenied, "PAIR_NAMESPACE_CHANGED"):
            self.check_plan(wss=fake_wss(proxy_record=p))

    def test_live_relay_and_sidecar_must_both_be_running(self):
        for member in ("relay", "proxy"):
            r, p = relay(), proxy()
            (r if member == "relay" else p)["State"]["Running"] = False
            with self.subTest(member=member), self.assertRaisesRegex(
                    pair.PairDenied, "PAIR_NOT_RUNNING"):
                self.check_plan(wss=fake_wss(relay_record=r, proxy_record=p))

    def test_foreign_image_or_pinned_id_never_admitted(self):
        p = proxy()
        p["Image"] = "sha256:" + "a" * 64
        with self.assertRaisesRegex(
                pair.PairDenied, "PAIR_IMAGE_OR_CONTAINER_CHANGED"):
            self.check_plan(wss=fake_wss(proxy_record=p))
        r = relay()
        r["Id"] = "b" * 64
        with self.assertRaisesRegex(
                pair.PairDenied, "PAIR_IMAGE_OR_CONTAINER_CHANGED"):
            self.check_plan(wss=fake_wss(relay_record=r))

    def test_missing_or_invalid_candidate_denied_before_pair(self):
        invalid = approved()
        invalid["deployment_approved"] = True
        with self.assertRaisesRegex(
                pair.PairDenied, "CANDIDATE_OR_PREVIOUS_IMAGE_INVALID"):
            self.check_plan(admitted=invalid)

    def test_existing_checkpoint_never_admitted(self):
        with self.assertRaisesRegex(pair.PairDenied,
                                    "ROLLBACK_CHECKPOINT_ALREADY_EXISTS"):
            self.check_plan(checkpoint="occupied-checkpoint")

    def test_docker_permission_error_does_not_prove_free_checkpoint(self):
        # Use the actual Stage 1 Docker parser, including nonzero return-code
        # handling; mocking optional inspect alone would mask this defect.
        failed = SimpleNamespace(returncode=1, stdout="", stderr="synthetic-private-error")
        with patch.object(pair.stage1.subprocess, "run", return_value=failed) as cmd:
            with self.assertRaisesRegex(pair.stage1.Hold, "DOCKER_OPERATION_FAILED"):
                pair.check_free_checkpoints()
        cmd.assert_called_once()

    def test_both_successful_empty_listings_prove_free_checkpoint_slots(self):
        empty = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(pair.stage1.subprocess, "run", return_value=empty) as cmd:
            pair.check_free_checkpoints()
        self.assertEqual(cmd.call_count, 2)
        self.assertTrue(all(call.args[0][0] == "/usr/bin/docker"
                            for call in cmd.call_args_list))

    def test_owner_root_and_installed_exact_release_are_required(self):
        with patch.object(pair.os, "geteuid", return_value=1000), \
             patch.object(pair, "verify_installed_source") as source:
            with self.assertRaisesRegex(pair.PairDenied, "ROOT_REQUIRED"):
                pair.plan(release_sha=RELEASE, bundle=Path("/verified"),
                          image=IMAGE, archive_sha=ARCHIVE,
                          candidate_sha=SOURCE)
            source.assert_not_called()
        with patch.object(pair.stage1, "LIVE_SHA",
                          SimpleNamespace(read_text=lambda **kw: RELEASE)), \
             patch.object(pair.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                    pair.PairDenied, "OPERATOR_SOURCE_NOT_INSTALLED"):
                pair.verify_installed_source(RELEASE)

    def test_wss_pending_recovery_refuses_to_continue(self):
        with patch.object(pair.stage1, "protected"), \
             patch.object(pair.stage1, "PENDING", SimpleNamespace(
                 exists=lambda: True, is_symlink=lambda: False)):
            with self.assertRaisesRegex(
                    pair.PairDenied, "PENDING_PAIR_RECOVERY_REQUIRED"):
                pair.verify_pair(fake_wss())

    def test_cli_exposes_only_read_only_plan(self):
        import inspect
        src = inspect.getsource(pair.main)
        self.assertIn('choices=("plan",)', src)
        self.assertNotIn('choices=("plan", "cutover")', src)

    def test_wss_error_payload_never_reaches_operator_json(self):
        secret = "SYNTHETIC_TOKEN_SHOULD_NEVER_BE_PRINTED"
        with patch.object(pair, "plan", side_effect=RuntimeError(secret)):
            output = io.StringIO()
            with redirect_stdout(output):
                code = pair.main([
                    "plan", "--release-sha", RELEASE,
                    "--bundle-dir", "/verified", "--image", IMAGE,
                    "--archive-sha", ARCHIVE, "--candidate-sha", SOURCE,
                ])
        self.assertEqual(code, 2)
        data = json.loads(output.getvalue())
        self.assertEqual(data["status"], "REFUSED")
        self.assertEqual(data["reason"], "ATTESTATION_OR_RUNTIME_UNAVAILABLE")
        self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    import unittest
    unittest.main()
