"""#454: pure checks and fail-closed status-proxy original-host read-only gate."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import inspect
import unittest
from unittest import mock

from scripts import h454_wss_native_status_preflight as gate


REPO = Path(__file__).resolve().parents[1]


class ProxySourceContractTests(unittest.TestCase):
    def setUp(self):
        self.source = (REPO / "scripts/h454_wss_relay_proxy.mjs").read_bytes()

    def test_candidate_matches_exact_merged_git_blob(self):
        self.assertEqual(gate.git_blob(self.source), gate.NEW_PROXY_BLOB)
        self.assertIn(b"nativeStatusResponse", self.source)
        self.assertNotEqual(gate.NEW_PROXY_BLOB, gate.OLD_PROXY_BLOB)

    def test_modified_source_is_rejected_even_when_old_pin_claims_it(self):
        with self.assertRaisesRegex(gate.Hold, "ACTIVE_PROXY_SOURCE_CHANGED"):
            gate.check_proxy_source(self.source, self.source, gate.sha256(self.source))

    def test_candidate_must_match_exact_git_blob_not_unverified_bytes(self):
        old = b"synthetic-legacy-proxy"
        with mock.patch.object(gate, "OLD_PROXY_BLOB", gate.git_blob(old)):
            with self.assertRaisesRegex(gate.Hold, "CANDIDATE_PROXY_SOURCE_CHANGED"):
                gate.check_proxy_source(old, self.source + b"\n", gate.sha256(old))

    def test_old_proxy_sha256_is_independent_of_old_git_blob(self):
        old = b"synthetic-legacy-proxy"
        with mock.patch.object(gate, "OLD_PROXY_BLOB", gate.git_blob(old)):
            with self.assertRaisesRegex(gate.Hold, "ACTIVE_PROXY_SOURCE_CHANGED"):
                gate.check_proxy_source(old, self.source, "0" * 64)

    def test_source_size_bounds(self):
        with self.assertRaisesRegex(gate.Hold, "OLD_PROXY_SIZE_CHANGED"):
            gate.check_proxy_source(b"", self.source, gate.sha256(b""))
        with self.assertRaisesRegex(gate.Hold, "CANDIDATE_PROXY_SIZE_CHANGED"):
            gate.check_proxy_source(b"old", b"x" * 100001, gate.sha256(b"old"))

    def test_sha256_distinct_from_git_blob_sha1(self):
        self.assertEqual(gate.sha256(b"abc"),
                         hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(len(gate.git_blob(b"abc")), 40)


class AcceptedLiveRelayTests(unittest.TestCase):
    """The H454 native3 candidate is live; original Stage1 image is rollback."""

    def setUp(self):
        self.pins = {
            "relay_name": gate.stage1.legacy.NAME,
            "sidecar_name": gate.stage1.PROXY,
            "relay_image": gate.LIVE_RELAY_IMAGE,
            "sidecar_image": gate.stage1.LEGACY_IMAGE,
            "relay_id": gate.LIVE_RELAY_ID,
            "sidecar_id": gate.LIVE_SIDECAR_ID,
        }

    def test_owner_attested_original_pair_passes(self):
        self.assertEqual(
            gate.LIVE_RELAY_IMAGE,
            "sha256:3488e1ff44bb0843ecbc62a1951277ccbf118d1f3ba899b7636a66aa84d55e06",
        )
        self.assertNotEqual(gate.LIVE_RELAY_IMAGE, gate.stage1.FORK_IMAGE)
        gate.check_pinned_live_pair(self.pins)

    def test_old_rollback_relay_is_not_current(self):
        altered = dict(self.pins, relay_image=gate.stage1.FORK_IMAGE)
        with self.assertRaisesRegex(gate.Hold, "EXISTING_BRC_WSS_PAIR_CHANGED"):
            gate.check_pinned_live_pair(altered)

    def test_self_consistent_foreign_relay_pair_is_not_trusted(self):
        for field, forged in (
            ("relay_image", "sha256:" + "f" * 64),
            ("sidecar_image", "sha256:" + "e" * 64),
            ("relay_id", "d" * 64),
            ("sidecar_id", "c" * 64),
            ("relay_name", "foreign-relay"),
            ("sidecar_name", "foreign-sidecar"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(gate.Hold, "EXISTING_BRC_WSS_PAIR_CHANGED"):
                    gate.check_pinned_live_pair(dict(self.pins, **{field: forged}))


class HostAdmissionTests(unittest.TestCase):
    def test_disabled_and_static_native_units(self):
        gate.unit_state("ActiveState=inactive\n"
                        "UnitFileState=disabled\nNeedDaemonReload=no\n", "disabled")
        gate.unit_state("UnitFileState=static\nNeedDaemonReload=no\n"
                        "ActiveState=inactive\n", "static")

    def test_active_or_changed_unit_refused(self):
        for field in ("ActiveState=active", "UnitFileState=enabled",
                      "NeedDaemonReload=yes"):
            raw = ("ActiveState=inactive\nUnitFileState=disabled\n"
                   "NeedDaemonReload=no\n").replace(field.split("=")[0] + "="
                                                      + {"ActiveState": "inactive",
                                                         "UnitFileState": "disabled",
                                                         "NeedDaemonReload": "no"}[field.split("=")[0]],
                                                      field)
            with self.subTest(field=field), self.assertRaises(gate.Hold):
                gate.unit_state(raw, "disabled")

    def test_free_checkpoint_requires_successful_exact_docker_discovery(self):
        with TemporaryDirectory() as scratch:
            with mock.patch.object(gate, "ROOT", Path(scratch)), mock.patch.object(
                gate.stage1, "docker", return_value=""
            ) as docker:
                gate.no_conflicting_transaction()
                docker.assert_called_once_with(
                    "container", "ls", "--all", "--no-trunc",
                    "--filter", "name=^/" + gate.SIDECAR_CHECKPOINT + "$",
                    "--format", "{{.Names}}",
                )
                docker.return_value = gate.SIDECAR_CHECKPOINT
                with self.assertRaisesRegex(gate.Hold, "SIDECAR_CHECKPOINT_OCCUPIED"):
                    gate.no_conflicting_transaction()

    def test_pending_symlink_blocks_reentry_even_when_broken(self):
        with TemporaryDirectory() as scratch:
            with mock.patch.object(gate, "ROOT", Path(scratch)), mock.patch.object(
                gate.stage1, "docker", return_value=""
            ):
                (Path(scratch) / "native3-pair.pending").symlink_to(
                    Path(scratch) / "missing-target")
                with self.assertRaisesRegex(gate.Hold, "EXISTING_WSS_TRANSACTION"):
                    gate.no_conflicting_transaction()

    def test_failed_docker_discovery_does_not_mean_free_slot(self):
        with TemporaryDirectory() as scratch:
            with mock.patch.object(gate, "ROOT", Path(scratch)), mock.patch.object(
                gate.stage1, "docker", side_effect=OSError("docker unavailable")
            ):
                with self.assertRaises(OSError):
                    gate.no_conflicting_transaction()

    def test_only_read_only_cli_mode(self):
        program = inspect.getsource(gate)
        self.assertIn('choices=("plan",)', program)
        for forbidden in ('"cutover"', '"install-off"', '"--execute"',
                          'docker("stop"', 'docker("start"',
                          'systemctl", "start"', 'os.replace(',
                          'os.unlink('):
            self.assertNotIn(forbidden, program)


if __name__ == "__main__":
    unittest.main()
