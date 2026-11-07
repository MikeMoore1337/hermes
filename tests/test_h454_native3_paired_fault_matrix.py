"""Hermes #454: isolated paired transaction fault-injection and recovery tests.

All Docker operations, owner approvals, TLS/pins and live device checks are
intercepted. No containers, credentials, services or host paths are touched.
These tests do not replace a real owner-approved maintenance cutover.
"""
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import h454_native3_paired_transaction as tx


RELEASE = "a" * 40
SOURCE = "b" * 40
CONFIG = "sha256:" + "c" * 64
ARCHIVE = "d" * 64
RUNTIME = "sha256:" + "e" * 64
ORIGINAL_RELAY = "f" * 64
ORIGINAL_PROXY = "1" * 64
NEW_RELAY = "2" * 64
NEW_PROXY = "3" * 64
KWARGS = dict(release_sha=RELEASE, bundle=Path("/synthetic/no-real-bundle"),
              image=CONFIG, archive_sha=ARCHIVE, candidate_sha=SOURCE)


class SimulatedCrash(BaseException):
    """Simulate process death, which is intentionally not caught by except Exception."""


class FakePairedDocker:
    """Stateful synthetic Docker name/ID model. It never calls Docker."""

    def __init__(self, root: Path, fault: str = "", crash: bool = False):
        self.root = root
        self.fault = fault
        self.crash = crash
        self.tripped = False
        self.events = []
        self.snapshot_calls = 0
        self.real_updated_pins = tx.updated_pins
        self.original_relay = {
            "Id": ORIGINAL_RELAY, "Name": "/" + tx.legacy.NAME,
            "Image": tx.stage1.FORK_IMAGE, "State": {"Running": True},
            "Config": {"User": "979:975",
                       "Labels": {"com.hermes.scope": "h15-brc-owner-relay"}},
        }
        self.original_proxy = {
            "Id": ORIGINAL_PROXY, "Name": "/" + tx.stage1.PROXY,
            "Image": tx.stage1.LEGACY_IMAGE, "State": {"Running": True},
            "Config": {"User": "65534:65534", "Labels": {
                "com.hermes.h454.role": "wss-proxy",
                "com.hermes.h454.request": "5" * 64}},
            "HostConfig": {"NetworkMode": "container:" + ORIGINAL_RELAY},
        }
        self.state = {tx.legacy.NAME: self.original_relay,
                      tx.stage1.PROXY: self.original_proxy}
        self.source_pins = {
            "relay_name": tx.legacy.NAME,
            "sidecar_name": tx.stage1.PROXY,
            "relay_image": tx.stage1.FORK_IMAGE,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "relay_id": ORIGINAL_RELAY,
            "sidecar_id": ORIGINAL_PROXY,
            "tls_directory": str(root / "synthetic-tls"),
        }
        self.original_pins = self.encode(self.source_pins)
        self.active_pins = self.original_pins
        self.wss = SimpleNamespace(
            _pins=lambda data: json.loads(data),
            _snapshot=self.snapshot_pair,
            _namespace=self.namespace,
            profile_sha256=lambda obj: "4" * 64,
            reconcile=self.reconcile)

    @staticmethod
    def encode(record: dict) -> bytes:
        return (json.dumps(record, sort_keys=True, separators=(",", ":"))
                + "\n").encode("ascii")

    def trip(self, name: str):
        if name == self.fault and not self.tripped:
            self.tripped = True
            if self.crash:
                raise SimulatedCrash(name)
            raise RuntimeError("synthetic fault " + name)

    def find_by_id(self, identity: str):
        return next((obj for obj in self.state.values()
                     if obj["Id"] == identity), None)

    def name_of_id(self, identity: str):
        return next((name for name, obj in self.state.items()
                     if obj["Id"] == identity), None)

    def strict_container(self, name: str):
        return self.state.get(name)

    def inspect(self, kind: str, identity: str):
        obj = self.find_by_id(identity) or self.state.get(identity)
        if obj is None:
            raise AssertionError("unknown synthetic container")
        return obj

    def docker(self, *args):
        self.events.append(args)
        action = args[0]
        if action == "stop":
            ident = args[-1]
            self.trip("stop_proxy" if ident == ORIGINAL_PROXY else "stop_relay")
            self.find_by_id(ident)["State"]["Running"] = False
        elif action == "update":
            ident = args[-1]
            policy = args[2]
            if policy == "no":
                self.trip("disable_proxy_restart" if ident == ORIGINAL_PROXY
                          else "disable_relay_restart")
            elif ident in (NEW_RELAY, NEW_PROXY):
                self.trip("enable_relay_restart" if ident == NEW_RELAY
                          else "enable_proxy_restart")
            self.find_by_id(ident).setdefault("HostConfig", {})[
                "RestartPolicy"] = {"Name": policy}
        elif action == "rename":
            ident, new_name = args[1], args[2]
            if ident in (ORIGINAL_RELAY, ORIGINAL_PROXY):
                self.trip("checkpoint_proxy" if ident == ORIGINAL_PROXY
                          else "checkpoint_relay")
            old_name = self.name_of_id(ident)
            if old_name is None or new_name in self.state:
                raise AssertionError("synthetic rename identity/name conflict")
            obj = self.state.pop(old_name)
            obj["Name"] = "/" + new_name
            self.state[new_name] = obj
        elif action == "run":
            self.trip("run_relay")
            self.state[tx.legacy.NAME] = {
                "Id": NEW_RELAY, "Name": "/" + tx.legacy.NAME,
                "Image": RUNTIME, "State": {"Running": True},
                "Config": {"User": "979:975", "Labels": {
                    "com.hermes.scope": "h15-brc-owner-relay"}},
                "HostConfig": {
                    "Privileged": False, "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"], "CapAdd": None, "Devices": None,
                    "Binds": None, "PortBindings": None,
                    "SecurityOpt": ["no-new-privileges"],
                    "NetworkMode": "hermes-brc-internal",
                    "PidsLimit": 80, "Memory": 512 * 1024 * 1024},
                "Mounts": [
                    {"Type": "bind", "RW": True,
                     "Source": "/var/lib/hermes-brc-relay", "Destination": "/state"},
                    {"Type": "bind", "RW": False,
                     "Source": str(tx.candidate.PINNED_REGISTRY_SOURCE),
                     "Destination": tx.candidate.REGISTRY_TARGET}],
            }
            return NEW_RELAY
        elif action == "start":
            ident = args[1]
            if ident == NEW_PROXY:
                self.trip("start_proxy")
            self.find_by_id(ident)["State"]["Running"] = True
        elif action == "rm":
            ident = args[-1]
            name = self.name_of_id(ident)
            if name is None:
                raise AssertionError("attempted deletion of an unidentified container")
            del self.state[name]
        else:
            raise AssertionError("unexpected synthetic Docker action: " + repr(args))
        return ""

    def create_sidecar(self, pins, relay_id, original):
        self.trip("create_sidecar")
        tls = self.source_pins["tls_directory"]
        self.state[tx.stage1.PROXY] = {
            "Id": NEW_PROXY, "Name": "/" + tx.stage1.PROXY,
            "Image": tx.stage1.LEGACY_IMAGE, "State": {"Running": False},
            "Config": {"User": "65534:65534", "Labels": {
                "com.hermes.h454.role": "wss-proxy",
                "com.hermes.h454.request": "5" * 64}},
            "HostConfig": {
                "Privileged": False, "ReadonlyRootfs": True,
                "CapDrop": ["ALL"], "CapAdd": None,
                "SecurityOpt": ["no-new-privileges"],
                "NetworkMode": "container:" + relay_id,
                "PidsLimit": 32, "Memory": 128 * 1024 * 1024},
            "Mounts": [
                {"Type": "bind", "RW": False,
                 "Source": str(tx.stage1.PIN_ROOT / "proxy.mjs"),
                 "Destination": "/run/h454-wss/proxy.mjs"},
                {"Type": "bind", "RW": False,
                 "Source": tls + "/relay.key",
                 "Destination": "/run/h454-wss/relay.key"},
                {"Type": "bind", "RW": False,
                 "Source": tls + "/relay.crt",
                 "Destination": "/run/h454-wss/relay.crt"},
            ],
        }
        return NEW_PROXY

    def update_pins(self, wss, old, relay_id, proxy_id, image):
        self.trip("compose_pins")
        return self.real_updated_pins(wss, old, relay_id, proxy_id, image)

    def replace_pins(self, raw):
        self.trip("replace_pins")
        self.active_pins = raw

    def snapshot_pair(self, *args):
        self.trip("wss_snapshot")
        return self.state[tx.legacy.NAME], self.state[tx.stage1.PROXY]

    def namespace(self, relay, proxy):
        self.trip("wss_namespace")
        if proxy["HostConfig"]["NetworkMode"] != "container:" + relay["Id"]:
            raise AssertionError("synthetic WSS no longer shares relay namespace")

    def reconcile(self, *args):
        self.trip("wss_reconcile")
        return "READY"

    def devices(self):
        return 2

    def healthy(self, *args, **kwargs):
        self.trip("healthy")
        return True

    def snapshot(self):
        self.snapshot_calls += 1
        self.trip("snapshot_before" if self.snapshot_calls == 1
                  else "snapshot_after")
        return str(self.root / ("sqlite-snapshot-" + str(self.snapshot_calls)))

    def compare_auth(self, *args):
        self.trip("compare_auth")

    def candidate_inspect(self, *args):
        self.trip("candidate_inspect")
        return self.state[tx.legacy.NAME]

    def candidate_gate(self, *args):
        self.trip("candidate_gate")
        return RUNTIME

    def patched(self):
        stack = ExitStack()
        def put(owner, name, value):
            stack.enter_context(patch.object(owner, name, value))
        put(tx.os, "geteuid", lambda: 0)
        put(tx.admission, "verify_installed_source", lambda *args: None)
        put(tx.admission, "verify_pair",
            lambda *args: (self.original_relay, self.original_proxy))
        put(tx.admission, "check_free_checkpoints", lambda: None)
        put(tx, "approval_record", lambda **kwargs: None)
        put(tx, "verified_candidate_for_recovery", lambda *args, **kwargs: RUNTIME)
        put(tx.legacy, "lock", lambda: nullcontext())
        put(tx.legacy, "check_files", lambda: None)
        put(tx.legacy, "devices", self.devices)
        put(tx.legacy, "healthy", self.healthy)
        put(tx.legacy, "snapshot", self.snapshot)
        put(tx.stage1, "protected", lambda *args, **kwargs: None)
        put(tx.stage1, "load_existing_wss", lambda: self.wss)
        put(tx.stage1, "locked_pins", lambda: nullcontext(self.active_pins))
        put(tx.stage1, "PIN_ROOT", self.root)
        put(tx.stage1, "PINS",
            SimpleNamespace(read_bytes=lambda: self.active_pins))
        put(tx.stage1, "sync_pin_directory", lambda: None)
        put(tx.stage1, "docker", self.docker)
        put(tx.stage1, "inspect", self.inspect)
        put(tx.stage1, "create_sidecar", self.create_sidecar)
        put(tx.stage1, "replace_pins", self.replace_pins)
        put(tx.candidate, "admit", lambda *args: {
            "status": "PREFLIGHT_PASS", "bundle_verified": True,
            "changes_performed": False, "deployment_approved": False,
            "current_image": tx.stage1.FORK_IMAGE,
            "candidate_image": RUNTIME})
        put(tx.candidate, "inspect", self.candidate_inspect)
        put(tx.candidate, "current_gate", self.candidate_gate)
        put(tx.candidate, "registry_mount_source",
            lambda *args: str(tx.candidate.PINNED_REGISTRY_SOURCE))
        put(tx.stage1, "compare_auth", self.compare_auth)
        put(tx, "strict_container", self.strict_container)
        put(tx, "PENDING", self.root / "native3-pair.pending")
        put(tx, "ORIGINAL_PINS", self.root / "native3-original-pins.json")
        put(tx, "updated_pins", self.update_pins)
        return stack

    def assert_restored(self, case):
        case.assertEqual(self.state[tx.legacy.NAME]["Id"], ORIGINAL_RELAY)
        case.assertEqual(self.state[tx.stage1.PROXY]["Id"], ORIGINAL_PROXY)
        case.assertTrue(self.state[tx.legacy.NAME]["State"]["Running"])
        case.assertTrue(self.state[tx.stage1.PROXY]["State"]["Running"])
        case.assertEqual(self.active_pins, self.original_pins)
        case.assertNotIn(tx.PAIR_RELAY, self.state)
        case.assertNotIn(tx.PAIR_PROXY, self.state)
        case.assertFalse(tx.PENDING.exists())


class PairedFaultMatrixTests(unittest.TestCase):
    def test_every_docker_and_security_step_recovers_original_pair(self):
        points = (
            "stop_proxy", "disable_proxy_restart", "checkpoint_proxy",
            "stop_relay", "disable_relay_restart", "checkpoint_relay",
            "run_relay", "create_sidecar", "compose_pins", "replace_pins",
            "start_proxy", "wss_snapshot", "wss_namespace", "healthy",
            "snapshot_after", "compare_auth", "enable_relay_restart",
            "enable_proxy_restart", "candidate_inspect", "candidate_gate",
            "wss_reconcile",
        )
        for point in points:
            with self.subTest(fault=point), tempfile.TemporaryDirectory(
                    prefix="h454-paired-fault-") as tmp:
                simulation = FakePairedDocker(Path(tmp), fault=point)
                with simulation.patched():
                    expected = ("WSS_FAILED_ORIGINAL_PAIR_RESTORED"
                                if point == "wss_reconcile"
                                else "PAIR_CUTOVER_FAILED_ORIGINAL_RESTORED")
                    with self.assertRaisesRegex(tx.TransactionDenied, expected):
                        tx.cutover(**KWARGS)
                    self.assertTrue(simulation.tripped, point)
                    simulation.assert_restored(self)
                    self.assertFalse(any(obj["Id"] in (NEW_RELAY, NEW_PROXY)
                                         for obj in simulation.state.values()))

    def test_prior_snapshot_failure_causes_no_docker_actions(self):
        with tempfile.TemporaryDirectory(prefix="h454-paired-fault-") as tmp:
            simulation = FakePairedDocker(Path(tmp), fault="snapshot_before")
            with simulation.patched():
                with self.assertRaisesRegex(RuntimeError, "snapshot_before"):
                    tx.cutover(**KWARGS)
                self.assertEqual(simulation.events, [])
                simulation.assert_restored(self)

    def test_crash_recovery_restores_both_checkpoints_from_marker(self):
        for point in ("create_sidecar", "compose_pins"):
            with self.subTest(crash=point), tempfile.TemporaryDirectory(
                    prefix="h454-crash-recover-") as tmp:
                simulation = FakePairedDocker(Path(tmp), fault=point, crash=True)
                with simulation.patched():
                    with self.assertRaises(SimulatedCrash):
                        tx.cutover(**KWARGS)
                    self.assertTrue(tx.PENDING.exists())
                    self.assertTrue(tx.ORIGINAL_PINS.exists())
                    self.assertIn(NEW_RELAY, [obj["Id"] for obj in
                                              simulation.state.values()])
                    receipt = tx.pending_read()
                    self.assertEqual(receipt["new_relay_id"], NEW_RELAY)
                    self.assertEqual(receipt["new_proxy_id"],
                                     NEW_PROXY if point == "compose_pins" else "")
                    result = tx.restore_authorized(**KWARGS, after_success=False)
                    self.assertEqual(
                        result["status"],
                        "ORIGINAL_PAIR_RESTORED_PENDING_CLIENT_VERIFICATION")
                    self.assertFalse(result["auth_database_reverted"])
                    simulation.assert_restored(self)

    def test_successful_pair_can_be_rolled_back_using_retained_ids(self):
        with tempfile.TemporaryDirectory(prefix="h454-postsuccess-") as tmp:
            simulation = FakePairedDocker(Path(tmp))
            with simulation.patched():
                result = tx.cutover(**KWARGS)
                self.assertEqual(
                    result["status"], "SWITCHED_PENDING_CHATGPT_CODEX_LIVE_ACCEPTANCE")
                self.assertEqual(self.state_id(simulation, tx.legacy.NAME),
                                 NEW_RELAY)
                self.assertEqual(self.state_id(simulation, tx.stage1.PROXY),
                                 NEW_PROXY)
                self.assertTrue(tx.ORIGINAL_PINS.exists())
                self.assertFalse(tx.PENDING.exists())
                restored = tx.restore_authorized(**KWARGS, after_success=True)
                self.assertEqual(
                    restored["status"],
                    "ORIGINAL_PAIR_RESTORED_PENDING_CLIENT_VERIFICATION")
                simulation.assert_restored(self)

    @staticmethod
    def state_id(simulation, name):
        return simulation.state[name]["Id"]


if __name__ == "__main__":
    unittest.main()
