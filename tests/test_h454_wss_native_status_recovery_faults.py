"""Synthetic WSS sidecar cutover fault phases; no host or Docker touched."""
from __future__ import annotations

from contextlib import ExitStack
import json
import unittest
from unittest import mock

from scripts import h454_wss_native_status_sidecar_cutover as tx


class RecoveryPhaseTests(unittest.TestCase):
    def run_phase(self, phase: str, *, known=True, foreign=False,
                  tamper_env=False, tamper_pins=False, tamper_restart=False):
        relay_id, old_id, new_id = "a" * 64, "b" * 64, "c" * 64
        old_source, candidate = b"synthetic-old-proxy", b"synthetic-status-proxy"
        old_pins = {
            "relay_id": relay_id, "sidecar_id": old_id,
            "relay_image": tx.stage1.FORK_IMAGE,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "proxy_sha256": tx.digest(old_source),
            "tls_directory": "/synthetic-tls", "gateway_ipv4": "172.21.0.1",
        }
        new_pins = dict(old_pins, sidecar_id=new_id,
                        proxy_sha256=tx.digest(candidate))
        old = {
            "Id": old_id, "Name": "/" + tx.stage1.PROXY,
            "Image": tx.stage1.LEGACY_IMAGE,
            "State": {"Running": phase == "old-running"},
            "Config": {"Labels": {"com.hermes.h454.request": "f" * 64}},
        }
        new = {
            "Id": new_id if not foreign else "d" * 64,
            "Name": "/" + tx.stage1.PROXY,
            "Image": tx.stage1.LEGACY_IMAGE,
            "State": {"Running": True},
            "Config": {
                "User": "65534:65534",
                "Env": ["NODE_VERSION=24", "H454_SSH_SOURCE_IPV4=172.21.0.1"],
                "Entrypoint": ["node"], "Cmd": ["/run/h454-wss/proxy.mjs"],
                "Labels": {"com.hermes.h454.role": "wss-proxy",
                           "com.hermes.h454.request": "f" * 64},
            },
            "HostConfig": {
                "NetworkMode": "container:" + relay_id,
                "ReadonlyRootfs": True, "Privileged": False,
                "CapDrop": ["ALL"], "PidsLimit": 32,
                "Memory": 128 * 1024 * 1024,
                "RestartPolicy": {"Name": "unless-stopped"},
                "PublishAllPorts": False,
                "SecurityOpt": ["no-new-privileges"],
                "PortBindings": {}, "CapAdd": [], "Devices": [],
            },
            "Mounts": [
                {"Destination": dest, "Source": path, "Type": "bind", "RW": False}
                for dest, path in (
                    ("/run/h454-wss/proxy.mjs", str(tx.ROOT / "proxy.mjs")),
                    ("/run/h454-wss/relay.key", "/synthetic-tls/relay.key"),
                    ("/run/h454-wss/relay.crt", "/synthetic-tls/relay.crt"),
                )
            ],
        }
        if tamper_env:
            new["Config"]["Env"] = ["H454_SSH_SOURCE_IPV4=8.8.8.8"]
        if tamper_restart:
            new["HostConfig"]["RestartPolicy"] = {"Name": "always"}
        if tamper_pins:
            new_pins["tls_directory"] = "/hostile-tls"
        if phase in ("old-stopped", "old-running"):
            active, checkpoint, source, pins = old, None, old_source, tx.canonical(old_pins)
        elif phase == "renamed":
            active, checkpoint, source, pins = None, old, candidate, tx.canonical(old_pins)
        else:
            active, checkpoint, source, pins = new, old, candidate, tx.canonical(new_pins)
        if checkpoint is not None:
            checkpoint["Name"] = "/" + tx.CHECKPOINT
            checkpoint["State"]["Running"] = False
        state = {"active": active, "checkpoint": checkpoint,
                 "source": source, "pins": pins, "commands": []}

        def current(name):
            if name == tx.stage1.PROXY:
                return state["active"]
            if name == tx.CHECKPOINT:
                return state["checkpoint"]
            if name == tx.CHECKPOINT_NEW:
                return None
            raise AssertionError("untrusted name")

        def read(path, *, mode, limit=100000):
            if path == tx.ROOT / "proxy.mjs":
                return state["source"]
            if path == tx.stage1.PINS:
                return state["pins"]
            raise AssertionError("untrusted source path")

        def docker(*args):
            state["commands"].append(args)
            action = args[0]
            if action == "stop":
                state["active"]["State"]["Running"] = False
            elif action == "rm":
                self.assertEqual(args[-1], new_id)
                state["active"] = None
            elif action == "rename":
                self.assertEqual(args[1], old_id)
                self.assertEqual(args[2], tx.stage1.PROXY)
                state["active"] = old
                state["active"]["Name"] = "/" + tx.stage1.PROXY
                state["checkpoint"] = None
            elif action == "start":
                self.assertEqual(args[1], old_id)
                state["active"]["State"]["Running"] = True
            return ""

        saved = {
            "old-pins.json": tx.canonical(old_pins),
            "old-proxy.mjs": old_source,
            "candidate-proxy.mjs": candidate,
            "relay-id.txt": (relay_id + "\n").encode("ascii"),
            "sidecar-id.txt": (old_id + "\n").encode("ascii"),
        }
        wss = mock.Mock()
        wss._pins.side_effect = lambda raw: json.loads(raw)
        preflight = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(tx, "OLD_BLOB", tx.git_blob(old_source)))
            stack.enter_context(mock.patch.object(tx, "SOURCE_BLOB", tx.git_blob(candidate)))
            stack.enter_context(mock.patch.object(tx, "current_name", side_effect=current))
            stack.enter_context(mock.patch.object(tx, "checked_file", side_effect=read))
            stack.enter_context(mock.patch.object(
                tx.stage1, "inspect", return_value={
                    "Id": relay_id, "Image": tx.stage1.FORK_IMAGE,
                    "State": {"Running": True}}))
            stack.enter_context(mock.patch.object(tx.stage1, "docker", side_effect=docker))
            stack.enter_context(mock.patch.object(
                tx, "replace_proxy", side_effect=lambda raw: state.update(source=raw)))
            stack.enter_context(mock.patch.object(
                tx.stage1, "replace_pins", side_effect=lambda raw: state.update(pins=raw)))
            stack.enter_context(mock.patch.object(tx, "verify_live"))
            if foreign or tamper_env or tamper_pins or tamper_restart:
                with self.assertRaises(tx.Refused):
                    tx.restore_known(wss, saved, new_id if known else "", preflight)
            else:
                tx.restore_known(wss, saved, new_id if known else "", preflight)
                self.assertEqual(state["source"], old_source)
                self.assertEqual(state["pins"], tx.canonical(old_pins))
                self.assertIs(state["active"], old)
                self.assertTrue(old["State"]["Running"])
                preflight.native_release.assert_called_once()
        return state

    def test_failure_before_rename_restores_stopped_old_proxy(self):
        result = self.run_phase("old-stopped")
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])
        self.assertIn(("start", "b" * 64), result["commands"])

    def test_after_old_rename_before_new_creation_restores_old_proxy(self):
        result = self.run_phase("renamed")
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])
        self.assertIn(("rename", "b" * 64, tx.stage1.PROXY), result["commands"])

    def test_after_new_pins_changed_removes_only_verified_new_proxy(self):
        result = self.run_phase("new-active")
        self.assertIn(("rm", "--force", "c" * 64), result["commands"])
        self.assertNotIn(("stop", "--time", "12", "a" * 64), result["commands"])

    def test_foreign_new_proxy_is_not_removed(self):
        result = self.run_phase("new-active", foreign=True)
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])

    def test_unknown_new_id_stops_before_destructive_action(self):
        result = self.run_phase("new-active", foreign=True, known=False)
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])

    def test_changed_tls_root_pins_refuse_before_removal(self):
        result = self.run_phase("new-active", tamper_pins=True)
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])

    def test_candidate_forbidden_egress_environment_refuses(self):
        result = self.run_phase("new-active", tamper_env=True)
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])

    def test_candidate_auto_restart_policy_refuses(self):
        result = self.run_phase("new-active", tamper_restart=True)
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])

    def test_running_old_proxy_is_kept_running(self):
        result = self.run_phase("old-running")
        self.assertNotIn("rm", [cmd[0] for cmd in result["commands"]])
        self.assertNotIn("start", [cmd[0] for cmd in result["commands"]])


class PendingTests(unittest.TestCase):
    def test_partial_marker_must_preserve_exact_owner_ids_and_hashes(self):
        old, candidate = b"old", b"candidate"
        saved = {
            "relay-id.txt": ("a" * 64 + "\n").encode(),
            "sidecar-id.txt": ("b" * 64 + "\n").encode(),
            "old-proxy.mjs": old,
            "candidate-proxy.mjs": candidate,
        }
        valid = {
            "schema": 1, "action": "cutover", "relay_id": "a" * 64,
            "old_sidecar_id": "b" * 64, "new_sidecar_id": "c" * 64,
            "old_proxy_sha256": tx.digest(old),
            "candidate_proxy_sha256": tx.digest(candidate),
        }
        with mock.patch.object(tx, "checked_file", return_value=tx.canonical(valid)):
            self.assertEqual(tx.pending_record(saved)["new_sidecar_id"], "c" * 64)
        valid["new_sidecar_id"] = "d" * 65
        with mock.patch.object(tx, "checked_file", return_value=tx.canonical(valid)):
            with self.assertRaisesRegex(tx.Refused, "PENDING_IDENTITY_DRIFT"):
                tx.pending_record(saved)


if __name__ == "__main__":
    unittest.main()
