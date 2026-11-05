"""Fail-closed Stage 1 relay/WSS cutover operator contracts (#454)."""
import json
import tempfile
import types
import unittest
from pathlib import Path
from contextlib import nullcontext
from unittest.mock import patch

from scripts import h454_stage1_pair_cutover as m


def old_relay():
    return {"Id": "a" * 64, "Image": m.LEGACY_IMAGE, "Config": {"User": "979:975"}}


def old_proxy():
    return {
        "Id": "b" * 64, "Image": m.LEGACY_IMAGE,
        "Config": {"Labels": {"com.hermes.h454.request": "c" * 64,
                              "com.hermes.h454.role": "wss-proxy"}},
    }


class CutoverTests(unittest.TestCase):
    def test_execute_required(self):
        with patch.object(m, "cutover") as cutover:
            self.assertEqual(m.main(["cutover", "--release-sha", "a" * 40]), 2)
            self.assertEqual(m.main(["plan", "--release-sha", "a" * 40, "--execute"]), 2)
            cutover.assert_not_called()

    def test_plan_readonly(self):
        with patch.object(m.legacy, "lock", return_value=nullcontext()), \
             patch.object(m, "locked_pins", return_value=nullcontext(b"{}")), \
             patch.object(m, "read_only") as read, \
             patch.object(m, "load_existing_wss") as loader, \
             patch.object(m, "read_old_pin_pair") as sidecar, \
             patch.object(m, "docker") as actions:
            self.assertEqual(m.main(["plan", "--release-sha", "a" * 40]), 0)
            actions.assert_not_called()
            read.assert_called_once()
            loader.assert_called_once()
            sidecar.assert_called_once()

    def test_path_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            target = root / "real"
            target.write_text("test")
            symlink = root / "link"
            symlink.symlink_to(target)
            with self.assertRaises(m.Hold):
                m.protected(symlink, 0o600)

    def test_proxy_refuses_foreign_label_and_retains_limits(self):
        pins = {"gateway_ipv4": "172.29.251.1", "tls_directory": "/var/lib/test"}
        with patch.object(m, "docker") as docker:
            with self.assertRaises(m.Hold):
                m.create_sidecar(pins, "d" * 64, {"Config": {"Labels": {}}})
            docker.assert_not_called()
            docker.return_value = "e" * 64
            self.assertEqual(m.create_sidecar(pins, "d" * 64, old_proxy()), "e" * 64)
            args = docker.call_args.args
            self.assertIn("--read-only", args)
            self.assertIn("--cap-drop", args)
            self.assertIn("no-new-privileges", args)
            self.assertIn("container:" + "d" * 64, args)
            self.assertNotIn("--privileged", args)
            self.assertNotIn("--publish", args)
            self.assertNotIn("BRC_ADMIN_PASSWORD", " ".join(args))

    def test_relay_preserves_immutable_state_mount(self):
        args = ["run", "-d", "--read-only", "--mount",
                "type=bind,src=/var/lib/hermes-brc-relay,dst=/state",
                "--env-file", "/etc/hermes-brc-relay/relay.env", m.FORK_IMAGE]
        with patch.object(m.legacy, "run_args", return_value=args), \
             patch.object(m, "registry_contract",
                          return_value=Path("/pinned/stage1-catalog.json")):
            cmd = m.new_relay_args()
        self.assertIn("BRC_DB=/state/relay.sqlite", cmd)
        self.assertIn("BRC_WORKSPACE_REGISTRY=" + m.REGISTRY_TARGET, cmd)
        self.assertIn("type=bind,src=/pinned/stage1-catalog.json,dst=" +
                      m.REGISTRY_TARGET + ",readonly", cmd)
        self.assertEqual(cmd.count("--mount"), 2)
        self.assertIn("HOME=/tmp", cmd)
        self.assertIn("--read-only", cmd)
        self.assertEqual(cmd[-1], m.FORK_IMAGE)

    def test_fork_registry_derives_only_four_owner_workspaces(self):
        with patch.object(m, "protected"):
            path = m.registry_contract()
        document = json.loads(path.read_bytes())
        self.assertEqual(document["schema"], 2)
        self.assertEqual(len(document["workspaces"]), 4)
        self.assertEqual(set(v["deviceId"] for v in document["workspaces"]),
                         {m.WINDOWS_SANDBOX_DEVICE})
        self.assertEqual(set(v["name"] for v in document["workspaces"]),
                         {"hermes", "your-fitness-coach",
                          "second-brain", "ai-development-toolkit"})
        self.assertTrue(all(v["scope"] == "sandbox" for v in document["workspaces"]))

    def test_registry_source_drift_refused(self):
        with patch.object(m, "protected"), \
             patch.object(m, "source_blob", return_value="0" * 40):
            with self.assertRaisesRegex(m.Hold, "WORKSPACE_SOURCE_DRIFT"):
                m.registry_contract()

    def test_old_pair_restart_restored_before_profile_hash(self):
        events = []
        relay = dict(old_relay(), State={"Running": True})
        proxy = dict(old_proxy(), State={"Running": True},
                     HostConfig={"NetworkMode": "container:" + relay["Id"]})
        def lookup(kind, name, optional=False):
            return {m.legacy.NAME: relay, m.PROXY: proxy}.get(name)
        def command(*args):
            events.append(args)
            return ""
        def review(raw):
            self.assertIn(("update", "--restart", "unless-stopped", m.legacy.NAME), events)
            self.assertIn(("update", "--restart", "unless-stopped", m.PROXY), events)
            events.append(("PROFILE",))
        pin = types.SimpleNamespace(read_bytes=lambda: b"attested")
        with patch.object(m, "inspect", side_effect=lookup), \
             patch.object(m, "docker", side_effect=command), \
             patch.object(m, "PINS", pin), patch.object(m, "PINS_OLD", pin), \
             patch.object(m, "read_old_pin_pair", side_effect=review), \
             patch.object(m.legacy, "healthy", return_value=True), \
             patch.object(m, "finalize_pending"):
            m.restore({}, relay, proxy, "", "", 3)
        self.assertEqual(events[-1], ("PROFILE",))

    def test_recover_reconciles_only_after_pins_lock_released(self):
        from contextlib import contextmanager
        locked = {"value": False}
        @contextmanager
        def pin_lock():
            locked["value"] = True
            try:
                yield b"attested"
            finally:
                locked["value"] = False
        relay = dict(old_relay(), State={"Running": True})
        proxy = dict(old_proxy(), State={"Running": True},
                     HostConfig={"NetworkMode": "container:" + relay["Id"]})
        def lookup(kind, name, optional=False):
            return {m.legacy.NAME: relay, m.PROXY: proxy}.get(name)
        def reconcile(path):
            self.assertFalse(locked["value"])
            return "READY"
        fake_wss = types.SimpleNamespace(
            _pins=lambda _: {
                "relay_name": m.legacy.NAME, "sidecar_name": m.PROXY,
                "relay_image": m.LEGACY_IMAGE, "sidecar_image": m.LEGACY_IMAGE,
                "relay_id": relay["Id"], "sidecar_id": proxy["Id"],
            },
            reconcile=reconcile,
        )
        receipt = json.dumps({
            "schema": 1, "original_pin_sha256": "f" * 64,
            "release_sha": "a" * 40, "devices": 3,
        }).encode()
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m, "LIVE_SHA",
                          types.SimpleNamespace(read_text=lambda: "a" * 40)), \
             patch.object(m.legacy, "lock", return_value=nullcontext()), \
             patch.object(m, "load_existing_wss", return_value=fake_wss), \
             patch.object(m, "protected"), \
             patch.object(m, "PINS_OLD",
                          types.SimpleNamespace(read_bytes=lambda: b"attested")), \
             patch.object(m, "PENDING",
                          types.SimpleNamespace(read_bytes=lambda: receipt)), \
             patch.object(m, "locked_pins", side_effect=pin_lock), \
             patch.object(m, "digest", return_value="f" * 64), \
             patch.object(m, "inspect", side_effect=lookup), \
             patch.object(m, "approval"), \
             patch.object(m, "restore") as restored:
            self.assertEqual(m.rollback_pair("a" * 40), (relay["Id"], proxy["Id"]))
            restored.assert_called_once()
        self.assertFalse(locked["value"])

    def test_approval_matches_exact_sha_and_pair(self):

        data = {
            "schema": 1,
            "decision": "OWNER_APPROVED_H454_STAGE1_RELAY_WSS_CUTOVER",
            "release_sha": "a" * 40,
            "fork_commit": m.FORK_COMMIT,
            "image": m.FORK_IMAGE,
            "archive_sha256": m.ARCHIVE_HASH,
            "legacy_image": m.LEGACY_IMAGE,
            "relay_id": "a" * 64,
            "sidecar_id": "b" * 64,
            "original_pins_sha256": m.ORIGINAL_PINS_SHA256,
            "observed_sidecar_profile_sha256": m.OBSERVED_PROFILE_SHA256,
        }
        class Approval:
            parent = Path("/private")
            def stat(self):
                return types.SimpleNamespace(st_size=300)
            def read_text(self, encoding):
                return json.dumps(data)
        with patch.object(m, "APPROVAL", Approval()), patch.object(m, "protected"):
            m.approval("a" * 40, old_relay(), old_proxy())
            with self.assertRaises(m.Hold):
                m.approval("f" * 40, old_relay(), old_proxy())

    def test_unreviewed_profile_drift_fails_closed(self):
        pins = {
            "relay_name": m.legacy.NAME, "sidecar_name": m.PROXY,
            "relay_image": m.LEGACY_IMAGE, "sidecar_image": m.LEGACY_IMAGE,
            "sidecar_id": "b" * 64, "profile_sha256": m.ORIGINAL_PROFILE_SHA256,
        }
        fake_wss = types.SimpleNamespace(
            _pins=lambda b: pins, profile_sha256=lambda x: "f" * 64,
        )
        with patch.object(m, "wss", fake_wss), patch.object(m, "inspect") as inspector:
            with self.assertRaisesRegex(m.Hold, "UNATTESTED_WSS_PROFILE_DRIFT"):
                m.read_old_pin_pair(b"untrusted")
            inspector.assert_called_once()

    def test_dual_pin_retains_strict_wss_validation(self):
        pins = {
            "relay_name": m.legacy.NAME, "sidecar_name": m.PROXY,
            "relay_image": m.LEGACY_IMAGE, "sidecar_image": m.LEGACY_IMAGE,
            "sidecar_id": "b" * 64, "profile_sha256": m.ORIGINAL_PROFILE_SHA256,
            "tls_directory": "/synthetic",
        }
        def verify_pin(data):
            return json.loads(data) if data.startswith(b"{") else pins
        fake_wss = types.SimpleNamespace(
            _pins=verify_pin, profile_sha256=lambda x: m.OBSERVED_PROFILE_SHA256,
            _snapshot=lambda *args: ({"Id": "a" * 64}, {"Id": "b" * 64}),
            _namespace=lambda *args: None, _tls=lambda *args: None,
            _directory=lambda *args: __import__("os").open("/dev/null", __import__("os").O_RDONLY),
            _read_file=lambda *args, **kwargs: b"synthetic-ca",
        )
        with patch.object(m, "wss", fake_wss), \
             patch.object(m, "inspect"), \
             patch.object(m, "digest_bytes", return_value=m.ORIGINAL_PINS_SHA256):
            approved, _, _, accepted = m.read_old_pin_pair(b"old-pins")
        self.assertEqual(approved["profile_sha256"], m.OBSERVED_PROFILE_SHA256)
        self.assertEqual(json.loads(accepted)["profile_sha256"], m.OBSERVED_PROFILE_SHA256)

    def test_pair_cutover_order_and_client_gate(self):
        from unittest.mock import Mock
        new_relay = "d" * 64
        new_proxy = "e" * 64
        events = []
        fake_wss = types.SimpleNamespace(
            _pins=lambda data: {"tls_directory": "/synthetic"},
            _snapshot=lambda *args: ({}, {}),
            _namespace=lambda *args: None,
            reconcile=lambda *args: "READY",
        )
        def command(*args):
            events.append(args)
            if args[0] == "run":
                return new_relay
            return ""
        candidate = {"Id": new_relay, "Image": m.FORK_IMAGE,
                     "Config": {"User": "979:975"}}
        # Do not inspect production's root-owned H454 pins in DynamicUser tests.
        with patch.object(m.legacy, "lock", return_value=nullcontext()), \
             patch.object(m, "read_only"), \
             patch.object(m, "load_existing_wss", return_value=fake_wss), \
             patch.object(m, "locked_pins", return_value=nullcontext(b"original")), \
             patch.object(m, "read_old_pin_pair",
                          return_value=({"tls_directory": "/synthetic"},
                                        old_relay(), old_proxy(), b"approved")), \
             patch.object(m, "approval"), \
             patch.object(m.legacy, "devices", return_value=3), \
             patch.object(m.legacy, "snapshot", side_effect=["before", "after"]), \
             patch.object(m, "PINS_OLD", types.SimpleNamespace(exists=lambda: False)), \
             patch.object(m, "write_once"), \
             patch.object(m, "digest", return_value="f" * 64), \
             patch.object(m, "sync_pin_directory"), \
             patch.object(m, "docker", side_effect=command), \
             patch.object(m, "new_relay_args", return_value=["run", "-d", m.FORK_IMAGE]), \
             patch.object(m, "inspect", return_value=candidate), \
             patch.object(m, "create_sidecar", return_value=new_proxy), \
             patch.object(m, "updated_pins", return_value=b"{}"), \
             patch.object(m, "replace_pins"), \
             patch.object(m.legacy, "healthy", return_value=True), \
             patch.object(m, "compare_auth") as guard, \
             patch.object(m, "PENDING", types.SimpleNamespace(unlink=lambda: None)):
            self.assertEqual(m.cutover("a" * 40), (new_relay, new_proxy))
        self.assertLess(events.index(("stop", "--time", "12", m.PROXY)),
                        events.index(("stop", "--time", "20", m.legacy.NAME)))
        self.assertLess(events.index(("rename", m.legacy.NAME, m.RELAY_OLD)),
                        events.index(("run", "-d", m.FORK_IMAGE)))
        self.assertIn(("start", new_proxy), events)
        guard.assert_called_once_with("before", "after")

    def test_failed_cutover_requests_original_pair_rollback(self):
        def refuse(*args):
            raise m.Hold("DOCKER_OPERATION_FAILED")
        # Do not inspect production's root-owned H454 pins in DynamicUser tests.
        with patch.object(m.legacy, "lock", return_value=nullcontext()), \
             patch.object(m, "read_only"), \
             patch.object(m, "load_existing_wss"), \
             patch.object(m, "locked_pins", return_value=nullcontext(b"original")), \
             patch.object(m, "read_old_pin_pair",
                          return_value=({}, old_relay(), old_proxy(), b"accepted")), \
             patch.object(m, "approval"), \
             patch.object(m.legacy, "devices", return_value=3), \
             patch.object(m.legacy, "snapshot", return_value="before"), \
             patch.object(m, "PINS_OLD", types.SimpleNamespace(exists=lambda: False)), \
             patch.object(m, "write_once"), \
             patch.object(m, "digest", return_value="f" * 64), \
             patch.object(m, "sync_pin_directory"), \
             patch.object(m, "docker", side_effect=refuse), \
             patch.object(m, "restore") as restore:
            with self.assertRaisesRegex(m.Hold, "ORIGINAL_PAIR_RESTORED"):
                m.cutover("a" * 40)
            restore.assert_called_once()

    def test_finalize_pending_missing_after_wss_commit_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "reconcile.pending"
            with patch.object(m, "PENDING", missing), \
                 patch.object(m, "sync_pin_directory") as sync:
                m.finalize_pending()
                sync.assert_not_called()

    def test_finalize_pending_exact_receipt_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "stage1-original-pins.json"
            backup.write_bytes(b"pinned-original")
            pending = root / "reconcile.pending"
            installed = root / "last-success.sha"
            installed.write_text("a" * 40)
            receipt = {
                "schema": 1, "original_pin_sha256": m.digest(backup),
                "release_sha": "a" * 40, "devices": 3,
            }
            with patch.object(m, "PENDING", pending), \
                 patch.object(m, "PINS_OLD", backup), \
                 patch.object(m, "LIVE_SHA", installed), \
                 patch.object(m, "protected"), \
                 patch.object(m, "sync_pin_directory") as sync:
                pending.write_text(json.dumps(receipt))
                m.finalize_pending()
                self.assertFalse(pending.exists())
                sync.assert_called_once()
                sync.reset_mock()
                pending.write_text(json.dumps(dict(receipt, original_pin_sha256="f" * 64)))
                with self.assertRaisesRegex(m.Hold, "PENDING_RECEIPT_CHANGED"):
                    m.finalize_pending()
                self.assertTrue(pending.exists())
                sync.assert_not_called()

    def test_foreign_sidecar_not_deleted(self):
        fake = {"Id": "f" * 64, "Image": m.LEGACY_IMAGE,
                "HostConfig": {"NetworkMode": "host"}}
        with patch.object(m, "inspect", return_value=fake), \
             patch.object(m, "docker") as actions:
            with self.assertRaisesRegex(m.Hold, "FOREIGN_SIDE_CAR"):
                m.restore({}, old_relay(), old_proxy(), "d" * 64, "e" * 64, 1)
            actions.assert_not_called()

    def test_foreign_relay_not_deleted(self):
        fake = {"Id": "f" * 64, "Image": m.LEGACY_IMAGE,
                "Config": {"Labels": {}}}
        with patch.object(m, "inspect", side_effect=[None, fake]), \
             patch.object(m, "docker") as actions:
            with self.assertRaisesRegex(m.Hold, "FOREIGN_RELAY"):
                m.restore({}, old_relay(), old_proxy(), "d" * 64, "", 1)
            actions.assert_not_called()


if __name__ == "__main__":
    unittest.main()
