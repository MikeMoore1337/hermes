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
        with patch.object(m.legacy, "run_args", return_value=args):
            cmd = m.new_relay_args()
        self.assertIn("BRC_DB=/state/relay.sqlite", cmd)
        self.assertIn("HOME=/tmp", cmd)
        self.assertIn("--read-only", cmd)
        self.assertEqual(cmd[-1], m.FORK_IMAGE)

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
