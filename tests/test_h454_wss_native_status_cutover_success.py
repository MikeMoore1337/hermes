"""H454 WSS status-only: exercise a complete synthetic successful transaction.

This is an in-memory Docker/systemd simulation. No real BRC devices, tokens,
VPS filesystem, TLS certificates, Docker socket, or production services used.
"""
from __future__ import annotations

from contextlib import nullcontext, ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest.mock import Mock, patch

from scripts import h454_wss_native_status_sidecar_cutover as tx


class SyntheticSuccessTests(unittest.TestCase):
    def test_success_retains_exact_old_sidecar_and_never_switches_brc(self):
        relay_id, old_id, new_id = "a" * 64, "b" * 64, "c" * 64
        old_source, new_source = b"original-private-wss", b"new-native-status-wss"
        previous = {
            "relay_id": relay_id,
            "relay_image": tx.LIVE_RELAY_IMAGE,
            "sidecar_id": old_id,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "proxy_sha256": tx.digest(old_source),
            "tls_directory": "/synthetic-no-real-tls",
        }
        original_pins = tx.canonical(previous)
        next_pins = tx.canonical(dict(
            previous, sidecar_id=new_id,
            proxy_sha256=tx.digest(new_source)))
        plan = {
            "status": "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS",
            "current_proxy_sha256": tx.digest(old_source),
            "candidate_proxy_sha256": tx.digest(new_source),
            "relay_container_id": relay_id,
            "sidecar_container_id": old_id,
            "sidecar_native_status_deployed": False,
            "brc_wss_mutation": False,
        }
        commands = []
        old = {
            "Id": old_id, "Name": "/" + tx.stage1.PROXY,
            "State": {"Running": True},
        }
        new = {
            "Id": new_id, "Name": "/" + tx.stage1.PROXY,
            "State": {"Running": False},
        }
        state = {
            "active": old,
            "checkpoint": None,
            "old_source": old_source,
            "pins": original_pins,
            "pending_id": "",
            "backup_created": False,
        }
        preflight = Mock()
        preflight.read_fixed.return_value = new_source
        wss = Mock()
        wss._pins.side_effect = json.loads
        wss._directory.return_value = 11
        wss._read_file.return_value = old_source
        wss.reconcile.return_value = "READY"

        def container_by_name(name):
            if name == tx.stage1.PROXY:
                return state["active"]
            if name == tx.CHECKPOINT:
                return state["checkpoint"]
            if name == tx.CHECKPOINT_NEW:
                return None
            raise AssertionError("unexpected container name")

        def docker(*args):
            commands.append(args)
            if args[0] == "stop":
                self.assertEqual(args[2], old_id)
                old["State"]["Running"] = False
            elif args[0] == "update":
                self.assertEqual(args[-1], old_id)
                self.assertEqual(args[2], "no")
            elif args[0] == "rename":
                self.assertEqual(args, ("rename", old_id, tx.CHECKPOINT))
                old["Name"] = "/" + tx.CHECKPOINT
                state["active"] = None
                state["checkpoint"] = old
            elif args[0] == "start":
                self.assertEqual(args, ("start", new_id))
                new["State"]["Running"] = True
            else:
                raise AssertionError("unexpected Docker operation")
            return ""

        def create_sidecar(pins, relay, old_proxy):
            self.assertIs(old_proxy, old)
            self.assertEqual(relay, relay_id)
            self.assertEqual(pins, previous)
            self.assertIs(state["checkpoint"], old)
            self.assertIsNone(state["active"])
            state["active"] = new
            return new_id

        def replace_proxy(raw):
            self.assertEqual(raw, new_source)
            state["old_source"] = raw

        def swap_pins(raw):
            self.assertEqual(raw, next_pins)
            state["pins"] = raw
            (root / "pins.json").write_bytes(raw)

        def persist_backup(*args):
            self.assertFalse(state["backup_created"])
            self.assertIs(state["active"], old)
            state["backup_created"] = True

        def write_pending(path, raw):
            self.assertEqual(path, root / "native-status-upgrade.pending")
            self.assertTrue(state["backup_created"])
            path.write_bytes(raw)

        def update_pending_id(value):
            self.assertEqual(value, new_id)
            state["pending_id"] = value

        def pending_record(saved):
            self.assertEqual(saved["relay-id.txt"], (relay_id + "\n").encode())
            return {"new_sidecar_id": state["pending_id"]}

        def verify_live(wss_arg, pins, relay, *, status=False):
            self.assertIs(wss_arg, wss)
            self.assertEqual(relay, relay_id)
            if status:
                self.assertEqual(pins["sidecar_id"], new_id)
                self.assertIs(state["active"], new)
                self.assertTrue(new["State"]["Running"])
            else:
                self.assertEqual(pins["sidecar_id"], old_id)
                self.assertIs(state["active"], old)
        saved = {
            "relay-id.txt": (relay_id + "\n").encode(),
            "sidecar-id.txt": (old_id + "\n").encode(),
            "old-pins.json": original_pins,
            "old-proxy.mjs": old_source,
            "candidate-proxy.mjs": new_source,
        }
        with TemporaryDirectory(prefix="h454-wss-success-fixture-") as dirname:
            root = Path(dirname)
            (root / "pins.json").write_bytes(original_pins)
            candidate = root / "synthetic-status-source.mjs"
            with ExitStack() as stack:
                def setmock(obj, name, **kw):
                    return stack.enter_context(patch.object(obj, name, **kw))
                setmock(tx, "ROOT", new=root)
                setmock(tx, "PENDING", new=root / "native-status-upgrade.pending")
                setmock(tx, "BACKUP", new=root / "native-status-upgrade-evidence")
                setmock(tx, "SOURCE_BLOB", new=tx.git_blob(new_source))
                setmock(tx, "verified_preflight", return_value=preflight)
                setmock(tx, "normal_plan", return_value=plan)
                confirm = setmock(tx, "owner_tty")
                setmock(tx, "current_name", side_effect=container_by_name)
                setmock(tx, "verify_live", side_effect=verify_live)
                setmock(tx, "backup", side_effect=persist_backup)
                setmock(tx, "read_backup", return_value=saved)
                setmock(tx, "pending_record", side_effect=pending_record)
                setmock(tx, "replace_proxy", side_effect=replace_proxy)
                setmock(tx, "fresh_pins", return_value=next_pins)
                setmock(tx, "update_pending_new", side_effect=update_pending_id)
                setmock(tx.os, "close")
                setmock(tx.stage1.legacy, "lock", side_effect=nullcontext)
                setmock(tx.stage1, "locked_pins",
                        side_effect=lambda: nullcontext(state["pins"]))
                setmock(tx.stage1, "load_existing_wss", return_value=wss)
                setmock(tx.stage1, "docker", side_effect=docker)
                setmock(tx.stage1, "create_sidecar", side_effect=create_sidecar)
                setmock(tx.stage1, "replace_pins", side_effect=swap_pins)
                setmock(tx.stage1, "sync_pin_directory")
                setmock(tx.stage1, "write_once", side_effect=write_pending)

                receipt = tx.cutover(candidate)
                self.assertEqual(
                    receipt["status"],
                    "H454_WSS_NATIVE_STATUS_SWITCHED_PENDING_OWNER_ACCEPTANCE",
                )
                self.assertEqual(receipt["relay_changed"], False)
                self.assertEqual(receipt["native_service_started"], False)
                self.assertEqual(receipt["device_paired"], False)
                self.assertEqual(receipt["rollback_checkpoint_retained"], True)
                self.assertIs(state["checkpoint"], old)
                self.assertIs(state["active"], new)
                self.assertEqual(state["old_source"], new_source)
                self.assertEqual(state["pins"], next_pins)
                self.assertFalse((root / "native-status-upgrade.pending").exists())
                preflight.native_release.assert_called_once()
                wss.reconcile.assert_called_once()
                self.assertEqual(confirm.call_count, 1)
                self.assertEqual(
                    [args[0] for args in commands],
                    ["stop", "update", "rename", "start"],
                )
                self.assertFalse(any(relay_id in args for args in commands))
                self.assertFalse(any(
                    args[0] in {"rm", "pull", "build", "restart"}
                    for args in commands))
                self.assertEqual(preflight.read_fixed.call_count, 2)


if __name__ == "__main__":
    unittest.main()
