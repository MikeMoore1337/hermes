"""H454 WSS sidecar-only: inject failures throughout the owner-gated cutover.

This test runs with a disposable in-memory/mock Docker interface. It never
connects to the owner VPS, a Docker socket, BRC, a real TLS endpoint, or systemd.
"""
from __future__ import annotations

from contextlib import ExitStack, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest import mock

from scripts import h454_wss_native_status_sidecar_cutover as tx


class CutoverFailureMatrix(unittest.TestCase):
    def exercise(self, failed_op: str, *, restored=True):
        relay_id, old_id, new_id = "a" * 64, "b" * 64, "c" * 64
        old_source, candidate = b"synthetic-old", b"synthetic-new"
        pins = {
            "relay_id": relay_id, "sidecar_id": old_id,
            "relay_image": tx.LIVE_RELAY_IMAGE,
            "sidecar_image": tx.stage1.LEGACY_IMAGE,
            "proxy_sha256": tx.digest(old_source),
            "tls_directory": "/synthetic-only",
        }
        raw = tx.canonical(pins)
        original = {
            "Id": old_id, "Image": tx.stage1.LEGACY_IMAGE,
            "Name": "/" + tx.stage1.PROXY, "State": {"Running": True},
        }
        report = {
            "status": "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS",
            "current_proxy_sha256": tx.digest(old_source),
            "candidate_proxy_sha256": tx.digest(candidate),
            "relay_container_id": relay_id,
            "sidecar_container_id": old_id,
            "brc_wss_mutation": False,
            "sidecar_native_status_deployed": False,
        }
        actions = []
        with TemporaryDirectory(prefix="h454-wss-cutover-test-") as tmp:
            root = Path(tmp)
            (root / "pins.json").write_bytes(raw)
            pending = root / "native-status-upgrade.pending"

            def docker(*args):
                actions.append(args)
                if failed_op == args[0]:
                    raise OSError("synthetic injected Docker error")
                return ""

            def write_once(path, data):
                self.assertEqual(path, pending)
                path.write_bytes(data)

            def read_protected(file, *, mode, limit=100000):
                if file == pending:
                    return pending.read_bytes()
                raise AssertionError("unexpected protected path")

            saved = {
                "old-pins.json": raw,
                "old-proxy.mjs": old_source,
                "candidate-proxy.mjs": candidate,
                "relay-id.txt": (relay_id + "\n").encode("ascii"),
                "sidecar-id.txt": (old_id + "\n").encode("ascii"),
            }
            wss = mock.Mock()
            wss._pins.side_effect = lambda blob: json.loads(blob)
            wss._directory.return_value = 90
            wss._read_file.return_value = old_source
            wss.reconcile.return_value = "READY"
            preflight = mock.Mock()
            preflight.read_fixed.return_value = candidate
            new_instance = {
                "Id": new_id,
                "Name": "/" + tx.stage1.PROXY,
                "Image": tx.stage1.LEGACY_IMAGE,
            }
            preflight.check_proxy_source.return_value = None
            restore = mock.Mock()
            if not restored:
                restore.side_effect = OSError("synthetic restoration refused")
            seen_live = 0

            def live(*args, **kwargs):
                nonlocal seen_live
                seen_live += 1
                if failed_op == "live_postcheck" and seen_live == 2:
                    raise tx.Refused("SYNTHETIC_STATUS_FAILED")

            def new_source(*args, **kwargs):
                if failed_op == "source_swap":
                    raise OSError("synthetic source replacement refused")

            def create(*args, **kwargs):
                if failed_op == "create":
                    raise OSError("synthetic container creation refused")
                return new_id

            def new_pins(*args, **kwargs):
                if failed_op == "pin_render":
                    raise OSError("synthetic pinned manifest refused")
                return tx.canonical(dict(pins, sidecar_id=new_id,
                                         proxy_sha256=tx.digest(candidate)))

            def replace_pins(*args, **kwargs):
                if failed_op == "pin_swap":
                    raise OSError("synthetic pin swap refused")

            state = {"native_checks": 0}
            def native_check():
                state["native_checks"] += 1
                if failed_op == "native_postcheck":
                    raise OSError("synthetic systemd state drift")

            def current_name(name):
                if name == tx.stage1.PROXY:
                    return original
                if name in (tx.CHECKPOINT, tx.CHECKPOINT_NEW):
                    return None
                raise AssertionError("unexpected name")

            with ExitStack() as stack:
                def patch(obj, name, **kwargs):
                    return stack.enter_context(mock.patch.object(obj, name, **kwargs))

                patch(tx, "ROOT", new=root)
                patch(tx, "PENDING", new=pending)
                patch(tx, "BACKUP", new=root / "backup")
                patch(tx, "OLD_BLOB", new=tx.git_blob(old_source))
                patch(tx, "SOURCE_BLOB", new=tx.git_blob(candidate))
                patch(tx, "verified_preflight", return_value=preflight)
                patch(tx, "normal_plan", return_value=report)
                patch(tx, "owner_tty")
                patch(tx, "verify_live", side_effect=live)
                patch(tx, "current_name", side_effect=current_name)
                patch(tx, "read_backup", return_value=saved)
                patch(tx, "backup")
                patch(tx, "replace_proxy", side_effect=new_source)
                patch(tx, "fresh_pins", side_effect=new_pins)
                patch(tx, "restore_known", new=restore)
                patch(tx, "acquire_reconcile_guard")
                patch(tx, "release_reconcile_guard")
                patch(tx, "update_pending_new")
                patch(tx, "pending_record", return_value={"new_sidecar_id": ""})
                patch(tx.os, "close")
                patch(tx.stage1, "load_existing_wss", return_value=wss)
                patch(tx.stage1.legacy, "lock", side_effect=lambda: nullcontext())
                patch(tx.stage1, "locked_pins", side_effect=lambda: nullcontext(raw))
                patch(tx.stage1, "write_once", side_effect=write_once)
                patch(tx.stage1, "sync_pin_directory")
                patch(tx.stage1, "docker", side_effect=docker)
                patch(tx.stage1, "create_sidecar", side_effect=create)
                patch(tx.stage1, "replace_pins", side_effect=replace_pins)
                patch(tx.stage1, "inspect", return_value=new_instance)
                patch(preflight, "native_release", side_effect=native_check)
                with self.assertRaises(tx.Refused):
                    tx.cutover(root / "h454-wss-native-status-synthetic.mjs")

                restore.assert_called_once()
                if failed_op == "native_postcheck":
                    self.assertEqual(state["native_checks"], 1)
                if failed_op == "live_postcheck":
                    self.assertEqual(seen_live, 2)
                if restored:
                    self.assertFalse(pending.exists(),
                                     "successful restoration clears task-owned pending marker")
                else:
                    self.assertTrue(pending.exists(),
                                    "unverified restore must preserve pending marker")

                self.assertNotIn(("stop", "--time", "12", relay_id), actions)
                self.assertTrue(all(relay_id not in a for a in actions
                                    if a and a[0] in ("stop", "rename", "rm")),
                                "BRC relay must never be stopped or renamed")
                self.assertTrue(any(a[0] == "stop" for a in actions)
                                or failed_op == "source_swap" and
                                any(a[0] == "stop" for a in actions))
                return actions

    def test_docker_stop_fail(self):
        self.exercise("stop")

    def test_docker_update_fail(self):
        self.exercise("update")

    def test_docker_rename_fail(self):
        self.exercise("rename")

    def test_source_swap_fail(self):
        self.exercise("source_swap")

    def test_docker_create_fail(self):
        self.exercise("create")

    def test_new_pins_render_fail(self):
        self.exercise("pin_render")

    def test_pin_swap_fail(self):
        self.exercise("pin_swap")

    def test_docker_start_fail(self):
        self.exercise("start")

    def test_native_postcheck_fail(self):
        self.exercise("native_postcheck")

    def test_private_status_postcheck_fail(self):
        self.exercise("live_postcheck")

    def test_failed_restore_retains_pending(self):
        self.exercise("stop", restored=False)


if __name__ == "__main__":
    unittest.main()
