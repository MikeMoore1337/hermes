"""H454 status-only WSS candidate: synthetic pins, denials, owner TTY."""
from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import unittest
from unittest import mock

from scripts import h454_wss_native_status_sidecar_cutover as tx


class SidecarOnlyCandidateTests(unittest.TestCase):
    def test_preflight_blob_bound_to_exact_merged_source(self):
        raw = (Path(__file__).resolve().parents[1] /
               "scripts/h454_wss_native_status_preflight.py").read_bytes()
        self.assertEqual(tx.git_blob(raw), tx.PREFLIGHT_BLOB)
        self.assertNotEqual(tx.SOURCE_BLOB, tx.OLD_BLOB)

    def test_fresh_pins_keep_relay_and_change_only_proxy_metadata(self):
        old = {"relay_id": "a" * 64, "relay_image": tx.stage1.FORK_IMAGE,
               "sidecar_id": "b" * 64, "sidecar_image": tx.stage1.LEGACY_IMAGE,
               "proxy_sha256": "c" * 64, "profile_sha256": "d" * 64,
               "tls_directory": "/synthetic"}
        observed = {"Id": "e" * 64, "Name": "/" + tx.stage1.PROXY,
                    "Image": tx.stage1.LEGACY_IMAGE}
        wss = mock.Mock()
        wss.profile_sha256.return_value = "f" * 64
        with mock.patch.object(tx.stage1, "inspect", return_value=observed):
            result = tx.fresh_pins(wss, old, "e" * 64, b"candidate", "a" * 64)
        change = json.loads(result)
        self.assertEqual(change["relay_id"], old["relay_id"])
        self.assertEqual(change["relay_image"], old["relay_image"])
        self.assertEqual(change["sidecar_id"], "e" * 64)
        self.assertEqual(change["proxy_sha256"], hashlib.sha256(b"candidate").hexdigest())
        self.assertEqual(change["profile_sha256"], "f" * 64)
        self.assertEqual(old["sidecar_id"], "b" * 64)
        wss._snapshot.assert_called_once()

    def test_fresh_pins_refuses_foreign_relay_and_proxy(self):
        old = {"relay_id": "a" * 64}
        with self.assertRaisesRegex(tx.Refused, "NEW_PROXY_IDENTITY_INVALID"):
            tx.fresh_pins(mock.Mock(), old, "c" * 64, b"x", "b" * 64)
        old["relay_id"] = "a" * 64
        observed = {"Id": "e" * 64, "Name": "/" + tx.stage1.PROXY,
                    "Image": "sha256:" + "a" * 64}
        with mock.patch.object(tx.stage1, "inspect", return_value=observed):
            with self.assertRaisesRegex(tx.Refused, "NEW_PROXY_CONTAINER_UNTRUSTED"):
                tx.fresh_pins(mock.Mock(), old, "e" * 64, b"x", "a" * 64)

    def test_failure_to_list_checkpoint_never_treated_as_absent(self):
        with mock.patch.object(tx.stage1, "docker", side_effect=OSError("Docker unavailable")):
            with self.assertRaises(OSError):
                tx.current_name(tx.CHECKPOINT)
        with mock.patch.object(tx.stage1, "docker", return_value="foreign"):
            with self.assertRaisesRegex(tx.Refused, "PROXY_DISCOVERY_AMBIGUOUS"):
                tx.current_name(tx.CHECKPOINT)

    def test_unknown_container_name_rejected_before_docker(self):
        with mock.patch.object(tx.stage1, "docker") as docker:
            with self.assertRaisesRegex(tx.Refused, "UNKNOWN_PROXY_NAME"):
                tx.current_name("my-live-production-db")
            docker.assert_not_called()

    def test_operator_rejects_noninteractive_tty(self):
        with mock.patch.object(tx.os, "geteuid", return_value=0), mock.patch.object(
            tx.sys.stdin, "isatty", return_value=False
        ):
            with self.assertRaisesRegex(tx.Refused, "ORIGINAL_OWNER_TTY_REQUIRED"):
                tx.owner_tty("CUTOVER", "a" * 64, "b" * 64, "c" * 64)

    def test_proxy_replace_rejects_foreign_script_before_any_writes(self):
        with mock.patch.object(tx.stage1, "write_once") as write:
            with self.assertRaisesRegex(tx.Refused, "PROXY_REPLACE_FOREIGN_SOURCE"):
                tx.replace_proxy(b"nonreviewed production script")
            write.assert_not_called()

    def test_pending_backup_strictly_no_foreign_item(self):
        with mock.patch.object(tx.stage1, "write_once") as write:
            with self.assertRaisesRegex(tx.Refused, "BACKUP_ITEM_UNKNOWN"):
                tx.persist("../state/relay.sqlite", b"irrelevant")
            write.assert_not_called()

    def test_missing_candidate_is_not_cause_to_change_system(self):
        with mock.patch.object(tx, "verified_preflight", return_value=object()), mock.patch.object(
            tx, "cutover") as cutover, mock.patch.object(tx, "rollback") as rollback:
            self.assertEqual(tx.main(["plan"]), 2)
            cutover.assert_not_called()
            rollback.assert_not_called()

    def test_explicit_execute_required_for_mutations(self):
        with mock.patch.object(tx, "verified_preflight", return_value=object()), mock.patch.object(
            tx, "cutover") as cutover, mock.patch.object(tx, "rollback") as rollback:
            self.assertEqual(tx.main(["cutover", "--candidate-source", "/root/a"]), 2)
            self.assertEqual(tx.main(["rollback"]), 2)
            cutover.assert_not_called()
            rollback.assert_not_called()

    def test_canonical_pins_has_single_trailing_lf(self):
        data = {"b": 2, "a": 1}
        self.assertEqual(tx.canonical(data), b'{"a":1,"b":2}\n')


if __name__ == "__main__":
    unittest.main()
