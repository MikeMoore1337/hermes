import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_brc_enrollment import Paired
from device_fabric import windows_personal_commander_bundle as bundle
from device_fabric import windows_personal_commander_config as config
from device_fabric.personal_replay import PersonalReplay
from scripts import h454_windows_personal_yfc_state as state

DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
CA = b"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
PAIRED = Paired("windows-personal", DEVICE, TOKEN, "wss://hermes.mikemoore.top/ws")


class StateValidationTests(unittest.TestCase):
    def test_invalid_environment_is_rejected_without_leaking_details(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "relative"}):
            with self.assertRaises(state.YfcStateDenied) as error:
                state.persist_new(PAIRED, release_sha="a" * 40, ca=CA,
                                  expected_manifest=b"", expected_sha256="b" * 64)
        self.assertEqual(str(error.exception), "yfc_state_denied")


if os.name == "nt":
    class StateProvisioningTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-yfc-state-")
            self.addCleanup(self.temp.cleanup)
            self.env = patch.dict(os.environ, {"LOCALAPPDATA": str(Path(self.temp.name).resolve())})
            self.env.start()
            self.addCleanup(self.env.stop)
            self.base = Path(self.temp.name).resolve() / state.APP_NAME
            self.release = self.base / "release"
            self.release.mkdir(parents=True)
            (self.release / "fixture.txt").write_text("synthetic", encoding="ascii")
            self.manifest = bundle.manifest(self.release)
            self.sha = hashlib.sha256(self.manifest).hexdigest()
            self.ca_patch = patch.object(state, "load_ca", return_value=CA)
            self.ca_patch.start()
            self.addCleanup(self.ca_patch.stop)

        def persist(self):
            state.persist_new(PAIRED, release_sha="a" * 40, ca=CA,
                              expected_manifest=self.manifest, expected_sha256=self.sha)

        def test_current_user_dpapi_and_replay_journal_are_preserved(self):
            with patch.object(state.status, "bearer_state", return_value=True):
                self.persist()
                private = self.base / "worker-private"
                raw = (private / "device.json").read_bytes()
                self.assertNotIn(TOKEN.encode(), raw)
                parsed = config.parse_config(raw)
                self.assertEqual(parsed.profile, "yfc-dev")
                self.assertEqual(config.unseal(parsed, owner_sid=state.current_sid(), ca=CA,
                                               bundle_sha256=self.sha), TOKEN)
                self.assertEqual((private / "release-manifest.json").read_bytes(), self.manifest)
                replay = PersonalReplay(private)
                self.assertTrue(replay.claim("synthetic-call"))
                self.assertFalse(PersonalReplay(private).claim("synthetic-call"))
                with self.assertRaises(state.YfcStateDenied):
                    self.persist()
                self.assertEqual((private / "device.json").read_bytes(), raw)
                self.assertFalse(PersonalReplay(private).claim("synthetic-call"))

        def test_revoked_grant_and_changed_release_create_no_private_state(self):
            with patch.object(state.status, "bearer_state", return_value=False):
                with self.assertRaises(state.YfcStateDenied):
                    self.persist()
            self.assertFalse((self.base / "worker-private").exists())
            (self.release / "fixture.txt").write_text("changed", encoding="ascii")
            with patch.object(state.status, "bearer_state") as status:
                with self.assertRaises(state.YfcStateDenied):
                    self.persist()
                status.assert_not_called()
            self.assertFalse((self.base / "worker-private").exists())
