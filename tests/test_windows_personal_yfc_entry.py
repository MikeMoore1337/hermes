import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from device_fabric.native_brc_enrollment import Paired
from device_fabric import windows_personal_commander_config as config
from scripts import h454_windows_personal_yfc_entry as entry

SID = "S-1-5-21-1-2-3-1001"
DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
CA = b"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
DIGEST = "c" * 64


class EntryFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-entry-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name).resolve()
        (self.private / "device.json").write_bytes(b"synthetic")

    def test_bounded_fixed_file_read(self):
        self.assertEqual(entry._read_private(self.private, "device.json", 32), b"synthetic")
        with self.assertRaises(ValueError):
            entry._read_private(self.private, "device.json", 4)
        with self.assertRaises(ValueError):
            entry._read_private(self.private, "other.json", 32)

    def test_hardlinked_private_file_is_denied_without_leaking_path(self):
        os.link(self.private / "device.json", self.private / "alias")
        with self.assertRaises(ValueError) as error:
            entry._read_private(self.private, "device.json", 32)
        self.assertEqual(str(error.exception), "yfc_entry_denied")

    def test_invalid_entry_arguments_do_not_start_worker(self):
        with patch.object(entry, "run") as run:
            self.assertEqual(entry.main([]), 2)
            run.assert_not_called()


if os.name == "nt":
    class EntryWorkerTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-entry-worker-")
            self.addCleanup(self.temp.cleanup)
            self.base = Path(self.temp.name).resolve()
            self.environment = patch.dict(os.environ, {"LOCALAPPDATA": str(self.base)})
            self.environment.start()
            self.addCleanup(self.environment.stop)
            app = self.base / entry.APP_NAME
            private, release = app / "worker-private", app / "release"
            private.mkdir(parents=True)
            (release / "deps").mkdir(parents=True)
            (release / "deps" / entry.WHEEL).write_bytes(b"synthetic")
            paired = Paired("windows-personal", DEVICE, TOKEN, "wss://hermes.mikemoore.top/ws")
            raw = config.prepare_config(paired, owner_sid=SID, release_sha="d" * 40, ca=CA,
                bundle_sha256=DIGEST, now=1000, profile="yfc-dev", seal=lambda *_a, **_k: b"s" * 64)
            (private / "device.json").write_bytes(raw)
            (private / "release-manifest.json").write_bytes(b"synthetic")

        def test_bad_release_never_attaches_job_or_starts_worker(self):
            with patch.object(entry, "load_ca", return_value=CA), \
                 patch.object(entry.bundle, "verify", side_effect=ValueError()), \
                 patch.object(entry, "attach_current_worker") as attach, patch.object(entry, "run") as run:
                self.assertEqual(entry.main(["--run"]), 2)
                attach.assert_not_called()
                run.assert_not_called()

        def test_outage_retries_and_revocation_stops_without_reattaching_job(self):
            package = types.ModuleType("websockets")
            package.__path__ = []
            sync = types.ModuleType("websockets.sync")
            sync.__path__ = []
            client = types.ModuleType("websockets.sync.client")
            client.connect = lambda *_a, **_k: None
            replay = types.SimpleNamespace(claim=lambda _id: True)
            modules = {"websockets": package, "websockets.sync": sync, "websockets.sync.client": client}
            with patch.dict(sys.modules, modules), patch.object(sys, "path", list(sys.path)), \
                 patch.object(entry, "load_ca", return_value=CA), patch.object(entry.bundle, "verify", return_value=DIGEST), \
                 patch.object(entry.private_tls, "private_websocket_connector", return_value=lambda *_a, **_k: None), \
                 patch.object(entry, "PersonalReplay", return_value=replay), \
                 patch.object(entry, "attach_current_worker") as attach, \
                 patch.object(entry, "run", side_effect=("reconnect_exhausted", "grant_inactive")) as run, \
                 patch.object(entry.time, "sleep") as sleep:
                self.assertEqual(entry.main(["--run"]), 0)
                attach.assert_called_once_with()
                self.assertEqual(run.call_count, 2)
                sleep.assert_called_once_with(60)

        def test_failed_dispatcher_starts_fresh_worker_and_revocation_stops(self):
            package = types.ModuleType("websockets")
            package.__path__ = []
            sync = types.ModuleType("websockets.sync")
            sync.__path__ = []
            client = types.ModuleType("websockets.sync.client")
            client.connect = lambda *_a, **_k: None
            replay = types.SimpleNamespace(claim=lambda _id: True)
            modules = {"websockets": package, "websockets.sync": sync, "websockets.sync.client": client}
            with patch.dict(sys.modules, modules), patch.object(sys, "path", list(sys.path)), \
                 patch.object(entry, "load_ca", return_value=CA), patch.object(entry.bundle, "verify", return_value=DIGEST), \
                 patch.object(entry.private_tls, "private_websocket_connector", return_value=lambda *_a, **_k: None), \
                 patch.object(entry, "PersonalReplay", return_value=replay), \
                 patch.object(entry, "attach_current_worker") as attach, \
                 patch.object(entry, "run", side_effect=("dispatcher_failed", "grant_inactive")) as run, \
                 patch.object(entry.time, "sleep") as sleep:
                self.assertEqual(entry.main(["--run"]), 0)
                attach.assert_called_once_with()
                self.assertEqual(run.call_count, 2)
                self.assertIs(run.call_args_list[0].kwargs['claim_call'], replay.claim)
                self.assertIs(run.call_args_list[1].kwargs['claim_call'], replay.claim)
                sleep.assert_called_once_with(60)

        def test_registration_reloads_changed_config_and_restores_on_startup_failure(self):
            package = types.ModuleType('websockets'); package.__path__ = []
            sync = types.ModuleType('websockets.sync'); sync.__path__ = []
            client = types.ModuleType('websockets.sync.client'); client.connect = lambda *_a, **_k: None
            modules = {'websockets': package, 'websockets.sync': sync, 'websockets.sync.client': client}
            private = self.base / entry.APP_NAME / 'worker-private'
            config_path = private / 'device.json'
            old_raw = config_path.read_bytes()
            paired = Paired('windows-personal', DEVICE, TOKEN, 'wss://hermes.mikemoore.top/ws')
            next_raw = config.prepare_config(paired, owner_sid=SID, release_sha='d' * 40, ca=CA,
                bundle_sha256=DIGEST, now=1000, profile='owner-projects',
                roots=(r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\example'), seal=lambda *_a, **_k: b's' * 64)
            seen = []
            def fake_run(raw, **_kwargs):
                seen.append(raw)
                if len(seen) == 1:
                    config_path.write_bytes(next_raw)
                    return 'reload_requested'
                if len(seen) == 2:
                    raise ValueError('synthetic startup failure')
                return 'grant_inactive'
            def restore(_private, _sid, current, previous):
                self.assertEqual(config_path.read_bytes(), current)
                config_path.write_bytes(previous)
                return 'project-registration-' + 'a' * 32
            with patch.dict(sys.modules, modules), patch.object(sys, 'path', list(sys.path)), \
                 patch.object(entry, 'load_ca', return_value=CA), patch.object(entry.bundle, 'verify', return_value=DIGEST), \
                 patch.object(entry.private_tls, 'private_websocket_connector', return_value=lambda *_a, **_k: None), \
                 patch.object(entry, 'PersonalReplay', return_value=types.SimpleNamespace(claim=lambda _id: True)), \
                 patch.object(entry, 'current_sid', return_value=SID), patch.object(entry.config, 'unseal', return_value=TOKEN), \
                 patch.object(entry, 'attach_current_worker'), patch.object(entry, 'commit_config', side_effect=restore) as rollback, \
                 patch.object(entry, 'run', side_effect=fake_run), patch.object(entry.time, 'sleep'):
                self.assertEqual(entry.main(['--run']), 0)
            self.assertEqual(seen, [old_raw, next_raw, old_raw])
            rollback.assert_called_once_with(private, SID, next_raw, old_raw)
            self.assertEqual(config_path.read_bytes(), old_raw)
