import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_brc_enrollment import Paired
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_yfc_runner as runner

SID = "S-1-5-21-1-2-3-1001"
DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
CA = b"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
DIGEST = "c" * 64


if os.name == "nt":
    class YfcRunnerTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-yfc-runner-")
            self.addCleanup(self.temp.cleanup)
            self.base = Path(self.temp.name).resolve()
            self.environment = patch.dict(os.environ, {"LOCALAPPDATA": str(self.base)})
            self.environment.start()
            self.addCleanup(self.environment.stop)
            release = self.base / runner.APP_NAME / "release"
            state = self.base / runner.APP_NAME / "adapter-state"
            state.mkdir(parents=True)
            for name in ("runner/node.exe", "runner/h454_windows_personal_adapter_launcher.mjs",
                         "bundle/packages/agent/dist/dispatcher.js",
                         "bundle/packages/agent/dist/core/search-manager.js",
                         "code/scripts/h15_offline_project_import.py"):
                path = release / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic", encoding="ascii")
            search_pin = patch.object(runner, "SEARCH_MANAGER_SHA256", hashlib.sha256(b"synthetic").hexdigest())
            search_pin.start()
            self.addCleanup(search_pin.stop)
            self.paired = Paired("windows-personal", DEVICE, TOKEN, "wss://hermes.mikemoore.top/ws")
            self.raw = config.prepare_config(self.paired, owner_sid=SID, release_sha="d" * 40,
                ca=CA, bundle_sha256=DIGEST, now=1000, profile="yfc-dev", seal=lambda *_a, **_k: b"s" * 64)
            self.args = {"ca": CA, "expected_manifest": b"synthetic", "current_sid": lambda: SID,
                "connector": lambda *_a, **_k: None, "status_factory": lambda *_a: lambda: True,
                "claim_call": lambda _value: True, "attach_job": lambda: None,
                "decrypt": lambda *_a, **_k: TOKEN}

        def test_wires_verified_yfc_profile_to_owned_terminal_and_broker(self):
            calls = []
            class Process:
                def __init__(self, _root, *, command, writable, readonly):
                    self.command = command
                    self._closed = False
                    self._environment = self._job = object()
                    calls.append((command, writable, readonly))
                def poll(self): return 0 if self.command == "exit /b 0" else None
                def close(self): self._closed = True
            def serve(_raw, **kwargs):
                self.assertEqual(kwargs["verify_bundle"](), DIGEST)
                self.assertTrue(kwargs["isolation_verified"]())
                child = kwargs["start_dispatcher"]()
                self.assertTrue(kwargs["isolation_verified"]())
                child.close()
                self.assertFalse(kwargs["isolation_verified"]())
                self.assertIsNotNone(kwargs["import_broker"])
                kwargs["import_broker"].close()
                kwargs["terminal_broker"].close()
                return "synthetic"
            with patch.object(runner.bundle, "verify", return_value=DIGEST), \
                 patch.object(runner, "scan"), patch.object(runner, "YfcDevPsecTerminal", Process), \
                 patch.object(runner.worker, "serve", side_effect=serve):
                self.assertEqual(runner.run(self.raw, **self.args), "synthetic")
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], "exit /b 0")
            self.assertIn("--preserve-symlinks", calls[1][0])

        def test_legacy_profile_is_rejected_before_starting_any_process(self):
            raw = config.prepare_config(self.paired, owner_sid=SID, release_sha="d" * 40,
                ca=CA, bundle_sha256=DIGEST, now=1000, seal=lambda *_a, **_k: b"s" * 64)
            with patch.object(runner, "YfcDevPsecTerminal") as process:
                with self.assertRaises(runner.YfcRunnerDenied):
                    runner.run(raw, **self.args)
                process.assert_not_called()

        def test_unverified_bundle_never_starts_the_probe_or_unseals(self):
            with patch.object(runner.bundle, "verify", side_effect=ValueError("synthetic")), \
                 patch.object(runner, "YfcDevPsecTerminal") as process, \
                 patch.object(runner.worker, "serve") as serve:
                with self.assertRaises(runner.YfcRunnerDenied):
                    runner.run(self.raw, **self.args)
                process.assert_not_called()
                serve.assert_not_called()

        def test_failed_psec_probe_is_closed_before_worker_starts(self):
            class Process:
                closed = False
                def __init__(self, *_args, **_kwargs): pass
                def poll(self): return 7
                def close(self): self.closed = True
            probe = Process()
            with patch.object(runner.bundle, "verify", return_value=DIGEST), \
                 patch.object(runner, "YfcDevPsecTerminal", return_value=probe), \
                 patch.object(runner.worker, "serve") as serve:
                with self.assertRaises(runner.YfcRunnerDenied):
                    runner.run(self.raw, **self.args)
                self.assertTrue(probe.closed)
                serve.assert_not_called()

        def test_unpatched_search_manager_never_starts_the_probe(self):
            with patch.object(runner.bundle, "verify", return_value=DIGEST), \
                 patch.object(runner, "SEARCH_MANAGER_SHA256", "0" * 64), \
                 patch.object(runner, "YfcDevPsecTerminal") as process:
                with self.assertRaises(runner.YfcRunnerDenied):
                    runner.run(self.raw, **self.args)
                process.assert_not_called()

        def test_unsafe_shell_path_is_rejected(self):
            with self.assertRaises(runner.YfcRunnerDenied):
                runner._quote(self.base / "%TEMP%")
