"""H454 real one-shot owner-paired Windows native READ worker contracts.

Disposable Windows GitHub runner tests actual process-token SID refusal.
Positive WSS protocol tests are fully synthetic: they do NOT read original
projects or contact the owner's Hermes relay.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import unittest
from unittest.mock import Mock, patch

from device_fabric import windows_native_reenrollment as admission
from scripts import h454_native_win32_worker as worker
from tests.test_h454_windows_native_reenrollment import (
    BEARER, DEVICE, RELEASE, SEALED, manifest, config,
)

NOW = int(time.time())


class NoHostWorkerSecurity(unittest.TestCase):
    def setUp(self):
        self.manifest = manifest()
        self.config = config(expiry=NOW + 200)
        self.source = Mock(side_effect=lambda path, limit: (
            self.manifest if path == worker.MANIFEST else self.config
            if path == worker.CONFIG else (_ for _ in ()).throw(
                AssertionError("untrusted file path"))
        ))
        self.sid = Mock(return_value=True)
        self.unseal = Mock(return_value=BEARER)
        self.active = Mock(return_value=True)
        self.status = Mock(return_value=self.active)
        self.transport = Mock()

    def call(self, **override):
        kwargs = {
            "expected_release": RELEASE,
            "sid_gate": self.sid,
            "source_reader": self.source,
            "unseal": self.unseal,
            "owner_status": self.status,
            "connector": self.transport,
        }
        with patch.object(worker.sys, "platform", "win32"):
            return worker.run_trusted_once(**{**kwargs, **override})

    def test_binds_live_owner_status_and_dpapi_to_actual_read_session(self):
        with patch.object(worker, "read_session", return_value="idle_timeout") as read:
            outcome = self.call()
        self.assertEqual(outcome, "idle_timeout")
        candidate = read.call_args.args[0]
        self.assertIsInstance(candidate, admission.PrivateWindowsSession)
        self.assertEqual(candidate.device_id, DEVICE)
        self.assertEqual(candidate.sealed_bearer, SEALED)
        self.assertEqual(read.call_args.kwargs["connector"], self.transport)
        self.assertEqual(self.source.call_count, 2)
        self.source.assert_any_call(worker.MANIFEST, worker.MAX_MANIFEST)
        self.source.assert_any_call(worker.CONFIG, worker.MAX_CONFIG)
        self.status.assert_called_once_with(
            target="windows", device_id=DEVICE,
            bearer=BEARER, base_url=worker.PUBLIC)
        self.unseal.assert_called_once_with(
            SEALED, manifest_sha256=hashlib.sha256(self.manifest).hexdigest(),
            device_id=DEVICE)
        self.assertGreaterEqual(self.sid.call_count, 2)
        self.assertTrue(read.call_args.kwargs["service_os_verified"]())
        self.assertTrue(read.call_args.kwargs["owner_pair_verified"]())
        self.assertFalse(read.call_args.kwargs["is_device_revoked"]())

    def test_missing_real_os_sid_refuses_without_reading_file_or_network(self):
        with patch.object(worker, "read_session") as session:
            with self.assertRaises(worker.Win32WorkerDenied):
                self.call(sid_gate=lambda: False)
            session.assert_not_called()
        self.source.assert_not_called()
        self.unseal.assert_not_called()
        self.status.assert_not_called()

    def test_forged_config_and_manifest_or_expired_bearer_fail_closed(self):
        for changed in (
            b'{}', self.config + b'\n',
            self.config.replace(b'"release_sha":', b'"release_sha":"f","release_sha":', 1),
            config(device=admission.REVOKED_LEGACY_ID, expiry=NOW+200),
            config(expiry=NOW - 1),
            config(expiry=NOW + 4000),
        ):
            with self.subTest(config=changed[:70]):
                self.source.side_effect = lambda path, size: (
                    self.manifest if path == worker.MANIFEST else changed)
                with patch.object(worker, "read_session") as session, \
                     self.assertRaises(worker.Win32WorkerDenied):
                    self.call()
                session.assert_not_called()

    def test_owner_revocation_refuses_before_websocket_connect(self):
        with patch.object(worker, "read_session") as session:
            self.active.return_value = False
            with self.assertRaises(worker.Win32WorkerDenied):
                self.call()
            session.assert_not_called()
        self.transport.assert_not_called()
        self.assertGreaterEqual(self.active.call_count, 1)

    def test_wrong_os_gate_after_read_denied_before_unseal(self):
        self.sid.side_effect = [True, False]
        with patch.object(worker, "read_session") as session, \
             self.assertRaises(worker.Win32WorkerDenied):
            self.call()
        session.assert_not_called()
        self.unseal.assert_not_called()

    def test_dpapi_secret_and_status_provider_exceptions_are_sanitized(self):
        secret = BEARER + " C:\\private"
        for label, override in (
            ("dpapi", {"unseal": Mock(side_effect=OSError(secret))}),
            ("status", {"owner_status": Mock(side_effect=OSError(secret))}),
        ):
            with self.subTest(label=label), self.assertRaises(
                worker.Win32WorkerDenied
            ) as exc:
                self.call(**override)
            self.assertEqual(str(exc.exception), "native_win32_worker_denied")
            self.assertNotIn(BEARER, str(exc.exception))

    def test_actual_brc_wss_hello_is_fresh_and_bounded_under_worker(self):
        class Socket:
            def __init__(self):
                self.sent = []
                self.reads = 0
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.closed = True

            def send(self, data):
                self.sent.append(json.loads(data))

            def recv(self, timeout=None):
                self.reads += 1
                if self.reads == 1:
                    return json.dumps({
                        "type": "welcome", "protocol": 1,
                        "relayVersion": "test", "serverTime": NOW,
                    })
                raise TimeoutError()

        socket = Socket()
        self.transport.side_effect = lambda *_args, **_kwargs: socket
        outcome = self.call()
        self.assertEqual(outcome, "idle_timeout")
        self.assertTrue(socket.closed)
        self.assertEqual(len(socket.sent), 1)
        hello = socket.sent[0]
        self.assertEqual(hello["device"]["name"], "H454 Windows native read-only")
        self.assertEqual(hello["device"]["deviceId"], DEVICE)
        self.assertEqual([t["name"] for t in hello["tools"]],
            ["native_file_stat", "native_file_read", "native_file_list"])
        self.assertNotIn("start_process", json.dumps(hello))
        self.assertNotIn("write_file", json.dumps(hello))
        self.assertNotIn(BEARER, json.dumps(socket.sent))

    def test_read_after_brc_revocation_never_reaches_native_file_handler(self):
        class Socket:
            def __init__(self):
                self.sent = []
                self.closed = False
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.closed = True

            def send(self, data):
                self.sent.append(json.loads(data))

            def recv(self, timeout=None):
                self.reads += 1
                if self.reads == 1:
                    return json.dumps({"type":"welcome","protocol":1,
                        "relayVersion":"test","serverTime":NOW})
                return json.dumps({"type":"call","id":"sensitive-read",
                                   "tool":"native_file_read",
                                   "args":{"project":"hermes","relative":"README.md"}})

        socket = Socket()
        self.transport.side_effect = lambda *_a, **_k: socket
        # Several pre-flight active checks occur, then after the first WSS
        # receive returns a native READ request, revoke immediately.
        self.active.side_effect = lambda: socket.reads < 2
        with patch(
            "scripts.h15_native_windows_mcp_stdio.native.handle_native_request"
        ) as original_read:
            with self.assertRaises(worker.Win32WorkerDenied):
                self.call()
            original_read.assert_not_called()
        self.assertTrue(socket.closed)

    def test_public_cli_rejects_unapproved_windows_host_launcher(self):
        with patch.object(worker, "service_sid_verified", return_value=False), \
             patch.object(worker.sys, "platform", "win32"), \
             patch.object(worker, "run_trusted_once",
                          wraps=worker.run_trusted_once):
            self.assertEqual(worker.main([
                "--run-once", "--release-sha", RELEASE
            ]), 2)
        with self.assertRaises(SystemExit):
            worker.main([
                "--run-once", "--release-sha", RELEASE,
                "--token", BEARER,
            ])


class Win32KernelIdentityNegative(unittest.TestCase):
    def test_disposable_runner_is_not_the_owner_service_identity(self):
        # The actual GitHub-hosted Windows user is NOT the target
        # NT SERVICE\\HermesCommanderNative. No token is provisioned.
        if sys.platform == "win32":
            self.assertFalse(worker.service_sid_verified())
        else:
            self.assertFalse(worker.service_sid_verified())


if __name__ == "__main__":
    unittest.main()
