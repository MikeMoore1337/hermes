"""Hermes #454: new Windows native identity, no revoked legacy pairing.

No network, owner-host files, DPAPI state, service, UAC or registration.
Runs on both the normal repository CI and an isolated Windows runner.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from unittest.mock import Mock, patch

from device_fabric.native_install_preview import SCHEMA as INSTALL, SERVICE, WINDOWS_ROOTS
from device_fabric import windows_native_reenrollment as native
from scripts import h15_native_windows_outbound as outbound

RELEASE = "a" * 40
ARTIFACT = "b" * 64
DEVICE = "h454-win-native-" + "c" * 32
SEALED = b"mock-encrypted-not-a-real-token-" + b"z" * 64
BEARER = "synthetic-not-real-paired-bearer-" + "z" * 50
NOW = 1794300000


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def manifest() -> bytes:
    service, identity = SERVICE["windows"]
    return canonical({
        "schema": INSTALL, "target": "windows", "release_sha": RELEASE,
        "artifact_sha256": ARTIFACT, "service_name": service,
        "service_identity": identity, "start_state": "DISABLED",
        "access_mode": "READ_ONLY",
        "roots": [
            {"project": key, "path": value}
            for key, value in sorted(WINDOWS_ROOTS.items())
        ],
    })


def config(*, device: str = DEVICE, expiry: int = NOW + 200,
           sealed: bytes = SEALED, **extra: object) -> bytes:
    value = {
        "schema": native.SCHEMA, "target": "windows",
        "release_sha": RELEASE,
        "manifest_sha256": hashlib.sha256(manifest()).hexdigest(),
        "device_id": device, "relay_url": native.RELAY,
        "sealed_bearer_b64": base64.b64encode(sealed).decode("ascii"),
        "expires_at": expiry,
    }
    return canonical({**value, **extra})


def candidate() -> native.PrivateWindowsSession:
    m = manifest()
    return native.parse_local_session(
        m, config(), expected_release=RELEASE,
        expected_manifest_sha256=hashlib.sha256(m).hexdigest(),
    )


class NewWindowsIdentityParserTests(unittest.TestCase):
    def parse(self, cfg: bytes, *, manifest_bytes: bytes | None = None,
              pinned: str | None = None) -> native.PrivateWindowsSession:
        m = manifest() if manifest_bytes is None else manifest_bytes
        return native.parse_local_session(
            m, cfg, expected_release=RELEASE,
            expected_manifest_sha256=(
                hashlib.sha256(m).hexdigest() if pinned is None else pinned
            ),
        )

    def test_exact_source_and_owner_read_roots(self):
        prepared = candidate()
        self.assertEqual(prepared.device_id, DEVICE)
        self.assertEqual(prepared.relay_url, native.RELAY)
        self.assertEqual(prepared.sealed_bearer, SEALED)
        self.assertEqual(prepared.expires_at, NOW + 200)
        for secret in (DEVICE, SEALED.decode(), BEARER):
            self.assertNotIn(secret, repr(prepared))
        self.assertNotIn("D:\\Pet-projects", repr(prepared))

    def test_rejects_revoked_identity_and_sandbox_name_reuse(self):
        for invalid in (
            native.REVOKED_LEGACY_ID,
            "h15-win-05be75515428",
            "h15-hermes-ab005bc0e0ea",
            "h454-win-native-" + "f"*16,
            "h454-win-native-" + "G"*32,
            "h454-win-native-" + "x"*32,
            DEVICE.upper(),
        ):
            with self.subTest(id=invalid), self.assertRaises(native.WindowsNativeIdentityDenied):
                self.parse(config(device=invalid))

    def test_untrusted_config_cannot_widen_scopes_or_change_relay(self):
        for mutation in (
            {"target": "yfc-vps"},
            {"relay_url": "ws://127.0.0.1:38183/ws"},
            {"relay_url": "wss://example.org/ws"},
            {"release_sha": "f"*40},
            {"manifest_sha256": "f"*64},
            {"roots": [{"project": "anything", "path": "C:\\Users"}]},
            {"owner_approved": True},
            {"install_now": True},
            {"command": "git status"},
            {"service_identity": "SYSTEM"},
            {"expires_at": True},
            {"expires_at": 0},
            {"sealed_bearer_b64": "%%%"},
            {"sealed_bearer_b64": base64.b64encode(b"bad").decode()},
        ):
            with self.subTest(mutation=str(mutation)[:100]), \
                 self.assertRaises(native.WindowsNativeIdentityDenied):
                self.parse(config(**mutation))

    def test_rejects_invalid_manifest_digest_and_extra_privileged_roots(self):
        m = manifest()
        with self.assertRaises(native.WindowsNativeIdentityDenied):
            self.parse(config(), pinned="f"*64)
        original = json.loads(m)
        original["roots"].append({"project": "private", "path": "C:\\Users"})
        with self.assertRaises(native.WindowsNativeIdentityDenied):
            self.parse(config(), manifest_bytes=canonical(original))
        original = json.loads(m)
        original["start_state"] = "ENABLED"
        with self.assertRaises(native.WindowsNativeIdentityDenied):
            self.parse(config(), manifest_bytes=canonical(original))

    def test_rejects_duplicate_keys_noncanonical_and_malformed_json(self):
        value = config()
        invalid = (
            b"", b"{}", b"[]", b"\xff", value + b"\n",
            b" " + value, value * 200,
            value.replace(b'"device_id":', b'"device_id":"other","device_id":', 1),
            value.replace(b'"expires_at":', b'"expires_at":NaN,"expires_at":', 1),
        )
        for entry in invalid:
            with self.subTest(size=len(entry)), self.assertRaises(
                native.WindowsNativeIdentityDenied,
            ):
                self.parse(entry)


class NewWindowsIdentityRunTests(unittest.TestCase):
    def setUp(self):
        self.prepared = candidate()
        self.check_os = Mock(return_value=True)
        self.check_owner = Mock(return_value=True)
        self.check_revoked = Mock(return_value=False)
        self.unseal = Mock(return_value=BEARER)
        self.connect = Mock()
        self.kwargs = dict(
            connector=self.connect,
            service_os_verified=self.check_os,
            owner_pair_verified=self.check_owner,
            is_device_revoked=self.check_revoked,
            unseal_bearer=self.unseal,
            utcnow=lambda: NOW,
        )

    def run_win(self, **changes):
        with patch.object(native.sys, "platform", "win32"):
            return native.run_once(self.prepared, **{**self.kwargs, **changes})

    def test_new_identity_calls_existing_read_only_transport_without_reactivating_legacy(self):
        with patch.object(native.outbound, "run_session", return_value="idle_timeout") as run:
            result = self.run_win()
        self.assertEqual(result, "idle_timeout")
        settings, callback = run.call_args.args
        self.assertEqual(settings.device_id, DEVICE)
        self.assertEqual(settings.device_token, BEARER)
        self.assertEqual(settings.websocket_url, native.RELAY)
        self.assertNotIn(BEARER, repr(settings))
        self.assertIs(callback, run.call_args.args[1])
        self.assertEqual(self.unseal.call_args.args, (SEALED,))
        self.assertGreaterEqual(self.check_revoked.call_count, 2)

    def test_preconnect_gates_deny_before_unsealing_or_network(self):
        for gate in ("service_os_verified", "owner_pair_verified", "is_device_revoked"):
            with self.subTest(gate=gate):
                unseal = Mock(return_value=BEARER)
                run = Mock(return_value="idle_timeout")
                failing = Mock(return_value=(True if gate == "is_device_revoked" else False))
                with patch.object(native.outbound, "run_session", run):
                    with self.assertRaises(native.WindowsNativeIdentityDenied):
                        self.run_win(**{gate: failing, "unseal_bearer": unseal})
                unseal.assert_not_called()
                run.assert_not_called()

    def test_expiry_or_invalid_token_refuses_before_any_transport(self):
        for token in ("short", "", "bad token", "x"*257, None):
            with self.subTest(token=repr(token)), \
                 patch.object(native.outbound, "run_session") as run:
                with self.assertRaises(native.WindowsNativeIdentityDenied):
                    self.run_win(unseal_bearer=lambda _blob: token)
                run.assert_not_called()
        for now in (NOW + 200, NOW - 4000, float("nan"), True):
            with self.subTest(now=now), \
                 patch.object(native.outbound, "run_session") as run:
                with self.assertRaises(native.WindowsNativeIdentityDenied):
                    self.run_win(utcnow=lambda: now)
                run.assert_not_called()

    def test_linux_never_executes_win32_session(self):
        if sys.platform == "win32":
            self.skipTest("Linux denial covered in repository CI")
        with patch.object(native.outbound, "run_session") as run:
            with self.assertRaises(native.WindowsNativeIdentityDenied):
                native.run_once(self.prepared, **self.kwargs)
            run.assert_not_called()

    def test_guarded_websocket_refuses_revoke_or_expiry_mid_session(self):
        class FakeSocket:
            def __init__(self):
                self.sent = []
                self.received = 0
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def send(self, frame):
                self.sent.append(json.loads(frame))
            def recv(self, timeout=None):
                self.received += 1
                if self.received == 1:
                    return json.dumps({"type": "welcome", "protocol": 1,
                                       "relayVersion": "test", "serverTime": NOW})
                return json.dumps({"type": "call", "id": "c1",
                                   "tool": "native_file_read",
                                   "args": {"project": "hermes", "relative": "README.md"}})
        socket = FakeSocket()
        revoked = [False]
        self.check_revoked.side_effect = lambda: revoked[0]
        with patch.object(native.outbound, "run_session", wraps=outbound.run_session):
            with patch("scripts.h15_native_windows_mcp_stdio.native.handle_native_request") as file_read:
                def connector(*_args, **_kwargs):
                    return socket
                self.check_revoked.side_effect = lambda: (
                    False if socket.received == 0 else True
                )
                with self.assertRaises(native.WindowsNativeIdentityDenied):
                    self.run_win(connector=connector)
                file_read.assert_not_called()
        self.assertTrue(socket.closed)
        self.assertEqual([x["type"] for x in socket.sent], ["hello"])

    def test_fail_closed_when_trusted_callback_crashes_no_secret_in_exception(self):
        secret = BEARER + " C:\\private"
        def bad(_blob):
            raise OSError(secret)
        with self.assertRaises(native.WindowsNativeIdentityDenied) as exc:
            self.run_win(unseal_bearer=bad)
        self.assertEqual(str(exc.exception), "native_win32_identity_denied")
        self.assertNotIn(BEARER, str(exc.exception))
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
