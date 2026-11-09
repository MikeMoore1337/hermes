"""H454 original Linux native runtime: private-owner config and OS-only fixtures.

Real tests ONLY inspect disposable kernel directory handles and use a
fake WSS connection. No production VPS, original owner checkout, network,
systemd, user provisioning, owner keys or external credential is touched.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SERVICE, SCHEMA as INSTALL_SCHEMA
from device_fabric.linux_native_outbound import ENDPOINT
from scripts import h454_native_linux_runtime as runtime

RELEASE = "a" * 40
ARTIFACT = "b" * 64
TARGET = "hermes-vps"
DEVICE = "h454-linux-hermes-" + "c" * 16
TOKEN = "synthetic-private-fixture-bearer-" + "X" * 55


def canonical(item: object) -> bytes:
    return json.dumps(item, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def candidate_manifest(roots: list[dict[str, str]],
                       target: str = TARGET) -> bytes:
    service, identity = SERVICE[target]
    return canonical({
        "schema": INSTALL_SCHEMA, "target": target,
        "release_sha": RELEASE, "artifact_sha256": ARTIFACT,
        "service_name": service, "service_identity": identity,
        "start_state": "DISABLED", "access_mode": "READ_ONLY",
        "roots": roots,
    })


def config(roots: list[dict[str, str]], manifest_digest: str,
           *, target: str = TARGET, device: str = DEVICE) -> bytes:
    return canonical({
        "schema": runtime.SCHEMA, "target": target,
        "release_sha": RELEASE, "device_id": device,
        "manifest_sha256": manifest_digest, "url": ENDPOINT,
        "token": TOKEN, "roots": roots,
    })


class RuntimeParsingContracts(unittest.TestCase):
    def setUp(self):
        self.roots = [{"project": "hermes", "path": "/srv/source-original"}]
        self.manifest = candidate_manifest(self.roots)
        self.digest = hashlib.sha256(self.manifest).hexdigest()
        from device_fabric.native_install_preview import parse_candidate
        self.candidate = parse_candidate(
            self.manifest, expected_release=RELEASE, expected_target=TARGET)

    def test_exact_protected_snapshot_matches_pinned_local_manifest(self):
        parsed = runtime._parse_config(
            config(self.roots, self.digest), self.candidate)
        self.assertEqual(parsed.device_id, DEVICE)
        self.assertEqual(parsed.target, TARGET)
        self.assertEqual(parsed.url, ENDPOINT)
        self.assertEqual(parsed.token, TOKEN)
        self.assertNotIn(TOKEN, repr(parsed))
        self.assertNotIn(DEVICE, repr(parsed))

    def test_malformed_token_pinning_and_wrong_project_denied(self):
        original = json.loads(config(self.roots, self.digest))
        changes = (
            {"target": "yfc-vps"},
            {"device_id": "h454-linux-yfc-" + "b"*16},
            {"device_id": "h15-hermes-ab005bc0e0ea"},
            {"url": "ws://127.0.0.1/ws"},
            {"url": "wss://other.example/ws"},
            {"release_sha": "c"*40},
            {"manifest_sha256": "e"*64},
            {"token": "short"},
            {"roots": [{"project": "hermes", "path": "/etc"}]},
            {"roots": [{"project": "financial-horizon",
                        "path": "/srv/source-original"}]},
            {"roots": []},
        )
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    runtime.RuntimeDenied, "^native_linux_runtime_denied$"):
                runtime._parse_config(canonical({**original, **changed}),
                                      self.candidate)

    def test_extra_owner_approval_fields_are_never_accepted(self):
        original = json.loads(config(self.roots, self.digest))
        for extra in ("owner_approved", "sudo", "install_now", "access_mode",
                      "command", "service_identity", "host_root",
                      "ssh_private_key", "wss_relay_override"):
            with self.subTest(extra=extra), self.assertRaises(runtime.RuntimeDenied):
                runtime._parse_config(
                    canonical({**original, extra: True}), self.candidate)

    def test_duplicate_noncanonical_and_oversize_secret_configuration_denied(self):
        valid = config(self.roots, self.digest)
        duplicate = valid.replace(b'"token":', b'"token":"other","token":', 1)
        invalid = (b"", b"{}", b"[]", b"\xff", b"\n"+valid,
                   valid+b"\n", duplicate, valid*100)
        for payload in invalid:
            with self.subTest(payload=payload[:25]), self.assertRaises(
                    runtime.RuntimeDenied):
                runtime._parse_config(payload, self.candidate)

    def test_privileged_context_and_missing_service_identity_denied(self):
        with patch.object(runtime.os, "geteuid", return_value=0):
            with self.assertRaises(runtime.RuntimeDenied):
                runtime._service_identity(TARGET)
        with patch.object(runtime, "pwd", None):
            with self.assertRaises(runtime.RuntimeDenied):
                runtime._service_identity(TARGET)


@unittest.skipUnless(
    sys.platform == "linux" and platform.machine().lower() in ("x86_64", "aarch64")
    and hasattr(os, "geteuid") and os.geteuid() != 0,
    "nonroot Linux with actual openat2 required")
class NativeLinuxRuntimeIntegration(unittest.TestCase):
    def setUp(self):
        # Use runner's owned, non-world-writable home instead of /tmp:
        # the strict preflight refuses group/world-writable ancestors.
        temp = tempfile.TemporaryDirectory(
            prefix="h454-native-runtime-fixture-", dir=Path.home())
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.root = self.base / "original"
        self.root.mkdir(mode=0o700)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_bytes(b"# Hermes\nTODO native\n")
        (self.root / ".env").write_bytes(b"SYNTHETIC_PRIVATE=NO_LEAK")
        self.roots = [{"project": "hermes", "path": str(self.root)}]
        self.manifest_data = candidate_manifest(self.roots)
        self.digest = hashlib.sha256(self.manifest_data).hexdigest()
        self.manifest = self.private / "manifest.json"
        self.manifest.write_bytes(self.manifest_data)
        self.manifest.chmod(0o600)
        self.config_path = self.private / "device.json"
        self.config_path.write_bytes(config(self.roots, self.digest))
        self.config_path.chmod(0o600)
        account = SimpleNamespace(
            pw_uid=os.geteuid(), pw_gid=os.getegid(),
            pw_shell="/usr/sbin/nologin")
        self.account = patch.object(runtime.pwd, "getpwnam",
                                    return_value=account)
        self.account.start()
        self.addCleanup(self.account.stop)

    def load(self, *, manifest=None, config_path=None,
             digest=None, target=TARGET, release=RELEASE):
        return runtime.load_local_runtime(
            target=target, expected_release=release,
            expected_manifest_sha256=self.digest if digest is None else digest,
            manifest_path=self.manifest if manifest is None else manifest,
            config_path=self.config_path if config_path is None else config_path)

    def test_load_never_reads_project_source_and_redacts_tokens(self):
        with patch.object(runtime, "run_session", side_effect=AssertionError):
            prepared = self.load()
        self.assertEqual(prepared.project_roots, (("hermes", str(self.root)),))
        self.assertNotIn(TOKEN, repr(prepared))
        self.assertNotIn(str(self.root), repr(prepared))
        self.assertEqual(runtime._preview(prepared)["connected"], False)
        self.assertEqual(runtime._preview(prepared)["root_count"], 1)

    def test_genuine_kernel_root_handle_preflight_metadata_only(self):
        before = (self.root / "README.md").read_bytes()
        p = self.load()
        with patch.object(runtime.LinuxNativeFiles, "read_file",
                          side_effect=AssertionError("No content permitted")):
            report = runtime.local_preflight(p)
        self.assertEqual(report["status"], "LOCAL_ROOT_HANDLES_PASS")
        self.assertEqual(report["roots_checked"], 1)
        self.assertFalse(report["connected"])
        self.assertFalse(report["native_host_pass"])
        self.assertFalse(report["changes_applied"])
        self.assertEqual((self.root / "README.md").read_bytes(), before)

    def test_source_only_cli_preflight_never_installs_or_connects(self):
        options = [
            "--target", TARGET, "--release-sha", RELEASE,
            "--manifest-sha256", self.digest,
            "--manifest", str(self.manifest), "--config", str(self.config_path),
            "--inspect-root-handles",
        ]
        with patch("builtins.print") as output, \
             patch.object(runtime, "run_session",
                          side_effect=AssertionError("Network prohibited")):
            code = runtime.main(options)
        self.assertEqual(code, 0)
        report = json.loads(output.call_args.args[0])
        self.assertEqual(report["status"], "PRIVATE_CONFIG_CONTRACT_VALID")
        self.assertEqual(report["local_roots"]["status"],
                         "LOCAL_ROOT_HANDLES_PASS")
        self.assertFalse(report["owner_authenticated"])
        self.assertFalse(report["os_isolation_verified"])
        self.assertFalse(report["connected"])
        self.assertFalse(report["changes_applied"])
        self.assertNotIn(TOKEN, str(report))
        self.assertNotIn(str(self.root), str(report))

    def test_wrong_manual_manifest_digest_or_release_denied(self):
        for digest, release in (("f"*64, RELEASE), (self.digest, "e"*40)):
            with self.subTest(digest=digest, release=release):
                with self.assertRaises(runtime.RuntimeDenied):
                    self.load(digest=digest, release=release)

    def test_manifest_project_changed_after_owner_review_denied(self):
        new_roots = [{"project": "hermes", "path": str(self.root)},
                     {"project": "financial-horizon", "path": "/srv/foreign"}]
        self.manifest.write_bytes(candidate_manifest(new_roots))
        with self.assertRaises(runtime.RuntimeDenied):
            self.load()

    def test_config_project_changed_while_manifest_unchanged_denied(self):
        payload = json.loads(self.config_path.read_bytes())
        payload["roots"] = [{"project": "hermes", "path": "/etc"}]
        self.config_path.write_bytes(canonical(payload))
        with self.assertRaises(runtime.RuntimeDenied):
            self.load()

    def test_group_world_manifest_or_config_denied(self):
        for item in (self.manifest, self.config_path):
            with self.subTest(item=item.name):
                item.chmod(0o644)
                with self.assertRaises(runtime.RuntimeDenied):
                    self.load()
                item.chmod(0o600)

    def test_unsafe_config_parent_mode_symlink_and_owner_denied(self):
        self.private.chmod(0o755)
        with self.assertRaises(runtime.RuntimeDenied):
            self.load()
        self.private.chmod(0o700)
        alias = self.base / "alias"
        alias.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(runtime.RuntimeDenied):
            self.load(manifest=alias/"manifest.json",
                      config_path=alias/"device.json")

    def test_private_config_malformed_json_returns_sanitized_hold(self):
        self.config_path.write_bytes(b"{'not-json':")
        with patch("builtins.print") as output:
            code = runtime.main([
                "--target", TARGET, "--release-sha", RELEASE,
                "--manifest-sha256", self.digest,
                "--manifest", str(self.manifest),
                "--config", str(self.config_path),
            ])
        self.assertEqual(code, 2)
        report = json.loads(output.call_args.args[0])
        self.assertEqual(report["status"], "HOLD")
        self.assertFalse(report["connected"])
        self.assertFalse(report["changes_applied"])
        self.assertNotIn(str(self.config_path), str(report))

    def test_isolation_or_revocation_failure_refuses_before_network(self):
        prepared = self.load()
        def not_invoked(*args, **kwargs):
            raise AssertionError("network must not be reached")
        for isolation, revoked in (
            (False, False), (None, False), ("true", False),
            (True, True), (True, None),
        ):
            with self.subTest(isolation=isolation, revoked=revoked):
                with self.assertRaises(runtime.RuntimeDenied):
                    runtime.run_once(
                        prepared, connector=not_invoked,
                        is_device_revoked=lambda: revoked,
                        is_os_isolation_verified=lambda: isolation)
        with self.assertRaises(runtime.RuntimeDenied):
            runtime.run_once(prepared, connector=not_invoked,
                             is_device_revoked=None,
                             is_os_isolation_verified=lambda: True)

    def test_injected_failing_revocation_probe_is_sanitized(self):
        prepared = self.load()
        def unavailable():
            raise OSError("SYNTHETIC_PRIVATE_REASON")
        with self.assertRaisesRegex(runtime.RuntimeDenied,
                                    "^native_linux_runtime_denied$"):
            runtime.run_once(
                prepared, connector=lambda *_a, **_kw: None,
                is_device_revoked=unavailable,
                is_os_isolation_verified=lambda: True)

    def test_runtime_error_from_trusted_isolation_callback_is_redacted(self):
        prepared = self.load()
        def broken():
            raise RuntimeError("SYNTHETIC_PRIVATE_EXCEPTION_DETAIL")
        with self.assertRaisesRegex(
                runtime.RuntimeDenied, "^native_linux_runtime_denied$") as denied:
            runtime.run_once(
                prepared, connector=lambda *_a, **_kw: None,
                is_device_revoked=lambda: False,
                is_os_isolation_verified=broken)
        self.assertNotIn("SYNTHETIC_PRIVATE", str(denied.exception))

    def test_full_injected_existing_brc_wire_reads_original_fixture(self):
        prepared = self.load()
        messages = [
            {"type": "welcome", "protocol": 1,
             "relayVersion": "synthetic", "serverTime": 1794250000000},
            {"type": "call", "id": "read-one", "tool": "native_file_read",
             "args": {"project": "hermes", "relative": "README.md"},
             "client": {"name": "chatgpt"}, "timeoutMs": 8000},
        ]
        class FakeWebSocket:
            def __init__(self):
                self.sent = []
                self.incoming = list(messages)
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
            def send(self, msg):
                self.sent.append(json.loads(msg))
            def recv(self, timeout=None):
                if not self.incoming:
                    raise TimeoutError
                return json.dumps(self.incoming.pop(0))
        ws = FakeWebSocket()
        def connector(url, **kwargs):
            self.assertEqual(url, ENDPOINT)
            self.assertTrue(kwargs["additional_headers"]["Authorization"].startswith("Bearer "))
            return ws
        out = runtime.run_once(
            prepared, connector=connector,
            is_device_revoked=lambda: False,
            is_os_isolation_verified=lambda: True)
        self.assertEqual(out, "idle_timeout")
        self.assertEqual([m["type"] for m in ws.sent], ["hello", "result"])
        text = json.loads(ws.sent[-1]["result"]["content"][0]["text"])
        self.assertEqual(base64.b64decode(text["data"]),
                         b"# Hermes\nTODO native\n")
        self.assertNotIn(TOKEN, str(ws.sent))
        self.assertNotIn(str(self.root), str(ws.sent))

    def test_failed_original_symlink_read_never_returns_sensitive_data(self):
        prepared = self.load()
        foreign = self.base / "foreign.md"
        foreign.write_text("SYNTHETIC_PRIVATE_REASON", encoding="utf-8")
        (self.root / "redirect.md").symlink_to(foreign)
        from device_fabric.linux_native_files import NativeLinuxDenied
        with runtime.ExitStack() as stack:
            root_handle = stack.enter_context(runtime.LinuxNativeFiles(
                root=self.root, project="hermes"))
            with self.assertRaises(NativeLinuxDenied):
                root_handle.read_file("redirect.md")
        self.assertEqual(foreign.read_text(), "SYNTHETIC_PRIVATE_REASON")


if __name__ == "__main__":
    unittest.main()
