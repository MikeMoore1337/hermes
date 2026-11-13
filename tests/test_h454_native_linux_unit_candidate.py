"""H454: inert systemd preflight unit generation on synthetic local inputs.

All tests run without systemd, sudo, service accounts, host SSH,
real original-owner files, secrets, network connections or commands.
No unit can be installed from these Python fixtures.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SERVICE, SCHEMA
from scripts import h454_native_linux_unit_candidate as units

SHA = "a" * 40
PACKAGE_SHA = "b" * 64


def candidate(*, target: str = "hermes-vps",
              roots=None, mode="READ_ONLY", startup="DISABLED") -> bytes:
    if roots is None:
        roots = [
            {"project": "hermes", "path": "/srv/hermes/source"},
            {"project": "financial-horizon", "path": "/opt/financial-horizon"},
        ]
    service, identity = SERVICE[target]
    return json.dumps(
        {
            "schema": SCHEMA, "target": target, "release_sha": SHA,
            "artifact_sha256": PACKAGE_SHA,
            "service_name": service,
            "service_identity": identity,
            "start_state": startup, "access_mode": mode,
            "roots": roots,
        },
        separators=(",", ":"), ensure_ascii=True,
        sort_keys=True,
    ).encode("ascii")


class LinuxUnitSourceOnlyTests(unittest.TestCase):
    def render(self, payload=None, *,
               target="hermes-vps", manifest_sha=None, release_sha=SHA):
        payload = candidate(target=target) if payload is None else payload
        digest = (hashlib.sha256(payload).hexdigest()
                  if manifest_sha is None else manifest_sha)
        return units.render_preflight_unit(
            payload, target=target, release_sha=release_sha,
            manifest_sha256=digest)

    def test_unit_is_inert_oneshot_preflight_and_never_autostarts(self):
        out = self.render()
        self.assertIn("[Unit]", out)
        self.assertIn("[Service]", out)
        # Reject a real section heading, not a harmless comment that
        # happens to mention the syntax by name.
        self.assertNotIn("[Install]", out.splitlines())
        self.assertNotIn("WantedBy=", out)
        self.assertIn("Type=oneshot", out)
        self.assertIn("Restart=no", out)
        self.assertIn("RemainAfterExit=no", out)
        self.assertIn("ExecStart=/usr/bin/python3 -B -m scripts.h454_native_linux_runtime", out)
        self.assertIn("--inspect-root-handles", out)
        self.assertIn("--target hermes-vps", out)
        self.assertIn("--release-sha " + SHA, out)
        self.assertIn("WorkingDirectory=/opt/hermes-commander-native/releases/main-"+SHA, out)
        self.assertNotIn("systemctl ", out)
        self.assertNotIn("useradd ", out)
        self.assertNotIn("sudo ", out)
        self.assertNotIn("ExecStartPre=", out)
        self.assertNotIn("ExecStop=", out)
        self.assertNotIn("Restart=always", out)
        self.assertNotIn("ExecStart=/bin/sh", out)
        self.assertNotIn("docker ", out)

    def test_all_os_resource_and_egress_hardening_is_explicit(self):
        out = self.render()
        required = (
            "User=hermes-commander-native",
            "Group=hermes-commander-native",
            "NoNewPrivileges=yes",
            "RestrictSUIDSGID=no",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any",
            "KillMode=control-group",
            "MemoryMax=256M",
            "TasksMax=24",
            "CPUQuota=25%",
            "TimeoutStartSec=30s",
            "UMask=0077",
            "ReadOnlyPaths=/var/lib/hermes-commander-native",
            "AssertPathExists=/var/lib/hermes-commander-native/manifest.json",
            "AssertPathExists=/var/lib/hermes-commander-native/device.json",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "SystemCallFilter=~@mount @reboot @swap",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item+"\n", out)
        # Preflight READ opens original root handles via openat2(2).
        # The old yes value blocked this syscall (ENOSYS) on the owner VPS.
        self.assertNotIn("RestrictSUIDSGID=yes", out)
        self.assertNotIn("DynamicUser=yes", out)
        self.assertNotIn("ReadWritePaths=", out)
        self.assertNotIn("BindPaths=", out)
        self.assertNotIn("EnvironmentFile=", out)

    def test_offline_root_handle_preflight_keeps_openat2_and_isolation(self):
        for target in ("hermes-vps", "yfc-vps"):
            with self.subTest(target=target):
                out = self.render(candidate(target=target), target=target)
                self.assertIn("--inspect-root-handles", out)
                self.assertIn("RestrictSUIDSGID=no\n", out)
                self.assertNotIn("RestrictSUIDSGID=yes", out)
                for rule in (
                    "User=hermes-commander-native",
                    "Group=hermes-commander-native",
                    "NoNewPrivileges=yes",
                    "CapabilityBoundingSet=\n",
                    "AmbientCapabilities=\n",
                    "PrivateNetwork=yes",
                    "ProtectSystem=strict",
                    "ProtectHome=yes",
                    "PrivateDevices=yes",
                    "PrivateTmp=yes",
                    "SystemCallFilter=~@mount @reboot @swap",
                    "IPAddressDeny=any",
                ):
                    self.assertIn(rule, out)

    def test_exact_package_and_manifest_digest_are_visible_only_as_hash(self):
        payload = candidate()
        digest = hashlib.sha256(payload).hexdigest()
        out = self.render(payload)
        self.assertIn("--manifest-sha256 " + digest, out)
        self.assertNotIn(PACKAGE_SHA, out)
        self.assertNotIn("/srv/hermes/source", out)
        self.assertNotIn("/opt/financial-horizon", out)
        self.assertNotIn("hermes.mikemoore.top", out)
        self.assertNotIn("Authorization", out)
        self.assertNotIn("Bearer ", out)
        self.assertNotIn("token", out)

    def test_both_vps_targets_render_different_exact_target_args(self):
        for target in ("hermes-vps", "yfc-vps"):
            with self.subTest(target=target):
                raw = candidate(target=target)
                unit = self.render(raw, target=target)
                self.assertIn("--target "+target, unit)
                self.assertNotIn("h454-linux-", unit)
                self.assertNotIn("OPENAI_API_KEY", unit)

    def test_forged_or_widened_manifest_fails_closed(self):
        changes = (
            {"access_mode": "WRITE"},
            {"start_state": "ENABLED"},
            {"service_name": "root.service"},
            {"service_identity": "root"},
            {"roots": [{"project": "hermes", "path": "/root"}]},
            {"roots": [{"project": "hermes", "path": "/var/lib/private"}]},
            {"roots": [{"project": "hermes", "path": "/srv/base"},
                       {"project": "financial-horizon", "path": "/srv/base/sub"}]},
            {"approved": True},
            {"install_now": True},
        )
        template = json.loads(candidate())
        for fields in changes:
            with self.subTest(fields=fields):
                raw = json.dumps({**template, **fields}, sort_keys=True,
                                 separators=(",", ":")).encode("ascii")
                with self.assertRaisesRegex(units.NativeUnitDenied, "^native_unit_denied$"):
                    self.render(raw)

    def test_mismatched_hash_release_or_target_denied(self):
        raw = candidate()
        for changes in (
            {"manifest_sha": "c"*64},
            {"manifest_sha": "Z"*64},
            {"release_sha": "c"*40},
            {"target": "yfc-vps"},
            {"target": "windows"},
        ):
            with self.subTest(changes=changes), self.assertRaises(units.NativeUnitDenied):
                self.render(
                    raw, target=changes.get("target", "hermes-vps"),
                    release_sha=changes.get("release_sha", SHA),
                    manifest_sha=changes.get("manifest_sha"))

    def test_noncanonical_and_duplicate_json_never_generate_unit(self):
        raw = candidate()
        cases = (
            b"", b"{}", b"[]", b"\xff", raw+b"\n", b" "+raw,
            raw.replace(b'"schema":', b'"schema":"wrong","schema":', 1),
        )
        for payload in cases:
            with self.subTest(payload=payload[:24]), self.assertRaises(units.NativeUnitDenied):
                self.render(payload)

    @unittest.skipUnless(
        sys.platform == "linux" and shutil.which("systemd-analyze"),
        "requires systemd-analyze on a disposable Linux test runner")
    def test_real_systemd_analyze_accepts_inert_unit_syntax(self):
        # systemd-analyze checks syntax only; it never executes the unit.
        # This is NOT real production host kernel isolation proof.
        with tempfile.TemporaryDirectory(prefix="h454-systemd-verify-") as tmp:
            path = Path(tmp) / units.SERVICE_NAME
            path.write_text(self.render(), encoding="utf-8")
            proc = subprocess.run(
                ["systemd-analyze", "verify", str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
        self.assertEqual(
            proc.returncode, 0,
            "INERT_SYSTEMD_UNIT_SYNTAX_INVALID")

    def test_render_does_not_run_host_commands_or_write_any_files(self):
        with patch("subprocess.run", side_effect=AssertionError("Host command forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("Host process forbidden")), \
             patch("builtins.open", side_effect=AssertionError("IO forbidden")):
            text = self.render()
        self.assertIn("PrivateNetwork=yes", text)


@unittest.skipUnless(sys.platform == "linux", "POSIX private manifest read only")
class LinuxUnitPureCliTests(unittest.TestCase):
    def test_local_private_manifest_cli_only_prints_source(self):
        with tempfile.TemporaryDirectory(prefix="h454-systemd-ci-") as folder:
            file = Path(folder) / "candidate.json"
            body = candidate()
            file.write_bytes(body)
            file.chmod(0o600)
            with patch("builtins.print") as output:
                exit_code = units.main([
                    "--manifest", str(file), "--target", "hermes-vps",
                    "--release-sha", SHA,
                    "--manifest-sha256", hashlib.sha256(body).hexdigest(),
                ])
            self.assertEqual(exit_code, 0)
            unit = output.call_args.args[0]
            self.assertIn("Type=oneshot", unit)
            self.assertNotIn("[Install]", unit.splitlines())
            self.assertNotIn(str(file), unit)

    def test_untrusted_manifest_is_denied_before_rendering(self):
        with tempfile.TemporaryDirectory(prefix="h454-systemd-ci-") as folder:
            file = Path(folder) / "candidate.json"
            file.write_bytes(candidate())
            file.chmod(0o644)
            with patch("builtins.print") as output:
                exit_code = units.main([
                    "--manifest", str(file), "--target", "hermes-vps",
                    "--release-sha", SHA,
                    "--manifest-sha256", hashlib.sha256(candidate()).hexdigest(),
                ])
            self.assertEqual(exit_code, 2)
            self.assertEqual(output.call_args.args[0],
                             "H454_NATIVE_PREFLIGHT_UNIT=HOLD")


if __name__ == "__main__":
    unittest.main()
