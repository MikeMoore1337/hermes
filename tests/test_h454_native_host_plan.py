"""Hermes #454 native SSH forced command: disposable READ-ONLY fixtures.

No real GitHub Actions secrets, private SSH keys, VPS account changes,
systemd, owner production roots, network, shell, or host installation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native_host_plan as hostplan
from device_fabric.native_install_preview import SERVICE, SCHEMA


RELEASE = "a" * 40
ARTIFACT = "b" * 64


def candidate(root: Path, target: str = "hermes-vps") -> bytes:
    service, user = SERVICE[target]
    return json.dumps({
        "schema": SCHEMA, "target": target, "release_sha": RELEASE,
        "artifact_sha256": ARTIFACT, "service_name": service,
        "service_identity": user, "start_state": "DISABLED",
        "access_mode": "READ_ONLY",
        "roots": [{"project":"hermes", "path":str(root)}],
    }, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def command(raw: bytes, *, target: str = "hermes-vps",
            release: str = RELEASE, digest: str | None = None) -> str:
    return "h454-native-plan-v1 %s %s %s" % (
        target, release, hashlib.sha256(raw).hexdigest() if digest is None else digest)


class SSHForcedCommandPureContracts(unittest.TestCase):
    def test_syntactic_proof_is_read_only_not_install_permission(self):
        output = hostplan.inspect_request(
            hostplan.PROOF, host_target="hermes-vps",
            installed_source_sha="", manifest_bytes=b"")
        self.assertEqual(output["status"], "FORCED_COMMAND_PROOF_READONLY")
        self.assertFalse(output["changes_applied"])
        self.assertFalse(output["install_authorized"])

    def test_refuses_any_shell_command_or_install_attempt(self):
        raw = b"fake"
        attacks = (
            "", "sudo systemctl start hermes-commander-native",
            "h454-native-install-v1", "h454-native-plan-v1",
            "h454-native-plan-v1 hermes-vps "+RELEASE+" "+ARTIFACT+";id",
            "h454-native-plan-v1 hermes-vps "+RELEASE+" "+ARTIFACT+"\nwhoami",
            "h454-native-plan-v1 YFC-VPS "+RELEASE+" "+ARTIFACT,
            "h454-native-plan-v1 hermes-vps "+RELEASE+" "+ARTIFACT+" --apply",
        )
        for text in attacks:
            with self.subTest(value=text[:45]), self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan.inspect_request(
                    text, host_target="hermes-vps",
                    installed_source_sha=RELEASE, manifest_bytes=raw)

    def test_wrong_host_target_release_and_digest_denied_without_file_io(self):
        raw = b"fixture"
        for cmd, target, source in (
            (command(raw), "yfc-vps", RELEASE),
            (command(raw), "hermes-vps", "c"*40),
            (command(raw,digest="b"*64), "hermes-vps", RELEASE),
        ):
            with self.subTest(cmd=cmd[:20]), self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan.inspect_request(cmd, host_target=target,
                                         installed_source_sha=source,
                                         manifest_bytes=raw)

    def test_target_is_only_two_distinct_linux_hosts(self):
        with self.assertRaises(hostplan.NativeHostPlanDenied):
            hostplan.inspect_request(hostplan.PROOF, host_target="windows",
                                     installed_source_sha="", manifest_bytes=b"")

    def test_inactive_root_or_unknown_account_fails_closed(self):
        # Tests never impersonate a real system account. Assert root and
        # unrelated unprivileged identities are denied.
        if hostplan.pwd is None:
            with self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan._uid_ready()
            return
        with patch.object(hostplan.os, "geteuid", return_value=0):
            with self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan._uid_ready()
        class User:
            pw_name = "some-other-service"
            pw_uid = 1234
        with patch.object(hostplan.os, "geteuid", return_value=1234), \
             patch.object(hostplan.pwd, "getpwuid", return_value=User()):
            with self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan._uid_ready()

    def test_forged_ssh_original_command_never_runs_subprocess(self):
        with patch.object(hostplan, "_uid_ready", return_value=None), \
             patch.object(hostplan, "_read_fixed_line", return_value="hermes-vps"), \
             patch("subprocess.Popen", side_effect=AssertionError("no subprocess")):
            with self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan.run_forced_command("h454-native-install-v1")


class ManualNativeWorkflowContract(unittest.TestCase):
    def test_manual_readonly_workflow_has_no_implicit_deployment(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/h454-native-host-plan.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertIn("  contents: read", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("Hermes repository checks", workflow)
        self.assertIn("Hermes Control Center UI", workflow)
        self.assertIn("H454_NATIVE_PLAN_SSH_KEY", workflow)
        self.assertNotIn("HERMES_DEPLOY_KEY", workflow)
        self.assertNotIn("BRC_SESSION_SECRET", workflow)
        self.assertIn("h454-native-proof-v1", workflow)
        self.assertIn("h454-native-plan-v1 $TARGET $SHA $MANIFEST_SHA", workflow)
        self.assertIn("FORCED_COMMAND_UNPROVEN", workflow)
        self.assertIn("install_authorized==false", workflow)
        self.assertIn("changes_applied==false", workflow)
        self.assertNotIn("systemctl", workflow)
        self.assertNotIn("sudo ", workflow)
        self.assertNotIn("useradd", workflow)
        self.assertNotIn("docker ", workflow)
        self.assertNotIn("h454-native-install-v1", workflow)
        self.assertLess(workflow.index("h454-native-proof-v1"),
                        workflow.index("h454-native-plan-v1 $TARGET"))


@unittest.skipUnless(sys.platform == "linux" and
                     platform.machine().lower() in ("x86_64", "aarch64")
                     and hasattr(os, "geteuid") and os.geteuid() != 0,
                     "actual non-root Linux temp-root FD preflight required")
class HostPlanNativeReadOnlyKernelContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-native-host-ssh-plan-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "original-project"
        self.root.mkdir(mode=0o700)
        (self.root / "README.md").write_bytes(b"original-data-never-export")
        self.wire = candidate(self.root)
        self.path = self.base / "candidate.json"
        self.path.write_bytes(self.wire)
        self.path.chmod(0o600)

    def test_real_kernel_verified_original_root_readonly_plan(self):
        cmd = command(self.wire)
        before = (self.root / "README.md").read_bytes()
        result = hostplan.inspect_request(
            cmd, host_target="hermes-vps",
            installed_source_sha=RELEASE, manifest_bytes=self.wire)
        self.assertEqual(result["status"], "READONLY_NATIVE_HOST_PLAN_VERIFIED")
        self.assertEqual(result["roots_checked"], 1)
        self.assertEqual(result["release_sha"], RELEASE)
        self.assertEqual(result["manifest_sha256"],
                         hashlib.sha256(self.wire).hexdigest())
        for key in ("changes_applied", "install_authorized",
                    "owner_approved", "host_service_installed",
                    "native_device_activated"):
            self.assertFalse(result[key])
        self.assertEqual((self.root / "README.md").read_bytes(), before)
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertNotIn("original-data-never-export", json.dumps(result))

    def test_forced_command_uses_local_pinned_target_manifest_and_release(self):
        cmd = command(self.wire)
        pins = iter(["hermes-vps", RELEASE])
        with patch.object(hostplan, "_uid_ready", return_value=None), \
             patch.object(hostplan, "_read_fixed_line",
                          side_effect=lambda *_args: next(pins)), \
             patch.object(hostplan, "_private_manifest",
                          side_effect=lambda _path: self.wire):
            result = hostplan.run_forced_command(cmd)
        self.assertEqual(result["status"], "READONLY_NATIVE_HOST_PLAN_VERIFIED")
        self.assertFalse(result["changes_applied"])

    def test_wrong_private_manifest_scope_rejected_before_kernel_op(self):
        altered = candidate(self.root, target="yfc-vps")
        with self.assertRaises(hostplan.NativeHostPlanDenied):
            hostplan.inspect_request(command(altered), host_target="hermes-vps",
                                     installed_source_sha=RELEASE,
                                     manifest_bytes=altered)

    def test_symlink_root_and_secret_location_denied(self):
        outside = self.base / "secret"
        outside.mkdir()
        link = self.base / "redirect"
        link.symlink_to(outside, target_is_directory=True)
        wire = candidate(link)
        with self.assertRaises(hostplan.NativeHostPlanDenied):
            hostplan.inspect_request(command(wire), host_target="hermes-vps",
                                     installed_source_sha=RELEASE,
                                     manifest_bytes=wire)

    def test_absent_original_root_denied(self):
        missing = self.base / "missing"
        wire = candidate(missing)
        with self.assertRaises(hostplan.NativeHostPlanDenied):
            hostplan.inspect_request(command(wire), host_target="hermes-vps",
                                     installed_source_sha=RELEASE,
                                     manifest_bytes=wire)
        self.assertFalse(missing.exists())

    def test_private_manifest_permission_denied_by_forced_operator(self):
        cmd = command(self.wire)
        self.path.chmod(0o644)
        with patch.object(hostplan, "_uid_ready", return_value=None), \
             patch.object(hostplan, "_read_fixed_line", return_value="hermes-vps"):
            with self.assertRaises(hostplan.NativeHostPlanDenied):
                hostplan.run_forced_command(
                    cmd, manifest_file=self.path)
        self.path.chmod(0o600)

    def test_cli_denies_install_and_uses_sanitized_status(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND":"h454-native-install-v1"}), \
             patch.object(hostplan, "_uid_ready", return_value=None), \
             patch.object(hostplan, "_read_fixed_line",
                          return_value="hermes-vps"), \
             patch("builtins.print") as printed:
            result = hostplan.main()
        self.assertEqual(result, 2)
        response = json.loads(printed.call_args.args[0])
        self.assertEqual(response["status"], "REFUSED")
        self.assertEqual(response["reason"], "NATIVE_PLAN_NO_GO")
        self.assertFalse(response["install_authorized"])
        self.assertNotIn(str(self.root), str(response))

    def test_proof_only_never_reads_manifest_or_original_project(self):
        with patch.object(hostplan, "_uid_ready", return_value=None), \
             patch.object(hostplan, "_read_fixed_line",
                          return_value="hermes-vps"), \
             patch.object(hostplan, "_private_manifest",
                          side_effect=AssertionError("must not read manifest")):
            response = hostplan.run_forced_command(hostplan.PROOF)
        self.assertEqual(response["status"], "FORCED_COMMAND_PROOF_READONLY")

    def test_no_shell_docker_ssh_or_systemd_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("no shell")), \
             patch("subprocess.Popen", side_effect=AssertionError("no child")):
            result = hostplan.inspect_request(
                command(self.wire), host_target="hermes-vps",
                installed_source_sha=RELEASE,
                manifest_bytes=self.wire)
        self.assertEqual(result["status"], "READONLY_NATIVE_HOST_PLAN_VERIFIED")


if __name__ == "__main__":
    unittest.main()
