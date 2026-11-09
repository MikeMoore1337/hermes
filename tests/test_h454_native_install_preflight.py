"""H454: synthetic candidate install preflight and real Linux metadata-only tests.

These tests never install services, mount owner folders, request host keys,
execute owner Windows commands or touch production. The source-root fixtures
are always disposable temporary directories belonging to the test runner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import (
    InstallPlanDenied, parse_candidate, preview, inspect_linux_roots,
    WINDOWS_ROOTS, SCHEMA, SERVICE,
)
from scripts.h454_native_install_preflight import execute, main, _private_manifest

RELEASE = "a" * 40
ARTIFACT = "b" * 64


def manifest(target: str, roots: list[dict[str, str]]) -> bytes:
    service, identity = SERVICE[target]
    data = {
        "schema": SCHEMA, "target": target, "release_sha": RELEASE,
        "artifact_sha256": ARTIFACT, "service_name": service,
        "service_identity": identity, "start_state": "DISABLED",
        "access_mode": "READ_ONLY", "roots": roots,
    }
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def windows_manifest() -> bytes:
    return manifest("windows", [
        {"project": project, "path": path}
        for project, path in WINDOWS_ROOTS.items()
    ])


class CandidateParsingContracts(unittest.TestCase):
    def test_windows_five_exact_owner_read_roots_and_disabled_service(self):
        parsed = parse_candidate(windows_manifest(), expected_release=RELEASE,
                                 expected_target="windows")
        result = preview(parsed)
        self.assertEqual(result["status"], "CANDIDATE_SYNTAX_VALID")
        self.assertEqual(result["roots_count"], 5)
        self.assertEqual(result["start_state"], "DISABLED")
        self.assertEqual(result["access_mode"], "READ_ONLY")
        self.assertEqual(result["original_paths"], "REDACTED")
        self.assertFalse(result["install_authorized"])
        self.assertFalse(result["owner_operation_approved"])
        self.assertFalse(result["release_deploy_approved"])
        self.assertFalse(result["changes_applied"])
        self.assertNotIn("D:\\", str(result))

    def test_relaxed_windows_root_or_parent_never_allowed(self):
        good = json.loads(windows_manifest())
        for altered in (
            {**good, "roots": good["roots"][:-1]},
            {**good, "roots": [
                {"project": "hermes", "path": "D:\\Pet-projects"}]},
            {**good, "roots": [
                dict(root, path="D:\\Pet-projects\\hermes\\..")
                if root["project"] == "hermes" else root
                for root in good["roots"]]},
            {**good, "roots": [
                dict(root, path="D:\\Pet-projects\\second-brain-workspace")
                if root["project"] == "second-brain" else root
                for root in good["roots"]]},
        ):
            with self.subTest(roots=altered["roots"]):
                raw = json.dumps(altered, sort_keys=True,
                                 separators=(",", ":")).encode()
                with self.assertRaises(InstallPlanDenied):
                    parse_candidate(raw, expected_release=RELEASE,
                                    expected_target="windows")

    def test_window_service_user_and_disabled_mode_are_fixed(self):
        for field, value in (
            ("service_name", "LocalSystem"),
            ("service_identity", "NT AUTHORITY\\SYSTEM"),
            ("start_state", "ENABLED"), ("access_mode", "WRITE")):
            with self.subTest(field=field):
                data = json.loads(windows_manifest())
                data[field] = value
                raw = json.dumps(data, sort_keys=True,
                                 separators=(",", ":")).encode()
                with self.assertRaises(InstallPlanDenied):
                    parse_candidate(raw, expected_release=RELEASE,
                                    expected_target="windows")

    def test_candidate_scope_cannot_be_supplied_as_owner_approval(self):
        for injected in ("owner_approved", "deploy", "install", "sudo",
                         "ssh_key", "password", "network_mode"):
            with self.subTest(field=injected):
                data = json.loads(windows_manifest())
                data[injected] = True
                raw = json.dumps(data, sort_keys=True,
                                 separators=(",", ":")).encode()
                with self.assertRaises(InstallPlanDenied):
                    parse_candidate(raw, expected_release=RELEASE,
                                    expected_target="windows")

    def test_release_sha_artifact_sha_and_target_pinned_by_operator(self):
        good = windows_manifest()
        for release, target in (
            ("0" * 40, "windows"), ("c" * 40, "windows"),
            (RELEASE, "yfc-vps"), (RELEASE, "hermes-vps"),
        ):
            with self.subTest(release=release,target=target):
                with self.assertRaises(InstallPlanDenied):
                    parse_candidate(good, expected_release=release,
                                    expected_target=target)
        data = json.loads(good)
        data["artifact_sha256"] = "0" * 64
        with self.assertRaises(InstallPlanDenied):
            parse_candidate(json.dumps(data, sort_keys=True,
                                       separators=(",", ":")).encode(),
                            expected_release=RELEASE, expected_target="windows")

    def test_duplicate_keys_unknown_shapes_and_noncanonical_encoding_denied(self):
        raw = windows_manifest()
        duplicates = raw.replace(b'"schema":', b'"schema":"bad","schema":', 1)
        for bad in (duplicates, b" " + raw, raw + b"\n", b"{}", b"[]",
                    b"", b"\xff", raw * 100):
            with self.subTest(data=bad[:30]), self.assertRaisesRegex(
                    InstallPlanDenied, "^native_install_plan_denied$"):
                parse_candidate(bad, expected_release=RELEASE,
                                expected_target="windows")

    def test_linux_root_lexical_confinement(self):
        good = manifest("hermes-vps", [
            {"project": "hermes", "path": "/srv/hermes/source"},
            {"project": "financial-horizon", "path": "/opt/financial-horizon"},
        ])
        parsed = parse_candidate(good, expected_release=RELEASE,
                                 expected_target="hermes-vps")
        self.assertEqual(len(parsed.roots), 2)
        self.assertFalse(preview(parsed)["os_isolation_verified"])
        badpaths = (
            "/", "//srv/code", "srv/code", "/srv/../etc",
            "/srv/./code", "/srv//code", "/srv/code/",
            "/root/project", "/etc/project", "/proc/self",
            "/var/lib/private", "/dev/shm/project",
            "/srv/credentials", "/srv/.git",
            "/srv/.env", "/srv/vault", "/srv/foo\\bar",
            "/srv/foo\x00bar", "/srv/cafe\u0301",
        )
        for path in badpaths:
            with self.subTest(path=path), self.assertRaises(InstallPlanDenied):
                parse_candidate(manifest("hermes-vps", [
                    {"project": "hermes", "path": path}]),
                    expected_release=RELEASE, expected_target="hermes-vps")

    def test_linux_overlapping_roots_and_duplicate_projects_denied(self):
        cases = (
            [("hermes", "/srv/base"), ("financial-horizon", "/srv/base/sub")],
            # Intermediate lexicographic name can hide nested roots from
            # sorted-neighbor-only overlap checks.
            [("hermes", "/srv/base"),
             ("ai-development-toolkit", "/srv/base-other"),
             ("financial-horizon", "/srv/base/sub")],
            [("hermes", "/srv/base"), ("hermes", "/srv/other")],
            [("hermes", "/srv/base"), ("financial-horizon", "/srv/base")],
        )
        for pair in cases:
            with self.subTest(pair=pair), self.assertRaises(InstallPlanDenied):
                parse_candidate(manifest("yfc-vps", [
                    {"project": project, "path": path}
                    for project, path in pair]),
                    expected_release=RELEASE, expected_target="yfc-vps")

    def test_linux_root_paths_are_not_sent_to_sanitized_preview(self):
        candidate = parse_candidate(manifest("yfc-vps", [
            {"project": "your-fitness-coach",
             "path": "/srv/unpublished-private-checkout"}]),
            expected_release=RELEASE, expected_target="yfc-vps")
        report = preview(candidate)
        self.assertNotIn("unpublished-private-checkout", repr(report))
        self.assertEqual(report["roots_count"], 1)
        self.assertFalse(report["install_authorized"])


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "geteuid")
                     and os.geteuid() != 0,
                     "real non-root Linux disposable test required")
class LinuxReadOnlyHostPreflight(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-native-install-ci-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.project = self.dir / "original-fixture"
        self.project.mkdir(mode=0o700)
        (self.project / "README.md").write_text("private original\n", encoding="utf-8")
        self.manifest_path = self.dir / "candidate.json"

    def candidate(self, root: Path | None = None):
        raw = manifest("hermes-vps", [
            {"project": "hermes", "path": str(self.project if root is None else root)}])
        return parse_candidate(raw, expected_release=RELEASE,
                               expected_target="hermes-vps")

    def write_manifest(self, root: Path | None = None):
        self.manifest_path.write_bytes(manifest("hermes-vps", [
            {"project": "hermes",
             "path": str(self.project if root is None else root)}]))
        self.manifest_path.chmod(0o600)
        return self.manifest_path

    def test_real_original_kernel_handle_stat_without_reading_contents(self):
        before = (self.project / "README.md").read_bytes()
        result = inspect_linux_roots(self.candidate())
        self.assertEqual(result["status"], "LOCAL_DIRECTORY_HANDLES_PASS")
        self.assertEqual(result["roots_checked"], 1)
        self.assertFalse(result["native_host_proven"])
        self.assertFalse(result["install_authorized"])
        self.assertFalse(result["changes_applied"])
        self.assertEqual((self.project / "README.md").read_bytes(), before)

    def test_private_local_manifest_and_command_are_read_only(self):
        manifest_path = self.write_manifest()
        before = set(self.dir.iterdir())
        result = execute(manifest=manifest_path, target="hermes-vps",
                         release_sha=RELEASE, verify_local_roots=True)
        self.assertEqual(result["status"], "CANDIDATE_SYNTAX_VALID")
        self.assertEqual(result["local_roots"]["status"],
                         "LOCAL_DIRECTORY_HANDLES_PASS")
        self.assertFalse(result["install_authorized"])
        self.assertFalse(result["changes_applied"])
        self.assertEqual(set(self.dir.iterdir()), before)
        self.assertNotIn(str(self.project), repr(result))

    def test_symlink_redirects_refused_without_disclosing_host_path(self):
        out = self.dir / "outside"
        out.mkdir()
        (out / "sensitive.txt").write_text("DO_NOT_LEAK")
        link = self.dir / "redirect"
        link.symlink_to(out, target_is_directory=True)
        with self.assertRaisesRegex(
                InstallPlanDenied, "^native_install_plan_denied$"):
            inspect_linux_roots(self.candidate(link))
        self.assertEqual((out / "sensitive.txt").read_text(), "DO_NOT_LEAK")

    def test_missing_original_checkout_fails_closed(self):
        missing = self.dir / "missing-fixture"
        with self.assertRaises(InstallPlanDenied):
            inspect_linux_roots(self.candidate(missing))
        self.assertFalse(missing.exists())

    def test_root_exec_identity_is_refused(self):
        with patch("device_fabric.native_install_preview.os.geteuid",
                   return_value=0):
            with self.assertRaises(InstallPlanDenied):
                inspect_linux_roots(self.candidate())

    def test_symlink_manifest_and_group_world_readable_manifest_denied(self):
        self.write_manifest()
        self.manifest_path.chmod(0o644)
        with self.assertRaises(InstallPlanDenied):
            _private_manifest(self.manifest_path)
        self.manifest_path.chmod(0o600)
        link = self.dir / "linked.json"
        link.symlink_to(self.manifest_path)
        with self.assertRaises(InstallPlanDenied):
            _private_manifest(link)
        self.assertTrue(self.manifest_path.exists())

    def test_manifest_symlink_parent_refused_without_private_contents(self):
        manifest_path = self.write_manifest()
        redirect = self.dir / "linked-parent"
        redirect.symlink_to(self.dir, target_is_directory=True)
        with self.assertRaisesRegex(
                InstallPlanDenied, "^native_install_plan_denied$"):
            _private_manifest(redirect / manifest_path.name)
        self.assertEqual(_private_manifest(manifest_path),
                         manifest_path.read_bytes())

    def test_manifest_chmod_race_between_lstat_and_open_denied(self):
        # A private manifest may become world-readable after path lstat.
        # Its mode must be verified on the actual OPEN file handle as well.
        manifest_path = self.write_manifest()
        raw_open = os.open
        races = []

        def race(path, flags, *args, **kwargs):
            races.append(True)
            manifest_path.chmod(0o644)
            return raw_open(path, flags, *args, **kwargs)

        with patch("scripts.h454_native_install_preflight.os.open",
                   side_effect=race):
            with self.assertRaisesRegex(
                    InstallPlanDenied, "^native_install_plan_denied$"):
                _private_manifest(manifest_path)
        self.assertEqual(len(races), 1)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o644)
        manifest_path.chmod(0o600)

    def test_manifest_chmod_race_after_open_denied(self):
        manifest_path = self.write_manifest()
        original_read = os.read

        def race(fd, limit):
            data = original_read(fd, limit)
            manifest_path.chmod(0o644)
            return data

        with patch("scripts.h454_native_install_preflight.os.read",
                   side_effect=race):
            with self.assertRaisesRegex(
                    InstallPlanDenied, "^native_install_plan_denied$"):
                _private_manifest(manifest_path)
        manifest_path.chmod(0o600)

    def test_cli_reports_hold_without_paths_on_mismatch(self):
        p = self.write_manifest()
        with patch("builtins.print") as output:
            code = main(["--manifest", str(p), "--target", "yfc-vps",
                         "--release-sha", RELEASE])
        self.assertEqual(code, 1)
        report = json.loads(output.call_args.args[0])
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["reason"], "NATIVE_INSTALL_PREFLIGHT_DENIED")
        self.assertFalse(report["install_authorized"])
        self.assertFalse(report["changes_applied"])
        self.assertNotIn(str(self.project), repr(report))

    def test_cli_success_does_not_authorize_install(self):
        p = self.write_manifest()
        with patch("builtins.print") as output:
            status = main(["--manifest", str(p), "--target", "hermes-vps",
                           "--release-sha", RELEASE, "--verify-local-roots"])
        self.assertEqual(status, 0)
        report = json.loads(output.call_args.args[0])
        self.assertEqual(report["local_roots"]["status"],
                         "LOCAL_DIRECTORY_HANDLES_PASS")
        self.assertFalse(report["os_isolation_verified"])
        self.assertFalse(report["install_authorized"])
        self.assertFalse(report["changes_applied"])


if __name__ == "__main__":
    unittest.main()
