"""Hermes H454: deterministic source-only Linux native READ archive QA.

Git repositories, tarballs and private output locations below are disposable
test fixtures. Nothing accesses owner projects, SSH, production VPS, keys,
MCP service accounts, or executable native device sessions.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native_readonly_bundle as bundle

SHA = "a" * 40
TARGET = "hermes-vps"


def fixture_sources() -> dict[str, bytes]:
    return {
        path: ("# selected SOURCE fixture: " + path + "\n").encode("ascii")
        for path in bundle.SOURCE_FILES
    }


def retarget_receipt(receipt: bytes, new_bundle: bytes) -> bytes:
    value = json.loads(receipt)
    value["bundle_sha256"] = hashlib.sha256(new_bundle).hexdigest()
    return bundle._json(value)


class SourceBundleWorkflowPolicy(unittest.TestCase):
    def test_workflow_is_dispatch_only_no_privileged_transport(self):
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/h454-native-linux-source-bundle.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("refs/heads/main", workflow)
        self.assertIn('"$APPROVED_SHA" == "$EXACT_SHA"', workflow)
        self.assertIn('name=="Hermes repository checks"', workflow)
        self.assertIn('name=="Hermes Control Center UI"', workflow)
        self.assertIn("if-no-files-found: error", workflow)
        for dangerous in (
            "systemctl", "sudo ", "useradd", "ssh -",
            "ssh-keygen", "docker ", "curl ", "scp ",
            "HERMES_DEPLOY_KEY", "HERMES_DEPLOY_TARGET",
            "secrets.", "Authorization: Bearer",
            "--install", "--apply", "service start",
        ):
            with self.subTest(pattern=dangerous):
                self.assertNotIn(dangerous, workflow)

    def test_workflow_uploads_only_two_verified_source_artifacts(self):
        text = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/h454-native-linux-source-bundle.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("scripts.h454_native_readonly_bundle build", text)
        self.assertIn("scripts.h454_native_readonly_bundle verify", text)
        self.assertIn(bundle.ARCHIVE_NAME, text)
        self.assertIn(bundle.RECEIPT_NAME, text)
        self.assertIn("NATIVE_AGENT_INSTALLED=NO", text)
        self.assertIn("OWNER_HOST_CHANGED=NO", text)


class NativeSourceArchivePure(unittest.TestCase):
    def test_exact_allowlist_excludes_write_process_grant_and_host_secrets(self):
        self.assertEqual(len(bundle.SOURCE_FILES), 13)
        self.assertIn("device_fabric/linux_native_outbound.py",
                      bundle.SOURCE_FILES)
        self.assertIn("scripts/h454_native_linux_runtime.py",
                      bundle.SOURCE_FILES)
        for path in ("device_fabric/native_brc_enrollment.py",
                     "device_fabric/native_brc_status.py",
                     "scripts/h454_native_linux_service.py"):
            self.assertIn(path, bundle.SOURCE_FILES)
        for forbidden in (
            "device_fabric/linux_native_create.py",
            "device_fabric/linux_native_process.py",
            "device_fabric/linux_native_child.py",
            "device_fabric/native_owner_issuer.py",
            "device_fabric/native_effect_admission.py",
            "scripts/h15_native_effect_receipts.py",
            "deploy/",
            ".github/",
        ):
            self.assertNotIn(forbidden, bundle.SOURCE_FILES)
        self.assertTrue(all(path.endswith(".py") for path in bundle.SOURCE_FILES))

    def test_bundle_is_reproducible_per_exact_target_and_commit(self):
        files = fixture_sources()
        first, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=files)
        second, same_receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=dict(reversed(list(files.items()))))
        self.assertEqual(first, second)
        self.assertEqual(receipt, same_receipt)
        proof = bundle.verify_bytes(first, receipt, target=TARGET,
                                    release_sha=SHA)
        self.assertEqual(proof["status"], "BUNDLE_SOURCE_VERIFIED")
        self.assertFalse(proof["install_authorized"])
        self.assertFalse(proof["connected"])
        self.assertFalse(proof["changes_on_owner_host"])
        self.assertEqual(proof["source_count"], len(bundle.SOURCE_FILES))

    def test_archive_only_contains_fixed_regular_readonly_source_and_manifest(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            members = tar.getmembers()
            self.assertEqual({m.name for m in members},
                             set(bundle.SOURCE_FILES) | {bundle.MANIFEST_NAME})
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o444)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.mtime, 0)
            manifest = json.loads(tar.extractfile(bundle.MANIFEST_NAME).read())
        self.assertEqual(manifest["schema"], bundle.SCHEMA)
        self.assertEqual(manifest["release_sha"], SHA)
        self.assertEqual(manifest["activation"], "DISABLED")
        self.assertFalse(manifest["install_authorized"])
        self.assertFalse(manifest["contains_secrets"])
        self.assertNotIn(b"ssh-rsa", data)
        self.assertNotIn(b"BEGIN PRIVATE KEY", data)

    def test_wrong_target_or_release_or_zero_sha_never_verifies(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        for target, sha in (
            ("yfc-vps", SHA), ("windows", SHA), (TARGET, "b" * 40),
            (TARGET, "0" * 40), (TARGET, "abc"),
        ):
            with self.subTest(target=target,sha=sha), self.assertRaises(
                    bundle.SourceBundleDenied):
                bundle.verify_bytes(data, receipt, target=target,
                                    release_sha=sha)

    def test_tampered_gzip_and_recomputed_external_hash_denied(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        changed = bytearray(data)
        changed[len(changed) // 2] ^= 0x01
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_bytes(bytes(changed), receipt, target=TARGET,
                                release_sha=SHA)
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_bytes(bytes(changed),
                                retarget_receipt(receipt, bytes(changed)),
                                target=TARGET, release_sha=SHA)

    def test_extra_tar_member_denied_even_if_untrusted_receipt_is_rehashed(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        archive = io.BytesIO()
        with gzip.GzipFile(fileobj=archive, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as tar:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as previous:
                    for entry in previous.getmembers():
                        tar.addfile(entry, previous.extractfile(entry))
                info, raw = bundle._member("device_fabric/linux_native_create.py", b"unsafe")
                tar.addfile(info, io.BytesIO(raw))
        changed = archive.getvalue()
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_bytes(changed, retarget_receipt(receipt, changed),
                                target=TARGET, release_sha=SHA)

    def test_symlink_archive_member_denied_even_with_matching_receipt_hash(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as prior:
                    for member in prior.getmembers():
                        if member.name == bundle.SOURCE_FILES[0]:
                            member.type = tarfile.SYMTYPE
                            member.linkname = "/etc/shadow"
                            member.size = 0
                            archive.addfile(member)
                        else:
                            archive.addfile(member, prior.extractfile(member))
        changed = buffer.getvalue()
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_bytes(changed, retarget_receipt(receipt, changed),
                                target=TARGET, release_sha=SHA)

    def test_recomputed_receipt_cannot_hide_pax_header_or_16mb_bomb(self):
        original, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        for size in (256, 16 * 1024 * 1024):
            with self.subTest(pax_bytes=size):
                result = io.BytesIO()
                with gzip.GzipFile(fileobj=result, mode="wb", filename="",
                                   mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w",
                                      format=tarfile.USTAR_FORMAT) as tar:
                        header = tarfile.TarInfo("pax-header")
                        header.type = tarfile.XGLTYPE
                        header.size = size
                        header.mode = 0o444
                        tar.addfile(header, io.BytesIO(b"0" * size))
                        with tarfile.open(fileobj=io.BytesIO(original),
                                          mode="r:gz") as valid:
                            for member in valid.getmembers():
                                tar.addfile(member, valid.extractfile(member))
                tampered = result.getvalue()
                self.assertLess(len(tampered), bundle.MAX_ARCHIVE_SIZE)
                with self.assertRaisesRegex(
                        bundle.SourceBundleDenied, "^native_source_bundle_denied$"):
                    bundle.verify_bytes(
                        tampered, retarget_receipt(receipt, tampered),
                        target=TARGET, release_sha=SHA)

    def test_recomputed_receipt_cannot_hide_concatenated_gzip_streams(self):
        original, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        changed = original + gzip.compress(b"second forbidden stream")
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_bytes(changed, retarget_receipt(receipt, changed),
                                target=TARGET, release_sha=SHA)

    def test_fake_approval_and_receipt_json_malleability_denied(self):
        data, receipt = bundle.build_bytes(
            target=TARGET, release_sha=SHA, sources=fixture_sources())
        base = json.loads(receipt)
        variations = (
            {**base, "owner_approved": True},
            {**base, "install_authorized": True},
            {**base, "service_installed": True},
            {**base, "provenance_signature": "SIGNED"},
            {**base, "bundle_sha256": "c" * 64},
            {**base, "source_count": True},
        )
        for extra in variations:
            with self.subTest(fields=list(extra)), self.assertRaises(
                    bundle.SourceBundleDenied):
                bundle.verify_bytes(data, bundle._json(extra),
                                    target=TARGET, release_sha=SHA)
        for malformed in (
            b" "+receipt, receipt+b"\n", b"{}",
            receipt.replace(b'"schema":',
                            b'"schema":"invalid","schema":',1),
            b"\xff",
        ):
            with self.subTest(data=malformed[:25]), self.assertRaises(
                    bundle.SourceBundleDenied):
                bundle.verify_bytes(data, malformed, target=TARGET,
                                    release_sha=SHA)

    def test_reject_missing_extra_or_large_selected_source(self):
        files = fixture_sources()
        files.pop(bundle.SOURCE_FILES[0])
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_bytes(target=TARGET, release_sha=SHA,
                               sources=files)
        files = fixture_sources()
        files["device_fabric/linux_native_create.py"] = b"bad"
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_bytes(target=TARGET, release_sha=SHA,
                               sources=files)
        files = fixture_sources()
        files[bundle.SOURCE_FILES[0]] = b"X" * (bundle.MAX_FILE_SIZE + 1)
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_bytes(target=TARGET, release_sha=SHA,
                               sources=files)


@unittest.skipUnless(sys.platform == "linux", "disposable Git/permissions fixture on Linux")
class GitNativeBundleIntegration(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="h454-native-bundle-ci-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "source"
        self.repo.mkdir(mode=0o700)
        self.out = self.base / "out"
        self.out.mkdir(mode=0o700)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic CI Owner")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        for name, body in fixture_sources().items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        # No real provider token or private project is included in archive.
        (self.repo / "untracked_secret").write_bytes(
            b"SYNTHETIC_PRIVATE_TOKEN_MUST_NEVER_ENTER_BUNDLE")
        self.git("add", *bundle.SOURCE_FILES)
        self.git("commit", "-q", "--no-gpg-sign", "-m", "synthetic")
        self.head = self.git("rev-parse", "HEAD").strip()

    def git(self, *args: str) -> str:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=True)
        return result.stdout.decode("ascii")

    def test_source_archive_built_only_from_exact_git_blobs(self):
        self.assertEqual(len(self.head), 40)
        changed = self.repo / bundle.SOURCE_FILES[0]
        changed.write_bytes(b"UNCOMMITTED_PRIVATE_MARKER_NOT_IN_BUNDLE")
        report = bundle.build_from_git(
            repo=self.repo, target=TARGET,
            release_sha=self.head, out_dir=self.out)
        self.assertEqual(report["status"], "BUNDLE_SOURCE_VERIFIED")
        self.assertEqual(
            report, bundle.verify_local(
                out_dir=self.out, target=TARGET, release_sha=self.head))
        artifact = (self.out / bundle.ARCHIVE_NAME).read_bytes()
        self.assertNotIn(b"UNCOMMITTED_PRIVATE_MARKER_NOT_IN_BUNDLE", artifact)
        self.assertNotIn(b"SYNTHETIC_PRIVATE_TOKEN_MUST_NEVER_ENTER_BUNDLE", artifact)
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:gz") as archive:
            self.assertEqual(
                archive.extractfile(bundle.SOURCE_FILES[0]).read(),
                fixture_sources()[bundle.SOURCE_FILES[0]])
        self.assertEqual((self.out / bundle.RECEIPT_NAME).stat().st_mode & 0o777,
                         0o600)

    def test_same_checkout_and_sha_yields_reproducible_bytes(self):
        a= bundle.collect_git_sources(self.repo, release_sha=self.head)
        first, receipt = bundle.build_bytes(
            target=TARGET, release_sha=self.head, sources=a)
        second, again = bundle.build_bytes(
            target=TARGET, release_sha=self.head,
            sources=bundle.collect_git_sources(self.repo, release_sha=self.head))
        self.assertEqual(first,second)
        self.assertEqual(receipt,again)

    def test_wrong_git_head_does_not_create_artifacts(self):
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_from_git(repo=self.repo, target=TARGET,
                                  release_sha="c"*40, out_dir=self.out)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_output_directory_must_be_private_and_empty(self):
        self.out.chmod(0o755)
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_from_git(repo=self.repo, target=TARGET,
                                  release_sha=self.head, out_dir=self.out)
        self.out.chmod(0o700)
        (self.out / "foreign-file").write_text("existing")
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_from_git(repo=self.repo, target=TARGET,
                                  release_sha=self.head, out_dir=self.out)

    def test_repeated_build_never_overwrites_existing_archive(self):
        bundle.build_from_git(repo=self.repo, target=TARGET,
                              release_sha=self.head, out_dir=self.out)
        before = (self.out / bundle.ARCHIVE_NAME).read_bytes()
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.build_from_git(repo=self.repo, target=TARGET,
                                  release_sha=self.head, out_dir=self.out)
        self.assertEqual((self.out / bundle.ARCHIVE_NAME).read_bytes(), before)

    def test_private_artifact_mode_symlink_and_extra_files_denied(self):
        bundle.build_from_git(repo=self.repo, target=TARGET,
                              release_sha=self.head, out_dir=self.out)
        target = self.out / bundle.ARCHIVE_NAME
        target.chmod(0o644)
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_local(out_dir=self.out, target=TARGET,
                                release_sha=self.head)
        target.chmod(0o600)
        backup = self.base / "backup.gz"
        target.rename(backup)
        target.symlink_to(backup)
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_local(out_dir=self.out, target=TARGET,
                                release_sha=self.head)
        target.unlink()
        backup.rename(target)
        (self.out / "foreign-file").write_bytes(b"not allowed")
        with self.assertRaises(bundle.SourceBundleDenied):
            bundle.verify_local(out_dir=self.out, target=TARGET,
                                release_sha=self.head)

    def test_git_replace_refs_cannot_swap_pinned_release_blob(self):
        name = bundle.SOURCE_FILES[0]
        original = fixture_sources()[name]
        blob = self.git("rev-parse", self.head + ":" + name).strip()
        injected = self.base / "replacement-source"
        injected.write_bytes(b"SYNTHETIC_REPLACEMENT_BLOB_NOT_RELEASE_SOURCE")
        replacement_oid = self.git("hash-object", "-w", str(injected)).strip()
        self.git("replace", blob, replacement_oid)
        actual = bundle.collect_git_sources(self.repo, release_sha=self.head)
        self.assertEqual(actual[name], original)
        self.assertNotEqual(actual[name], injected.read_bytes())
        payload, receipt = bundle.build_bytes(
            target=TARGET, release_sha=self.head, sources=actual)
        self.assertEqual(
            bundle.verify_bytes(payload, receipt,
                                target=TARGET, release_sha=self.head)["status"],
            "BUNDLE_SOURCE_VERIFIED")

    def test_git_mode_symlink_or_executable_is_not_regular_selected_blob(self):
        for change in ("symlink", "executable"):
            with self.subTest(change=change):
                entry = self.repo / bundle.SOURCE_FILES[0]
                entry.unlink()
                if change == "symlink":
                    entry.symlink_to(self.base / "private-target")
                else:
                    entry.write_bytes(b"not trusted as source")
                    entry.chmod(0o755)
                self.git("add", bundle.SOURCE_FILES[0])
                self.git("commit", "-q", "--no-gpg-sign", "-m", change)
                changed_head = self.git("rev-parse", "HEAD").strip()
                with self.assertRaises(bundle.SourceBundleDenied):
                    bundle.collect_git_sources(self.repo, release_sha=changed_head)


@unittest.skipUnless(
    sys.platform == "linux"
    and os.environ.get("GITHUB_ACTIONS") == "true"
    and os.environ.get("RUNNER_OS") == "Linux",
    "exact-source packaging exercised only on isolated GitHub Linux CI",
)
class GitHubRealCheckoutBundleSmoke(unittest.TestCase):
    """Prove the ACTUAL repo tree is packageable, not only synthetic Git blobs.

    The test never uses owner original paths, native host credentials, SSH
    or production. It verifies two target-specific bundles in RUNNER_TEMP.
    """

    def test_actual_checkout_exact_sha_build_and_verify_both_target_bundles(self):
        root = Path(os.environ["GITHUB_WORKSPACE"])
        expected_sha = os.environ["GITHUB_SHA"]
        actual_sha = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root),
             "rev-parse", "HEAD"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10,
        ).stdout.decode("ascii").strip()
        self.assertEqual(actual_sha, expected_sha)
        self.assertEqual(len(expected_sha), 40)

        source_hashes = set()
        with tempfile.TemporaryDirectory(
            prefix="h454-real-checkout-readonly-",
            dir=os.environ["RUNNER_TEMP"],
        ) as location:
            parent = Path(location)
            for target in ("hermes-vps", "yfc-vps"):
                with self.subTest(target=target):
                    output = parent / target
                    output.mkdir(mode=0o700)
                    report = bundle.build_from_git(
                        repo=root, target=target,
                        release_sha=expected_sha, out_dir=output)
                    verified = bundle.verify_local(
                        out_dir=output, target=target,
                        release_sha=expected_sha)
                    self.assertEqual(report, verified)
                    self.assertEqual(report["status"],
                                     "BUNDLE_SOURCE_VERIFIED")
                    self.assertEqual(report["release_sha"], expected_sha)
                    self.assertFalse(report["install_authorized"])
                    self.assertFalse(report["connected"])
                    self.assertFalse(report["service_installed"])
                    self.assertFalse(report["changes_on_owner_host"])
                    self.assertEqual(report["source_count"], len(bundle.SOURCE_FILES))
                    source_hashes.add(report["bundle_sha256"])
                    with tarfile.open(output / bundle.ARCHIVE_NAME, "r:gz") as tar:
                        self.assertEqual(
                            {item.name for item in tar.getmembers()},
                            set(bundle.SOURCE_FILES) | {bundle.MANIFEST_NAME})
                    self.assertEqual(
                        (output / bundle.ARCHIVE_NAME).stat().st_mode & 0o777,
                        0o600)
        # Different owner-host targets cannot accidentally share one candidate.
        self.assertEqual(len(source_hashes), 2)
