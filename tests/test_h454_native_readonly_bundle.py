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


class NativeSourceArchivePure(unittest.TestCase):
    def test_exact_allowlist_excludes_write_process_grant_and_host_secrets(self):
        self.assertEqual(len(bundle.SOURCE_FILES), 10)
        self.assertIn("device_fabric/linux_native_outbound.py",
                      bundle.SOURCE_FILES)
        self.assertIn("scripts/h454_native_linux_runtime.py",
                      bundle.SOURCE_FILES)
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
