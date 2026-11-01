"""H-24/#191 offline key handoff regressions: synthetic-only, no SSH or Google."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    path = ROOT / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


receiver = load("h191_gsc_credential_provision")
sender = load("h191_gsc_key_send")
SHA = "a" * 40
TARGET = "root@example-vps.test"


def fake_json():
    return {
        "type": "service_account", "private_key_id": "a" * 40,
        "private_key": "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n",
        "client_email": "fake@fake-project.iam.gserviceaccount.com",
        "token_uri": receiver.GOOGLE_TOKEN_URL,
    }


def sample_bytes(data=None):
    return json.dumps(fake_json() if data is None else data).encode()


class H191KeyHandoffTests(unittest.TestCase):
    def test_offline_validator_accepts_only_service_account_and_scoped_key(self):
        values = []
        receiver.validate_key_json(
            sample_bytes(), verifier=lambda i: values.append(i["client_email"])
        )
        self.assertEqual(values, [fake_json()["client_email"]])

    def test_validator_rejects_bad_types_host_key_and_universe(self):
        for change in (
            {"type": "external_account"},
            {"token_uri": "https://evil.example/token"},
            {"client_email": "evil@example.com"},
            {"private_key_id": "xx"},
            {"private_key": "bad"},
            {"universe_domain": "evil.example"},
        ):
            with self.subTest(change=change):
                data = fake_json() | change
                with self.assertRaises(receiver.ProvisionError):
                    receiver.validate_key_json(
                        sample_bytes(data), verifier=lambda _: None
                    )

    def test_validator_rejects_duplicate_fields_nonstandard_and_bad_sizes(self):
        duplicate = sample_bytes().replace(
            b'"type": "service_account",',
            b'"type": "service_account", "type": "external_account",',
        )
        with self.assertRaisesRegex(receiver.ProvisionError, "duplicate_json_field"):
            receiver.validate_key_json(duplicate, verifier=lambda _: None)
        for raw in (
            b"", b"a" * 63, b"a" * (receiver.MAX_CREDENTIAL_BYTES + 1),
            b"\xff" * 128,
        ):
            with self.assertRaises(receiver.ProvisionError):
                receiver.validate_key_json(raw, verifier=lambda _: None)

    def test_private_key_validation_error_redacted(self):
        def bad(_info):
            raise ValueError("EXPOSE_ME_TOKEN")
        with self.assertRaises(receiver.ProvisionError) as cm:
            receiver.validate_key_json(sample_bytes(), verifier=bad)
        self.assertEqual(str(cm.exception), "credential_private_key_invalid")
        self.assertNotIn("EXPOSE_ME_TOKEN", str(cm.exception))

    def test_atomic_exclusive_install_mode_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                raw = sample_bytes()
                receiver.install_key_exclusive(
                    fd, raw, uid=os.getuid(), gid=os.getgid(), chown=lambda *_: None
                )
                file = Path(tmp) / "service-account.json"
                self.assertEqual(file.read_bytes(), raw)
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o400)
                self.assertTrue(
                    receiver._check_credential_file(fd, os.getuid(), os.getgid())
                )
                with self.assertRaisesRegex(
                    receiver.ProvisionError, "credential_already_installed"
                ):
                    receiver.install_key_exclusive(
                        fd, b"not-a-real-key",
                        uid=os.getuid(), gid=os.getgid(), chown=lambda *_: None
                    )
                self.assertEqual(file.read_bytes(), raw)
                self.assertEqual(list(Path(tmp).glob(".h191-*")), [])
            finally:
                os.close(fd)

    def test_existing_symlink_and_insecure_mode_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                target = Path(tmp) / "target"
                target.write_text("DO_NOT_CHANGE")
                link = Path(tmp) / "service-account.json"
                link.symlink_to(target)
                with self.assertRaisesRegex(
                    receiver.ProvisionError, "existing_credential_metadata_unsafe"
                ):
                    receiver._check_credential_file(fd, os.getuid(), os.getgid())
                self.assertEqual(target.read_text(), "DO_NOT_CHANGE")
                link.unlink()
                link.write_bytes(sample_bytes())
                link.chmod(0o644)
                with self.assertRaisesRegex(
                    receiver.ProvisionError, "existing_credential_metadata_unsafe"
                ):
                    receiver._check_credential_file(fd, os.getuid(), os.getgid())
            finally:
                os.close(fd)

    def test_wrong_host_and_release_rejected_before_secret(self):
        with self.assertRaisesRegex(receiver.ProvisionError, "wrong_host"):
            receiver._check_installed_release(hostname="other", euid=0)
        with self.assertRaisesRegex(receiver.ProvisionError, "root_required"):
            receiver._check_installed_release(hostname=receiver.HOST, euid=9999)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "last.sha"
            state.write_text("../escape")
            with self.assertRaisesRegex(receiver.ProvisionError, "release_sha_invalid"):
                receiver._check_installed_release(
                    hostname=receiver.HOST, euid=0, state=state,
                    releases=Path(tmp), script_path=Path(tmp) / "other"
                )

    def test_receiver_no_oauth_no_service_mutation_and_no_secret_args(self):
        source = (ROOT / "scripts/h191_gsc_credential_provision.py").read_text()
        for phrase in (
            "--install-stdin", "--status", "sys.stdin.buffer.read",
            "O_NOFOLLOW", "O_EXCL", "os.link(", "H191_OAUTH=NOT_RUN",
            "H191_TIMER=NOT_ENABLED", "GOOGLE_SCOPE",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, source)
        for forbidden in ("systemctl", "--credentials", "requests.get(", "curl "):
            self.assertNotIn(forbidden, source)

    def test_sender_uses_strict_pinned_ssh_without_shell(self):
        cmd = sender._ssh_command(TARGET, SHA, "--status")
        for item in (
            "BatchMode=yes", "StrictHostKeyChecking=yes",
            "ForwardAgent=no", "ProxyCommand=none", "ProxyJump=none", "-T",
        ):
            self.assertIn(item, cmd)
        self.assertIn(SHA, cmd[-1])
        with self.assertRaises(sender.TransferError):
            sender._ssh_command("root@evil;id", SHA, "--status")
        with self.assertRaises(sender.TransferError):
            sender._ssh_command(TARGET, "../escape", "--status")

    def test_sender_pins_remote_status_before_binary_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private.json"
            payload = b"SYNTHETIC_SECRET_123" + b"a" * 100
            path.write_bytes(payload)
            calls = []

            def fake(cmd, **kwargs):
                calls.append((cmd, kwargs))
                if len(calls) == 1:
                    return subprocess.CompletedProcess(
                        cmd, 0, sender.STATUS_OK.encode(), b""
                    )
                self.assertEqual(kwargs["stdin"].read(), payload)
                return subprocess.CompletedProcess(
                    cmd, 0, sender.TRANSFER_OK.encode(), b""
                )
            sender.send_key(path, TARGET, SHA, runner=fake)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][1]["input"], b"")
            for cmd, _ in calls:
                self.assertNotIn(payload.decode(), " ".join(cmd))

    def test_sender_refuses_failed_preflight_without_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private.json"
            path.write_bytes(b"x" * 100)
            calls = []

            def fake(cmd, **kwargs):
                calls.append(cmd)
                return subprocess.CompletedProcess(
                    cmd, 0,
                    b"H191_CREDENTIAL=READY_METADATA_ONLY\nH191_OAUTH=NOT_RUN", b""
                )
            with self.assertRaisesRegex(
                sender.TransferError, "remote_host_or_credential_state_unverified"
            ):
                sender.send_key(path, TARGET, SHA, runner=fake)
            self.assertEqual(len(calls), 1)

    def test_sender_refuses_symlink_oversize_and_no_owner_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "large"
            p.write_bytes(b"x" * (sender.MAX_SIZE + 1))
            link = Path(tmp) / "link"
            link.symlink_to(p)
            for path in (p, link, Path(tmp)):
                with self.assertRaises(sender.TransferError):
                    sender._validate_key_path(path)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/h191_gsc_key_send.py"),
             "--ssh-target", TARGET, "--release-sha", SHA,
             "--key-file", "/missing/file"],
            capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"--confirm-owner-key-transfer", proc.stderr)


if __name__ == "__main__":
    unittest.main()
