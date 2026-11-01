"""Binary-safe transfer of an existing GSC key over pre-authorized SSH.

Run locally after explicit owner approval. The SSH host key must already be
trusted; no secrets are put in argv, CI, chat, shells, or process output.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
TARGET_RE = re.compile(r"root@[A-Za-z0-9][A-Za-z0-9.-]{0,251}\Z")
MIN_SIZE = 64
MAX_SIZE = 32 * 1024
STATUS_OK = "H191_CREDENTIAL=MISSING\nH191_OAUTH=NOT_RUN"
TRANSFER_OK = (
    "H191_CREDENTIAL=INSTALLED_METADATA_ONLY\n"
    "H191_OAUTH=NOT_RUN\nH191_TIMER=NOT_ENABLED"
)


class TransferError(Exception):
    """Stable, secret-free error codes."""


def _ssh_command(target: str, sha: str, action: str) -> list[str]:
    if not TARGET_RE.fullmatch(target) or not SHA_RE.fullmatch(sha):
        raise TransferError("ssh_identity_or_release_invalid")
    if action not in ("--status", "--install-stdin"):
        raise TransferError("ssh_action_invalid")
    program = (
        "/opt/hermes-gsc/venv/bin/python -I -B "
        f"/opt/hermes-agent-owner/releases/main-{sha}/scripts/"
        f"h191_gsc_credential_provision.py {action}"
    )
    return [
        "ssh", "-T", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes", "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none", "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        target, program,
    ]


def _validate_key_path(path: Path) -> None:
    if path.is_symlink():
        raise TransferError("local_key_symlink_denied")
    try:
        meta = path.stat()
    except OSError:
        raise TransferError("local_key_unavailable") from None
    if not stat.S_ISREG(meta.st_mode) or not MIN_SIZE <= meta.st_size <= MAX_SIZE:
        raise TransferError("local_key_type_or_size_invalid")


def send_key(path: Path, target: str, sha: str, *, runner=subprocess.run) -> None:
    """Verify receiver first, then transfer bytes directly using file stdin."""
    _validate_key_path(path)
    try:
        before = runner(
            _ssh_command(target, sha, "--status"),
            input=b"", capture_output=True, timeout=25, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise TransferError("ssh_status_unavailable") from None
    if (before.returncode != 0
            or before.stdout.decode("ascii", "replace").strip() != STATUS_OK):
        raise TransferError("remote_host_or_credential_state_unverified")
    try:
        original = path.stat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            meta = os.fstat(source.fileno())
            if (not stat.S_ISREG(meta.st_mode)
                    or not MIN_SIZE <= meta.st_size <= MAX_SIZE
                    or (meta.st_dev, meta.st_ino) != (original.st_dev, original.st_ino)
                    or path.is_symlink()):
                raise TransferError("local_key_changed_or_unsafe")
            # No PowerShell text pipeline: the original bytes are SSH stdin.
            after = runner(
                _ssh_command(target, sha, "--install-stdin"),
                stdin=source, capture_output=True, timeout=35, check=False,
            )
    except (OSError, subprocess.TimeoutExpired):
        raise TransferError("ssh_install_unavailable") from None
    if (after.returncode != 0
            or after.stdout.decode("ascii", "replace").strip() != TRANSFER_OK):
        raise TransferError("remote_install_unverified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H191 direct private SSH key transfer")
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--ssh-target", required=True,
                        help="Trusted root@host (in SSH known_hosts)")
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--confirm-owner-key-transfer", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        send_key(args.key_file, args.ssh_target, args.release_sha)
    except TransferError as exc:
        print("H191_KEY_TRANSFER=HOLD REASON=" + str(exc), file=sys.stderr)
        return 2
    print("H191_KEY_TRANSFER=PASS")
    print("H191_GOOGLE_OAUTH=NOT_RUN")
    print("H191_TIMER=NOT_ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
