"""H-24/#191: install existing Google service-account credentials from private stdin.

Not a provider client. No OAuth, API requests, key creation or service activation.
Run only on the approved VPS after a separate owner credential approval.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Callable

HOST = "vps1777112993"
STATE = Path("/var/lib/hermes-main-deploy/last-success.sha")
RELEASES = Path("/opt/hermes-agent-owner/releases")
DESTINATION = Path("/etc/hermes-gsc")
BASENAME = "service-account.json"
MIN_CREDENTIAL_BYTES = 64
MAX_CREDENTIAL_BYTES = 32 * 1024
GOOGLE_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com\Z")
KEY_ID_PATTERN = re.compile(r"[a-f0-9]{40}\Z")
HEX40_PATTERN = re.compile(r"[a-f0-9]{40}\Z")


class ProvisionError(Exception):
    """Secret-free stable error codes."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProvisionError("duplicate_json_field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ProvisionError("nonstandard_json_value")


def validate_key_json(raw: bytes, *, verifier: Callable[[dict], None] | None = None) -> None:
    """Validate locally; do not contact Google or echo JSON/PEM."""
    if not isinstance(raw, bytes) or not MIN_CREDENTIAL_BYTES <= len(raw) <= MAX_CREDENTIAL_BYTES:
        raise ProvisionError("credential_size_invalid")
    try:
        info = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_json_constant,
        )
    except ProvisionError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ProvisionError("credential_json_invalid") from None
    if not isinstance(info, dict) or info.get("type") != "service_account":
        raise ProvisionError("credential_type_invalid")
    email, key_id, pem = (
        info.get("client_email"), info.get("private_key_id"), info.get("private_key")
    )
    if (
        info.get("token_uri") != GOOGLE_TOKEN_URL
        or type(email) is not str or not EMAIL_PATTERN.fullmatch(email)
        or type(key_id) is not str or not KEY_ID_PATTERN.fullmatch(key_id)
        or type(pem) is not str or len(pem) > 16 * 1024
        or not pem.startswith("-----BEGIN PRIVATE KEY-----\n")
        or not pem.endswith("-----END PRIVATE KEY-----\n")
        or info.get("universe_domain", "googleapis.com") != "googleapis.com"
    ):
        raise ProvisionError("credential_fields_invalid")
    if verifier is None:
        try:
            from google.oauth2 import service_account
        except ImportError:
            raise ProvisionError("google_auth_dependency_missing") from None

        def verifier(data: dict) -> None:
            creds = service_account.Credentials.from_service_account_info(
                data, scopes=[GOOGLE_SCOPE]
            )
            if creds.service_account_email != data["client_email"]:
                raise ValueError("credential identity mismatch")
    try:
        verifier(info)
    except Exception:
        raise ProvisionError("credential_private_key_invalid") from None


def _check_installed_release(
    *, script_path: Path = Path(__file__), state: Path = STATE,
    releases: Path = RELEASES, hostname: str | None = None,
    euid: int | None = None,
) -> str:
    if (os.geteuid() if euid is None else euid) != 0:
        raise ProvisionError("root_required")
    host = os.uname().nodename.split(".")[0] if hostname is None else hostname
    if host != HOST:
        raise ProvisionError("wrong_host")
    if not state.is_file() or state.is_symlink():
        raise ProvisionError("release_state_untrusted")
    try:
        sha = state.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise ProvisionError("release_state_unreadable") from None
    if not HEX40_PATTERN.fullmatch(sha):
        raise ProvisionError("release_sha_invalid")
    release = releases / ("main-" + sha)
    receipt = release / ".deployment-receipt.txt"
    expected = release / "scripts" / "h191_gsc_credential_provision.py"
    if (
        release.is_symlink() or not release.is_dir()
        or not receipt.is_file() or receipt.is_symlink()
        or expected.is_symlink() or not expected.is_file()
        or not script_path.is_absolute() or script_path != expected
    ):
        raise ProvisionError("release_source_untrusted")
    try:
        if (
            release.stat().st_uid != 0
            or expected.stat().st_uid != 0
            or receipt.stat().st_uid != 0
            or f"SHA={sha}" not in receipt.read_text().splitlines()
        ):
            raise ProvisionError("release_receipt_invalid")
    except (OSError, UnicodeError):
        raise ProvisionError("release_receipt_invalid") from None
    return sha


def _account():
    try:
        import grp
        import pwd
        acct = pwd.getpwnam("hermes-gsc")
    except (KeyError, ImportError):
        raise ProvisionError("gsc_user_missing") from None
    if acct.pw_uid == 0 or acct.pw_shell != "/usr/sbin/nologin":
        raise ProvisionError("gsc_identity_invalid")
    try:
        group = grp.getgrnam("hermes-gsc")
        groups = set(os.getgrouplist("hermes-gsc", acct.pw_gid))
    except (KeyError, OSError):
        raise ProvisionError("gsc_group_missing") from None
    if group.gr_gid != acct.pw_gid or groups != {acct.pw_gid}:
        raise ProvisionError("gsc_identity_extra_groups")
    return acct


def _open_private_directory(path: Path, expected_gid: int) -> int:
    if not path.is_absolute() or path != DESTINATION:
        raise ProvisionError("destination_not_allowed")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = None
    try:
        fd = os.open(path, flags)
        meta = os.fstat(fd)
        if (
            not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0
            or meta.st_gid != expected_gid
            or stat.S_IMODE(meta.st_mode) != 0o750
        ):
            raise ProvisionError("credential_directory_unsafe")
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _check_credential_file(dirfd: int, uid: int, gid: int) -> bool:
    try:
        meta = os.stat(BASENAME, dir_fd=dirfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
        or meta.st_gid != gid or stat.S_IMODE(meta.st_mode) != 0o400
        or not MIN_CREDENTIAL_BYTES <= meta.st_size <= MAX_CREDENTIAL_BYTES
        or meta.st_nlink != 1
    ):
        raise ProvisionError("existing_credential_metadata_unsafe")
    return True


def install_key_exclusive(
    dirfd: int, raw: bytes, *, uid: int, gid: int,
    chown: Callable[[int, int, int], None] | None = None,
) -> None:
    """Create 0400 key atomically, no overwrite, using trusted directory fd."""
    if _check_credential_file(dirfd, uid, gid):
        raise ProvisionError("credential_already_installed")
    temporary = ".h191-" + secrets.token_hex(16)
    fd = None
    try:
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o400, dir_fd=dirfd,
        )
        (chown or os.fchown)(fd, uid, gid)
        os.fchmod(fd, 0o400)
        with os.fdopen(fd, "wb") as output:
            fd = None
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        # Exclusive hard link: existing regular files AND symlinks cannot be replaced.
        os.link(
            temporary, BASENAME, src_dir_fd=dirfd,
            dst_dir_fd=dirfd, follow_symlinks=False,
        )
        os.fsync(dirfd)
    except OSError:
        raise ProvisionError("credential_install_failed") from None
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=dirfd)
        except FileNotFoundError:
            pass
    if not _check_credential_file(dirfd, uid, gid):
        raise ProvisionError("credential_install_unverified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H191 private GSC key (offline)")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--status", action="store_true", help="metadata only")
    actions.add_argument("--install-stdin", action="store_true", help="private SSH pipe")
    args = parser.parse_args(argv)
    try:
        pinned = _check_installed_release()
        acct = _account()
        fd = _open_private_directory(DESTINATION, acct.pw_gid)
        try:
            if args.status:
                state = ("READY_METADATA_ONLY"
                         if _check_credential_file(fd, acct.pw_uid, acct.pw_gid)
                         else "MISSING")
                print("H191_CREDENTIAL=" + state)
                print("H191_OAUTH=NOT_RUN")
                return 0
            if os.isatty(sys.stdin.fileno()):
                raise ProvisionError("stdin_must_be_private_pipe")
            if _check_credential_file(fd, acct.pw_uid, acct.pw_gid):
                raise ProvisionError("credential_already_installed")
            raw = sys.stdin.buffer.read(MAX_CREDENTIAL_BYTES + 1)
            validate_key_json(raw)
            if _check_installed_release() != pinned:
                raise ProvisionError("release_changed_during_install")
            install_key_exclusive(fd, raw, uid=acct.pw_uid, gid=acct.pw_gid)
            print("H191_CREDENTIAL=INSTALLED_METADATA_ONLY")
            print("H191_OAUTH=NOT_RUN")
            print("H191_TIMER=NOT_ENABLED")
            return 0
        finally:
            os.close(fd)
    except ProvisionError as exc:
        print("H191_CREDENTIAL=HOLD REASON=" + str(exc), file=sys.stderr)
        return 2
    except (OSError, PermissionError):
        print("H191_CREDENTIAL=HOLD REASON=local_operation_unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
