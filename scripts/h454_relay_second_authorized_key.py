"""No-overwrite installation and inode-pinned revocation of a second SSH key.

Callers supply freshly verified directory handles; this is not a deployment CLI.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat

try:
    import fcntl
except ImportError:  # Windows can import the module but cannot run the operator.
    fcntl = None

from scripts.h454_relay_authorized_keys import ForwardAuthorizationError, restricted_second_key

SLOT = "h454-wss-authorized-key"
TARGET = "authorized_keys2"


class SecondKeyHold(ValueError):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise SecondKeyHold(reason)


def _directories(registry_fd: int, ssh_fd: int, uid: int) -> None:
    _require(fcntl is not None and os.geteuid() == 0 and type(uid) is int and uid > 0, "ROOT_REQUIRED")
    registry, ssh = os.fstat(registry_fd), os.fstat(ssh_fd)
    _require(stat.S_ISDIR(registry.st_mode) and registry.st_uid == 0 and
             stat.S_IMODE(registry.st_mode) == 0o700 and stat.S_ISDIR(ssh.st_mode) and
             ssh.st_uid == uid and stat.S_IMODE(ssh.st_mode) == 0o700 and
             registry.st_dev == ssh.st_dev, "DIRECTORY_DRIFT")


def _read(fd: int, limit: int) -> bytes:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, "FILE_DRIFT")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks, remaining = [], limit + 1
    while remaining:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    after = os.fstat(fd)
    _require(len(data) == before.st_size and len(data) <= limit and
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns), "FILE_DRIFT")
    return data


def _original(ssh_fd: int, uid: int, expected_sha256: str, key: bytes) -> None:
    fd = os.open("authorized_keys", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ssh_fd)
    try:
        info = os.fstat(fd)
        _require(info.st_uid in (0, uid) and info.st_nlink == 1 and
                 not (stat.S_IMODE(info.st_mode) & 0o022), "ORIGINAL_UNTRUSTED")
        data = _read(fd, 1_048_576)
        current = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
        after = os.fstat(fd)
        identities = [(x.st_dev, x.st_ino, x.st_uid, x.st_gid, x.st_mode, x.st_nlink) for x in (info, current, after)]
        _require(identities[0] == identities[1] == identities[2] and
                 hashlib.sha256(data).hexdigest() == expected_sha256, "ORIGINAL_DRIFT")
        pattern = rb"(?:^|[ \t])ssh-ed25519[ \t]+" + re.escape(key) + rb"(?:[ \t\r\n]|$)"
        _require(not any(re.search(pattern, line) for line in data.splitlines(keepends=True)
                         if not line.lstrip().startswith(b"#")), "NEW_KEY_ALREADY_PRESENT")
    finally:
        os.close(fd)


def _slot(registry_fd: int, expected: bytes) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW
    try:
        fd = os.open(SLOT, flags, dir_fd=registry_fd)
    except FileNotFoundError:
        name = ".h454-wss-" + secrets.token_hex(16)
        temp = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=registry_fd)
        try:
            written = 0
            while written < len(expected):
                count = os.write(temp, expected[written:])
                _require(count > 0, "WRITE_FAILED")
                written += count
            os.fchown(temp, 0, 0)
            os.fchmod(temp, 0o644)
            os.fsync(temp)
            try:
                os.link(name, SLOT, src_dir_fd=registry_fd, dst_dir_fd=registry_fd, follow_symlinks=False)
            except FileExistsError:
                pass
        finally:
            os.close(temp)
            os.unlink(name, dir_fd=registry_fd)
        os.fsync(registry_fd)
        fd = os.open(SLOT, flags, dir_fd=registry_fd)
    try:
        info = os.fstat(fd)
        _require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644 and
                 _read(fd, 4096) == expected, "SLOT_DRIFT")
        return fd
    except BaseException:
        os.close(fd)
        raise


def install(registry_fd: int, ssh_fd: int, *, uid: int, original_sha256: str,
            public_key: str, relay_ip: str) -> dict[str, object]:
    """Install one restricted public key without replacing either SSH file."""
    try:
        _require(isinstance(original_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", original_sha256) is not None,
                 "ORIGINAL_PIN")
        entry = restricted_second_key(public_key, relay_ip)
        key = entry.split()[-1]
        _directories(registry_fd, ssh_fd, uid)
        fcntl.flock(registry_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            _original(ssh_fd, uid, original_sha256, key)
            try:
                target = os.stat(TARGET, dir_fd=ssh_fd, follow_symlinks=False)
            except FileNotFoundError:
                target = None
            if target is not None:
                try:
                    existing = os.stat(SLOT, dir_fd=registry_fd, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise SecondKeyHold("SECOND_FILE_OCCUPIED") from exc
                _require((target.st_dev, target.st_ino) == (existing.st_dev, existing.st_ino), "SECOND_FILE_OCCUPIED")
            fd = _slot(registry_fd, entry)
            try:
                info = os.fstat(fd)
                authorized = False
                try:
                    try:
                        os.link(SLOT, TARGET, src_dir_fd=registry_fd, dst_dir_fd=ssh_fd, follow_symlinks=False)
                        authorized = True
                    except FileExistsError:
                        pass
                    target = os.stat(TARGET, dir_fd=ssh_fd, follow_symlinks=False)
                    matches = stat.S_ISREG(target.st_mode) and (target.st_dev, target.st_ino) == (info.st_dev, info.st_ino)
                    if not matches and authorized:
                        raise SecondKeyHold("KEY_INSTALL_UNSETTLED")
                    _require(matches, "SECOND_FILE_OCCUPIED")
                    authorized = True
                    os.fsync(ssh_fd)
                    _original(ssh_fd, uid, original_sha256, key)
                    _require(_read(fd, 4096) == entry, "SLOT_DRIFT")
                    return {"device": info.st_dev, "inode": info.st_ino,
                            "sha256": hashlib.sha256(entry).hexdigest()}
                except Exception as exc:
                    if isinstance(exc, SecondKeyHold) and str(exc) == "KEY_INSTALL_UNSETTLED":
                        raise
                    if authorized:
                        try:
                            _require(_read(fd, 4096) in (b"", entry), "SLOT_DRIFT")
                            os.ftruncate(fd, 0)
                            os.fsync(fd)
                            _require(_read(fd, 4096) == b"", "REVOCATION_FAILED")
                        except (OSError, SecondKeyHold) as revoke_error:
                            raise SecondKeyHold("KEY_INSTALL_UNSETTLED") from revoke_error
                        raise SecondKeyHold("KEY_INSTALL_REVOKED") from exc
                    raise
            finally:
                os.close(fd)
        finally:
            fcntl.flock(registry_fd, fcntl.LOCK_UN)
    except (OSError, ForwardAuthorizationError) as exc:
        raise SecondKeyHold("KEY_INSTALL_HOLD") from exc


def revoke(registry_fd: int, ssh_fd: int, *, uid: int, device: int, inode: int, sha256: str) -> None:
    """Empty only the pinned root-owned inode, even if the SSH path was replaced."""
    try:
        _require(type(device) is int and type(inode) is int and inode > 0 and
                 isinstance(sha256, str) and re.fullmatch(r"[a-f0-9]{64}", sha256) is not None, "RECEIPT")
        _directories(registry_fd, ssh_fd, uid)
        fcntl.flock(registry_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            fd = os.open(SLOT, os.O_RDWR | os.O_NOFOLLOW, dir_fd=registry_fd)
            try:
                info = os.fstat(fd)
                _require((info.st_dev, info.st_ino) == (device, inode) and info.st_uid == 0 and
                         info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644, "SLOT_DRIFT")
                data = _read(fd, 4096)
                _require(not data or hashlib.sha256(data).hexdigest() == sha256, "SLOT_DRIFT")
                if data:
                    os.ftruncate(fd, 0)
                    os.fsync(fd)
                # shortcut: revoked slots cannot be reused; add pinned retry before production activation.
                _require(_read(fd, 4096) == b"", "REVOCATION_FAILED")
            finally:
                os.close(fd)
        finally:
            fcntl.flock(registry_fd, fcntl.LOCK_UN)
    except OSError as exc:
        raise SecondKeyHold("KEY_REVOKE_HOLD") from exc
