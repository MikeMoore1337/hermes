"""Dormant Stage 2A Linux exclusive file create on ORIGINAL host paths.

This module is never registered as an MCP tool and creates no service, key,
socket or privilege. The trusted native agent must supply a locally pinned
LinuxNativeFiles root and an owner-authenticated NativeEffectAdmission.
Only explicit, signed, one-use 'file_write' scopes can create a NEW file;
existing files are NEVER replaced, deleted or edited. No OS-level access is
granted by this library. Real-host use requires separately approved OS ACLs,
runtime identity, owner grant issuer, device revocation and live acceptance.
"""
from __future__ import annotations

import hashlib
import os
import stat

from device_fabric.linux_native_files import (
    LinuxNativeFiles, NativeLinuxDenied, READ_EXTENSIONS, MAX_READ_BYTES,
    _kernel_openat2, _relative,
)
from device_fabric.native_effect_admission import (
    AdmissionDenied, NativeEffectAdmission,
)

# Never permit untrusted callers to choose creation mode or access flags.
_CREATE_FLAGS = (os.O_RDWR | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)


class LinuxNativeExclusiveCreate:
    """Single locally configured project; no path-to-host mapping from MCP."""

    def __init__(self, files: LinuxNativeFiles,
                 admission: NativeEffectAdmission):
        if type(files) is not LinuxNativeFiles or type(admission) is not NativeEffectAdmission:
            raise NativeLinuxDenied("native_linux_denied")
        self._files = files
        self._admission = admission

    def create(self, signed_grant: bytes, content: bytes, *,
               now: int | None = None) -> dict[str, object]:
        """Create an absent source file once; refuse overwrite or replay.

        The signed relative filename is the ONLY destination. The grant's
        UUID is consumed in durable storage *before* the first host effect.
        Failures may leave a partial file; never automatically unlink or
        retry an ambiguous operation after a crash/disconnect.
        """
        try:
            identity, effect = self._admission.reserve_effect(
                signed_grant, content, now=now)
        except AdmissionDenied:
            raise NativeLinuxDenied("native_linux_denied") from None

        try:
            if (effect.action != "file_write" or effect.project != self._files.project
                or type(content) is not bytes or len(content) > MAX_READ_BYTES
                or self._files._root_fd < 0):
                raise NativeLinuxDenied("native_linux_denied")
            _relative(effect.relative)
            if effect.relative.rsplit("/", 1)[-1].lower().rsplit(".", 1)[-1] not in {
                    extension.lstrip(".") for extension in READ_EXTENSIONS}:
                raise NativeLinuxDenied("native_linux_denied")

            parent, _, filename = effect.relative.rpartition("/")
            # Both opens use pinned owner-approved root, with openat2
            # RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV.
            # Checking parent first also lets us fsync the correct directory.
            parent_fd = self._files._open(parent, directory=True)
            try:
                parent_before = os.fstat(parent_fd)
                if not stat.S_ISDIR(parent_before.st_mode):
                    raise NativeLinuxDenied("native_linux_denied")
                self._admission.check_active()
                fd = _kernel_openat2(self._files._root_fd, effect.relative,
                                     _CREATE_FLAGS, mode=0o600)
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_dev != parent_before.st_dev
                        or info.st_mode & 0o777 & ~0o600):
                        raise NativeLinuxDenied("native_linux_denied")
                    offset = 0
                    view = memoryview(content)
                    while offset < len(content):
                        written = os.write(fd, view[offset:])
                        if written <= 0:
                            raise NativeLinuxDenied("native_linux_denied")
                        offset += written
                    os.fsync(fd)
                    # Verify post-write content from the same open file
                    # description, not by reopening a raceable pathname.
                    os.lseek(fd, 0, os.SEEK_SET)
                    recovered = bytearray()
                    while len(recovered) < len(content):
                        block = os.read(fd, len(content) - len(recovered))
                        if not block:
                            break
                        recovered.extend(block)
                    after = os.fstat(fd)
                    at_name = os.stat(filename, dir_fd=parent_fd,
                                      follow_symlinks=False)
                    if (bytes(recovered) != content or after.st_size != len(content)
                        or after.st_nlink != 1
                        or (after.st_dev, after.st_ino) !=
                           (at_name.st_dev, at_name.st_ino)
                        or not stat.S_ISREG(at_name.st_mode)):
                        raise NativeLinuxDenied("native_linux_denied")
                    # Verify the parent still resolves under the pinned root.
                    # OS account + parent ACLs must prevent hostile moves.
                    check_fd = self._files._open(parent, directory=True)
                    try:
                        parent_after = os.fstat(check_fd)
                        if ((parent_before.st_dev, parent_before.st_ino)
                            != (parent_after.st_dev, parent_after.st_ino)):
                            raise NativeLinuxDenied("native_linux_denied")
                    finally:
                        os.close(check_fd)
                    os.fsync(parent_fd)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)
            if self._admission.complete(identity, success=True) != "RECORDED":
                raise NativeLinuxDenied("native_linux_denied")
            return {
                "status": "created",
                "project": effect.project,
                "relative": effect.relative,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "operation_id": effect.operation_id,
            }
        except (OSError, ValueError, AdmissionDenied):
            # Receipt is already consumed, regardless of whether the host
            # created a file. Never delete untrusted raceable names or retry.
            try:
                self._admission.complete(identity, success=False)
            except (AdmissionDenied, OSError, ValueError):
                pass
            raise NativeLinuxDenied("native_linux_denied") from None
