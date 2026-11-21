"""Fail-closed Landlock read boundary for a single-threaded Linux worker.

Call only after opening the explicitly admitted directory handles and O_PATH
file handles, before starting any transport thread or reading user requests.
The caller owns and must close every admitted descriptor.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import re
try:
    import resource
except ImportError:
    resource = None
import stat
import sys
import time
from pathlib import Path, PurePosixPath

try:
    import fcntl
except ImportError:
    fcntl = None

from device_fabric.linux_native_files import (
    LinuxNativeFiles, NativeLinuxDenied, READ_EXTENSIONS, MAX_READ_BYTES,
    _kernel_openat2, _relative,
)

READ_FILE = 1 << 2
HANDLED_FS = (1 << 15) - 1  # ABI 3: execute, read, create, remove, refer, truncate.
MAX_FILES = 16000
MAX_DIRECTORIES = 3000
MAX_ENTRIES = 40000
MAX_DEPTH = 64
MAX_SCAN_SECONDS = 30
PRIVATE_DIRECTORIES = frozenset({
    'data', 'uploads', 'media', 'backup', 'backups', 'logs', 'private', 'storage',
})


class _Ruleset(ctypes.Structure):
    _fields_ = [('handled_access_fs', ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32),
                ('reserved', ctypes.c_uint32)]


class _StatFs(ctypes.Structure):
    _fields_ = [('type', ctypes.c_long), ('remaining', ctypes.c_byte * 248)]


def _trusted_source_fs(fd: int) -> bool:
    """Admit only the local ext filesystem verified for the YFC source host."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        info = _StatFs()
        return libc.fstatfs(ctypes.c_int(fd), ctypes.byref(info)) == 0 and info.type == 0xEF53
    except Exception:
        return False


def _identity(node: os.stat_result) -> tuple[int, ...]:
    return (node.st_dev, node.st_ino, node.st_mode, node.st_nlink,
            node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def _trusted_runtime_fd(fd: int) -> bool:
    """Permit only the immutable libffi descriptor retained by Python 3.14."""
    try:
        path = Path(os.readlink('/proc/self/fd/' + str(fd)))
        if (not path.is_absolute() or not path.is_relative_to('/usr/lib') or
            re.fullmatch(r'libffi\.so\.[0-9.]+', path.name) is None or
            fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY or
            not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
            return False
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            info.st_mode & 0o022 or not info.st_mode & stat.S_IROTH or
            not os.access(path, os.R_OK, effective_ids=True, follow_symlinks=False)):
            return False
        for ancestor in (path.parent, *path.parent.parents):
            node = ancestor.lstat()
            if not stat.S_ISDIR(node.st_mode) or node.st_uid != 0 or node.st_mode & 0o022:
                return False
        current = path.lstat()
        return (stat.S_ISREG(current.st_mode) and current.st_uid == 0 and
                (current.st_dev, current.st_ino, current.st_mode, current.st_nlink) ==
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink))
    except (OSError, ValueError, TypeError):
        return False


class ReadSnapshot:
    """Bounded source-inode admission; never read source file contents."""

    def __init__(self, files: LinuxNativeFiles):
        if type(files) is not LinuxNativeFiles or files._root_fd < 0:
            raise NativeLinuxDenied('native_linux_denied')
        self.files = files
        root = os.fstat(files._root_fd)
        self.directories = {'': (files._root_fd, root.st_dev, root.st_ino)}
        self.regular: dict[str, tuple[int, ...]] = {}
        self.file_fds: list[int] = []
        self._owned_dirs: list[int] = []
        self._sealed = False
        self._attempted = False
        self._closed = False
        deadline = time.monotonic() + MAX_SCAN_SECONDS
        scanned = 0
        try:
            if resource is None or resource.getrlimit(resource.RLIMIT_NOFILE)[0] < MAX_FILES + MAX_DIRECTORIES + 32:
                raise NativeLinuxDenied('native_linux_denied')
            if not _trusted_source_fs(files._root_fd):
                raise NativeLinuxDenied('native_linux_denied')
            for ancestor in (files._root_path, *files._root_path.parents):
                node = ancestor.lstat()
                if (not stat.S_ISDIR(node.st_mode) or node.st_uid != 0 or node.st_mode & 0o022):
                    raise NativeLinuxDenied('native_linux_denied')
            current = files._root_path.lstat()
            if (current.st_dev, current.st_ino) != (root.st_dev, root.st_ino):
                raise NativeLinuxDenied('native_linux_denied')
            pending = [('', 0)]
            while pending:
                relative, depth = pending.pop()
                if time.monotonic() > deadline:
                    raise NativeLinuxDenied('native_linux_denied')
                directory = self.directories[relative][0]
                os.lseek(directory, 0, os.SEEK_SET)
                with os.scandir(directory) as entries:
                    for entry in entries:
                        scanned += 1
                        if scanned > MAX_ENTRIES or time.monotonic() > deadline:
                            raise NativeLinuxDenied('native_linux_denied')
                        child = relative + '/' + entry.name if relative else entry.name
                        try:
                            _relative(child)
                        except NativeLinuxDenied:
                            continue
                        if entry.name.casefold() in PRIVATE_DIRECTORIES:
                            continue
                        if entry.is_symlink():
                            continue
                        fd = _kernel_openat2(files._root_fd, child, os.O_PATH)
                        keep = False
                        try:
                            node = os.fstat(fd)
                            if stat.S_ISDIR(node.st_mode):
                                if node.st_uid != 0 or node.st_mode & 0o022:
                                    continue
                                if not os.access(child, os.R_OK | os.X_OK, dir_fd=files._root_fd,
                                                 effective_ids=True, follow_symlinks=False):
                                    continue
                                if depth >= MAX_DEPTH or len(self.directories) >= MAX_DIRECTORIES:
                                    raise NativeLinuxDenied('native_linux_denied')
                                opened = _kernel_openat2(files._root_fd, child,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK)
                                try:
                                    current = os.fstat(opened)
                                    if (current.st_dev, current.st_ino) != (node.st_dev, node.st_ino):
                                        raise NativeLinuxDenied('native_linux_denied')
                                except Exception:
                                    os.close(opened)
                                    raise
                                self._owned_dirs.append(opened)
                                self.directories[child] = (opened, node.st_dev, node.st_ino)
                                pending.append((child, depth + 1))
                            elif (stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and
                                  node.st_uid == 0 and not node.st_mode & 0o022 and
                                  0 <= node.st_size <= MAX_READ_BYTES and
                                  os.access(child, os.R_OK, dir_fd=files._root_fd,
                                            effective_ids=True, follow_symlinks=False) and
                                  PurePosixPath(entry.name).suffix.lower() in READ_EXTENSIONS):
                                if len(self.file_fds) >= MAX_FILES - 3:
                                    raise NativeLinuxDenied('native_linux_denied')
                                self.file_fds.append(fd)
                                self.regular[child] = _identity(node)
                                keep = True
                        finally:
                            if not keep:
                                os.close(fd)
            if not self.file_fds:
                raise NativeLinuxDenied('native_linux_denied')
        except Exception:
            self.close()
            raise NativeLinuxDenied('native_linux_denied') from None

    def seal(self) -> None:
        if self._attempted or self._closed or self.files._root_fd < 0:
            raise NativeLinuxDenied('native_linux_denied')
        self._attempted = True
        proc_fds = []
        try:
            for name in ('/proc/self/status', '/proc/self/cgroup', '/proc/self/mountinfo'):
                proc_fds.append(os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW))
            restrict_to_open_files(file_fds=tuple(self.file_fds + proc_fds),
                directory_fds=tuple(v[0] for v in self.directories.values()))
            self._sealed = True
            self.files._landlock_snapshot = self
        finally:
            for fd in proc_fds + self.file_fds:
                os.close(fd)
            self.file_fds.clear()

    def close(self) -> None:
        self._closed = True
        for fd in self.file_fds + self._owned_dirs:
            os.close(fd)
        self.file_fds.clear()
        self._owned_dirs.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def restrict_to_open_files(*, file_fds: tuple[int, ...], directory_fds: tuple[int, ...]) -> None:
    """Restrict this process; unlisted files and newly opened directories fail.

    Existing readable directory FDs are intentionally retained for bounded
    directory listing. Unexpected open FDs and extra threads fail before the
    irreversible policy transition.
    """
    ruleset_fd = None
    try:
        if (fcntl is None or sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'aarch64') or
            type(file_fds) is not tuple or type(directory_fds) is not tuple or
            not 1 <= len(file_fds) <= MAX_FILES or not 1 <= len(directory_fds) <= MAX_DIRECTORIES or
            any(type(fd) is not int or fd < 3 for fd in file_fds + directory_fds) or
            len(set(file_fds + directory_fds)) != len(file_fds) + len(directory_fds)):
            raise NativeLinuxDenied('native_linux_denied')
        for fd in file_fds:
            node = os.fstat(fd)
            if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or
                not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH):
                raise NativeLinuxDenied('native_linux_denied')
        for fd in directory_fds:
            node = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            if not stat.S_ISDIR(node.st_mode) or flags & os.O_PATH or flags & os.O_ACCMODE != os.O_RDONLY:
                raise NativeLinuxDenied('native_linux_denied')
        for fd in (0, 1, 2):
            mode = os.fstat(fd).st_mode
            if not (stat.S_ISCHR(mode) or stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode)):
                raise NativeLinuxDenied('native_linux_denied')
        if len(os.listdir('/proc/self/task')) != 1:
            raise NativeLinuxDenied('native_linux_denied')
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        if libc.syscall(444, 0, 0, 1) < 3:
            raise NativeLinuxDenied('native_linux_denied')
        ruleset = _Ruleset(HANDLED_FS)
        ruleset_fd = int(libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0))
        if ruleset_fd < 0:
            raise NativeLinuxDenied('native_linux_denied')
        for fd in file_fds:
            path = _PathBeneath(READ_FILE, fd, 0)
            if libc.syscall(445, ruleset_fd, 1, ctypes.byref(path), 0) < 0:
                raise NativeLinuxDenied('native_linux_denied')
        admitted = set(file_fds + directory_fds + (0, 1, 2, ruleset_fd))
        for name in os.listdir('/proc/self/fd'):
            fd = int(name)
            if fd in admitted:
                continue
            try:
                os.fstat(fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            if _trusted_runtime_fd(fd):
                continue
            raise NativeLinuxDenied('native_linux_denied')
        if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.syscall(446, ruleset_fd, 0) != 0:
            raise NativeLinuxDenied('native_linux_denied')
    except Exception:
        raise NativeLinuxDenied('native_linux_denied') from None
    finally:
        if ruleset_fd is not None and ruleset_fd >= 0:
            os.close(ruleset_fd)
