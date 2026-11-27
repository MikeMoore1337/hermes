"""Launch a project-scoped personal dispatcher in a Linux mount namespace.

The caller is responsible for authentication, replay protection, selecting a
trusted dispatcher, and running as an unprivileged project identity. This
module does not enroll a device or modify project permissions. Network access
and host process visibility are unavailable to the sandboxed child.
"""
from __future__ import annotations

import os
from pathlib import PurePosixPath
import subprocess
import sys
from typing import Sequence


class SandboxDenied(ValueError):
    """A sanitized refusal without project paths or process output."""


_FORBIDDEN = tuple(PurePosixPath(p) for p in (
    '/etc', '/root', '/proc', '/sys', '/dev', '/var', '/usr', '/boot',
    '/run', '/srv/second-brain/second-brain-vault',
))
_CONTAINERS = frozenset(('/', '/home', '/opt', '/srv', '/tmp'))


def _project_path(value: str) -> str:
    if (type(value) is not str or not value.startswith('/') or len(value) > 2048
            or '\0' in value or '\n' in value or '\r' in value):
        raise SandboxDenied('linux_personal_sandbox_denied')
    path = PurePosixPath(value)
    if str(path) != value or value in _CONTAINERS or any(p in ('.', '..') for p in value.split('/')):
        raise SandboxDenied('linux_personal_sandbox_denied')
    if any(path == denied or path in denied.parents or denied in path.parents for denied in _FORBIDDEN):
        raise SandboxDenied('linux_personal_sandbox_denied')
    return value


def open_project(value: str) -> int:
    """Pin one real project directory; caller closes the returned descriptor.

    Reject symlinks in every path component. This does not prevent a different
    host process from modifying files within the pinned directory afterward.
    """
    fd = -1
    try:
        path = _project_path(value)
        if sys.platform != 'linux' or os.geteuid() == 0:
            raise ValueError()
        flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        for component in path.split('/')[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        result, fd = fd, -1
        return result
    except Exception:
        raise SandboxDenied('linux_personal_sandbox_denied') from None
    finally:
        if fd >= 0:
            os.close(fd)


def start(project: str, bundle: str, command: Sequence[str]) -> subprocess.Popen:
    """Start an unprivileged, offline child with the project at /workspace.

    `bundle` and `command` must be selected and verified by the trusted parent,
    never by a remote request. The child inherits only its stdio and the pinned
    mount descriptor; a caller must kill/reap it if its transport is lost.
    """
    fd = -1
    try:
        if (sys.platform != 'linux' or os.geteuid() == 0 or type(bundle) is not str
                or not bundle.startswith('/') or os.path.realpath(bundle) != bundle
                or not os.path.isdir(bundle) or not isinstance(command, (list, tuple))
                or not 1 <= len(command) <= 32
                or any(type(part) is not str or not part or '\0' in part or len(part) > 4096
                       for part in command)
                or not command[0].startswith('/opt/commander/')):
            raise ValueError()
        root = _project_path(project)
        if (os.path.commonpath((root, bundle)) in (root, bundle)):
            raise ValueError()
        fd = open_project(root)
        args = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
                '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
                '--ro-bind', '/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
                '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                '--ro-bind', bundle, '/opt/commander',
                '--bind', f'/proc/self/fd/{fd}', '/workspace', '--chdir', '/workspace',
                '--clearenv', '--setenv', 'HOME', '/tmp',
                '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                '--setenv', 'GIT_CONFIG_GLOBAL', '/dev/null', '--setenv', 'GIT_CONFIG_NOSYSTEM', '1',
                '--setenv', 'GIT_CONFIG_COUNT', '1', '--setenv', 'GIT_CONFIG_KEY_0', 'safe.directory',
                '--setenv', 'GIT_CONFIG_VALUE_0', '/workspace', '--', *command]
        return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, pass_fds=(fd,),
                                start_new_session=True)
    except Exception:
        raise SandboxDenied('linux_personal_sandbox_denied') from None
    finally:
        if fd >= 0:
            os.close(fd)
