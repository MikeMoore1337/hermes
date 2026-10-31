#!/usr/bin/env python3
"""Read-only public GitHub and Windows BRC sandbox project preflight."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable

ROOT = Path("/workspace/projects")
MAX_INPUT = 512
MAX_OUTPUT = 16_384
MAX_ENTRIES = 256
TIMEOUT_SECONDS = 12
RESERVED = frozenset(("hermes", "your-fitness-coach", "second-brain", "ai-development-toolkit"))
WINDOWS_DEVICES = frozenset(("con", "prn", "aux", "nul", *(f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(1, 10))))
URL = re.compile(
    r"https://github\.com/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)/"
    r"([a-z0-9_][a-z0-9_.-]{0,103})/?\Z",
    re.ASCII | re.IGNORECASE,
)
REF = re.compile(r"ref: refs/heads/([A-Za-z0-9_][A-Za-z0-9._/-]{0,127})\tHEAD\Z", re.ASCII)
HEAD = re.compile(r"([a-f0-9]{40})\tHEAD\Z", re.ASCII)


class ProbeRejected(ValueError):
    """Fixed, non-sensitive reason; no input or subprocess output is reflected."""


def _reject(reason: str) -> None:
    raise ProbeRejected(reason)


def parse_url(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 200:
        _reject("invalid_repository")
    match = URL.fullmatch(value)
    if not match:
        _reject("invalid_repository")
    owner, repo = match.groups()
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not repo or len(repo) > 100 or repo.endswith(".") or ".." in repo:
        _reject("invalid_repository")
    name = repo.lower()
    return name, f"https://github.com/{owner}/{name}.git"


def parse_remote(raw: bytes) -> tuple[str, str]:
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        _reject("remote_unavailable")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        _reject("remote_unavailable")
    if len(lines) != 2:
        _reject("remote_unavailable")
    ref, head = REF.fullmatch(lines[0]), HEAD.fullmatch(lines[1])
    if not ref or not head:
        _reject("remote_unavailable")
    branch = ref.group(1)
    if (".." in branch or "//" in branch or branch.endswith(("/", ".")) or
        any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
        _reject("remote_unavailable")
    return branch, head.group(1)


def _limit_git() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def git_remote(repository: str) -> bytes:
    """Fetch only HEAD metadata, with no inherited config, prompts or disk writes."""
    env = {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
        "GIT_ALLOW_PROTOCOL": "https", "GIT_OPTIONAL_LOCKS": "0",
    }
    args = ["/usr/bin/git", "-c", "credential.helper=", "-c", "http.followRedirects=false",
            "-c", "http.sslVerify=true", "-c", "core.hooksPath=/dev/null",
            "ls-remote", "--symref", "--exit-code", "--", repository, "HEAD"]
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env, start_new_session=True,
                                   preexec_fn=_limit_git)
    except (OSError, subprocess.SubprocessError):
        _reject("remote_unavailable")
    assert process.stdout is not None
    deadline = time.monotonic() + TIMEOUT_SECONDS
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    _reject("remote_unavailable")
                part = os.read(process.stdout.fileno(), 4096)
                if not part:
                    break
                output.extend(part)
                if len(output) > MAX_OUTPUT:
                    _reject("remote_unavailable")
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, subprocess.SubprocessError, ProbeRejected):
        # The child is unreaped here, so its process-group ID cannot be reused.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        _reject("remote_unavailable")
    finally:
        process.stdout.close()
    if returncode != 0:
        _reject("remote_unavailable")
    return bytes(output)


def _same_inode(a: os.stat_result, b: os.stat_result) -> bool:
    return stat.S_ISDIR(a.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _root_unchanged(root: Path, parent_fd: int, root_fd: int) -> None:
    try:
        parent = os.stat(root.parent, follow_symlinks=False)
        child = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_inode(parent, os.fstat(parent_fd)) or not _same_inode(child, os.fstat(root_fd)):
            _reject("workspace_changed")
    except OSError:
        _reject("workspace_changed")


def _conflict(root_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        pass
    except OSError:
        _reject("workspace_unavailable")
    try:
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_ENTRIES:
                    _reject("workspace_too_many_entries")
                if entry.name.casefold() == name.casefold():
                    return True
    except OSError:
        _reject("workspace_unavailable")
    return False


def probe(repository_url: object, *, root: Path = ROOT,
          remote: Callable[[str], bytes] = git_remote) -> dict:
    name, repository = parse_url(repository_url)
    if name in RESERVED or name.partition(".")[0] in WINDOWS_DEVICES:
        _reject("name_reserved")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = root_fd = None
    try:
        parent_fd = os.open(root.parent, flags)
        root_fd = os.open(root.name, flags, dir_fd=parent_fd)
        _root_unchanged(root, parent_fd, root_fd)
        if _conflict(root_fd, name):
            _reject("name_conflict")
        branch, head = parse_remote(remote(repository))
        _root_unchanged(root, parent_fd, root_fd)
        if _conflict(root_fd, name):
            _reject("name_conflict")
    except OSError:
        _reject("workspace_unavailable")
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            os.close(parent_fd)
    return {"schema": 1, "status": "preflight_ok", "repository": repository,
            "root": "/workspace/projects/" + name, "branch": branch, "head": head,
            "filesystem": "absent_at_check", "remote": "public_head_verified",
            "reservation": False, "can_connect": False}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    output = {}
    for key, value in pairs:
        if key in output:
            _reject("invalid_request")
        output[key] = value
    return output


def main() -> int:
    try:
        if (os.name != "posix" or os.getuid() != 65534 or
            not Path("/.dockerenv").is_file() or os.path.lexists("/var/run/docker.sock") or sys.argv[1:]):
            _reject("invalid_request")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            _reject("invalid_request")
        request = json.loads(raw, object_pairs_hook=_unique_pairs,
                             parse_constant=lambda _: _reject("invalid_request"))
        if not isinstance(request, dict) or set(request) != {"repository_url"}:
            _reject("invalid_request")
        print(json.dumps(probe(request["repository_url"]), sort_keys=True))
        return 0
    except (ProbeRejected, ValueError, UnicodeError, RecursionError):
        reason = sys.exc_info()[1]
        code = str(reason) if isinstance(reason, ProbeRejected) else "invalid_request"
        print(json.dumps({"status": "refused", "reason": code, "can_connect": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
