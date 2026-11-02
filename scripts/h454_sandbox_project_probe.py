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
LOCAL_HEAD = re.compile(rb"ref: refs/heads/([A-Za-z0-9_][A-Za-z0-9._/-]{0,127})\n?\Z", re.ASCII)
COMMIT = re.compile(rb"[a-f0-9]{40}\n?\Z", re.ASCII)


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
    if not _safe_branch(branch):
        _reject("remote_unavailable")
    return branch, head.group(1)


def _safe_branch(branch: str) -> bool:
    return not (".." in branch or "//" in branch or branch.endswith(("/", ".")) or
                any(part.startswith(".") or part.endswith((".", ".lock")) for part in branch.split("/")))


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


def _open_regular(parent_fd: int, name: str, limit: int) -> tuple[int, os.stat_result]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            _reject("repository_unavailable")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks = bytearray()
    while len(chunks) <= limit:
        part = os.read(fd, min(4096, limit + 1 - len(chunks)))
        if not part:
            return bytes(chunks)
        chunks.extend(part)
    _reject("repository_unavailable")


def _unchanged_file(parent_fd: int, name: str, fd: int, before: os.stat_result) -> None:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    live = os.fstat(fd)
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
    if not stat.S_ISREG(current.st_mode) or key(current) != key(before) or key(live) != key(before):
        _reject("repository_changed")


def _configured_origin(config_fd: int) -> str:
    config = _read_bounded(config_fd, MAX_OUTPUT)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false"}
    try:
        result = subprocess.run(
            ["/usr/bin/git", "config", "--no-includes", "--null", "--file",
             "-", "--get-all", "remote.origin.url"],
            input=config, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, start_new_session=True, preexec_fn=_limit_git,
            timeout=5, check=False,
        )
        if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
            _reject("repository_origin_unavailable")
        fields = result.stdout.split(b"\0")
        if len(fields) != 2 or fields[1] != b"":
            _reject("repository_origin_unavailable")
        return fields[0].decode("ascii")
    except (OSError, UnicodeError, subprocess.SubprocessError):
        _reject("repository_origin_unavailable")


def inspect_existing(repository_url: object, *, root: Path = ROOT,
                     remote: Callable[[str], bytes] = git_remote) -> dict:
    """Inspect one existing sandbox repository without modifying it."""
    name, repository = parse_url(repository_url)
    if name in RESERVED or name.partition(".")[0] in WINDOWS_DEVICES:
        _reject("name_reserved")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    opened: list[int] = []
    files: list[tuple[int, str, int, os.stat_result]] = []
    directories: list[tuple[int, str, int, os.stat_result]] = []
    try:
        parent_fd = os.open(root.parent, flags); opened.append(parent_fd)
        root_fd = os.open(root.name, flags, dir_fd=parent_fd); opened.append(root_fd)
        _root_unchanged(root, parent_fd, root_fd)
        project_fd = os.open(name, flags, dir_fd=root_fd); opened.append(project_fd)
        project = os.fstat(project_fd)
        git_fd = os.open(".git", flags, dir_fd=project_fd); opened.append(git_fd)
        git_dir = os.fstat(git_fd)
        config_fd, config_info = _open_regular(git_fd, "config", MAX_OUTPUT)
        opened.append(config_fd); files.append((git_fd, "config", config_fd, config_info))
        origin = _configured_origin(config_fd)
        try:
            _, canonical_origin = parse_url(origin)
        except ProbeRejected:
            _reject("repository_origin_mismatch")
        if canonical_origin.casefold() != repository.casefold():
            _reject("repository_origin_mismatch")
        head_fd, head_info = _open_regular(git_fd, "HEAD", 256)
        opened.append(head_fd); files.append((git_fd, "HEAD", head_fd, head_info))
        raw_head = _read_bounded(head_fd, 256)
        ref = LOCAL_HEAD.fullmatch(raw_head)
        if ref is None:
            _reject("repository_branch_unavailable")
        branch = ref.group(1).decode("ascii")
        if not _safe_branch(branch):
            _reject("repository_branch_unavailable")
        missing_ref = None
        try:
            ref_parent = git_fd
            for component in ("refs", "heads", *branch.split("/")[:-1]):
                missing_ref = (ref_parent, component)
                child = os.open(component, flags, dir_fd=ref_parent); opened.append(child)
                directories.append((ref_parent, component, child, os.fstat(child)))
                ref_parent = child
            ref_name = branch.split("/")[-1]
            missing_ref = (ref_parent, ref_name)
            ref_fd, ref_info = _open_regular(ref_parent, ref_name, 128)
            opened.append(ref_fd); files.append((ref_parent, ref_name, ref_fd, ref_info))
            local_head = _read_bounded(ref_fd, 128)
            if not COMMIT.fullmatch(local_head):
                _reject("repository_head_unavailable")
            missing_ref = None
        except FileNotFoundError:
            packed_fd, packed_info = _open_regular(git_fd, "packed-refs", 1_048_576)
            opened.append(packed_fd); files.append((git_fd, "packed-refs", packed_fd, packed_info))
            raw_packed = _read_bounded(packed_fd, 1_048_576)
            needle = b" refs/heads/" + branch.encode("ascii")
            matches = [line[:-len(needle)] for line in raw_packed.splitlines() if line.endswith(needle)]
            if len(matches) != 1 or not COMMIT.fullmatch(matches[0]):
                _reject("repository_head_unavailable")
            local_head = matches[0]
        remote_branch, remote_head = parse_remote(remote(repository))
        _root_unchanged(root, parent_fd, root_fd)
        if not _same_inode(os.stat(name, dir_fd=root_fd, follow_symlinks=False), project) or not _same_inode(
            os.stat(".git", dir_fd=project_fd, follow_symlinks=False), git_dir
        ):
            _reject("repository_changed")
        for parent, leaf, fd, info in files:
            _unchanged_file(parent, leaf, fd, info)
        for parent, leaf, fd, info in directories:
            if not _same_inode(os.stat(leaf, dir_fd=parent, follow_symlinks=False), info) or not _same_inode(
                os.fstat(fd), info
            ):
                _reject("repository_changed")
        if missing_ref is not None:
            try:
                os.stat(missing_ref[1], dir_fd=missing_ref[0], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _reject("repository_changed")
    except OSError:
        _reject("repository_unavailable")
    finally:
        for fd in reversed(opened):
            os.close(fd)
    return {"schema": 1, "status": "existing_metadata_checked", "repository": repository,
            "root": "/workspace/projects/" + name, "branch": branch,
            "head": local_head.decode("ascii").strip(), "remote_branch": remote_branch,
            "remote_head": remote_head, "filesystem": "existing_not_modified", "can_connect": False}


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
        if not isinstance(request, dict) or set(request) not in (
            {"repository_url"}, {"repository_url", "operation"}
        ):
            _reject("invalid_request")
        operation = request.get("operation", "probe")
        if operation == "probe":
            result = probe(request["repository_url"])
        elif operation == "inspect_existing":
            result = inspect_existing(request["repository_url"])
        else:
            _reject("invalid_request")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProbeRejected, ValueError, UnicodeError, RecursionError):
        reason = sys.exc_info()[1]
        code = str(reason) if isinstance(reason, ProbeRejected) else "invalid_request"
        print(json.dumps({"status": "refused", "reason": code, "can_connect": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
