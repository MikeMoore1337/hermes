"""Discover owner repositories inside the existing H-15 sandbox.

This module runs on the sandbox device, never on a native host. Its caller is
responsible for selecting the owner-paired sandbox and relaying the result.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path('/workspace/projects')
NAME = re.compile(r'[a-z][a-z0-9-]{1,79}\Z')
ORIGIN_PREFIX = 'https://github.com/MikeMoore1337/'


class ProjectError(Exception):
    pass


def git(root: Path, *args: str, timeout: int = 10) -> str:
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0'}
    try:
        result = subprocess.run(['git', '-c', f'safe.directory={root}', '-c', 'core.fsmonitor=false', '-c',
            'core.hooksPath=/dev/null', '-c', 'credential.helper=', '-C', str(root), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProjectError('git_unavailable') from exc
    if result.returncode or len(result.stdout) > 1024:
        raise ProjectError('git_failed')
    return result.stdout.decode('utf-8', 'strict').strip()


def inspect(name: str, root: Path = ROOT, *, git_timeout: float = 10) -> dict:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ProjectError('invalid_name')
    target = root / name
    if root.is_symlink() or not root.is_dir() or target.is_symlink() or not target.is_dir():
        raise ProjectError('project_not_found')
    if target.resolve().parent != root.resolve() or (target / '.git').is_symlink() or not (target / '.git').is_dir():
        raise ProjectError('invalid_project')
    origin = git(target, 'remote', 'get-url', 'origin', timeout=git_timeout)
    if origin != ORIGIN_PREFIX + name + '.git':
        raise ProjectError('origin_mismatch')
    branch = git(target, 'branch', '--show-current', timeout=git_timeout)
    head = git(target, 'rev-parse', '--verify', 'HEAD', timeout=git_timeout)
    if not branch or len(branch) > 255 or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ProjectError('invalid_git_state')
    return {'status': 'verified', 'workspace': name, 'scope': 'sandbox',
            'root': str(target), 'origin': origin, 'branch': branch, 'head': head,
            'verification_required_before_write': True}


def discover(root: Path = ROOT, *, max_entries: int = 128, max_projects: int = 16,
             seconds: float = 3) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ProjectError('sandbox_root_missing')
    deadline = time.monotonic() + seconds
    projects = []
    incomplete = False
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            if index >= max_entries or time.monotonic() >= deadline:
                incomplete = True
                break
            if not NAME.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            if len(projects) >= max_projects:
                incomplete = True
                break
            gitdir = root / entry.name / '.git'
            if gitdir.is_file() or gitdir.is_symlink():
                # Worktrees and indirections need separate verification.
                incomplete = True
                continue
            try:
                remaining = max(0.05, min(1.0, deadline - time.monotonic()))
                projects.append(inspect(entry.name, root, git_timeout=remaining))
            except ProjectError as exc:
                if str(exc) in ('git_unavailable', 'git_failed'):
                    incomplete = True
                continue
            except (OSError, UnicodeError):
                incomplete = True
                continue
    projects.sort(key=lambda project: project['workspace'])
    return {'status': 'catalog', 'projects': projects, 'incomplete': incomplete}


def main() -> int:
    if sys.argv[1:] == ['list']:
        try:
            result = discover()
        except (ProjectError, OSError, UnicodeError):
            result = {'status': 'refused', 'reason': 'sandbox_root_missing'}
    elif len(sys.argv) == 3 and sys.argv[1] == 'inspect':
        try:
            result = inspect(sys.argv[2])
        except (ProjectError, OSError, UnicodeError) as exc:
            result = {'status': 'refused', 'reason': str(exc) if isinstance(exc, ProjectError) else 'operation_failed'}
    else:
        result = {'status': 'refused', 'reason': 'invalid_arguments'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] in ('verified', 'catalog') else 2


if __name__ == '__main__':
    raise SystemExit(main())
