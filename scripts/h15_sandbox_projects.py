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


def inspect(name: str, root: Path = ROOT) -> dict:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ProjectError('invalid_name')
    target = root / name
    if root.is_symlink() or not root.is_dir() or target.is_symlink() or not target.is_dir():
        raise ProjectError('project_not_found')
    if target.resolve().parent != root.resolve() or (target / '.git').is_symlink() or not (target / '.git').is_dir():
        raise ProjectError('invalid_project')
    origin = git(target, 'remote', 'get-url', 'origin')
    if origin != ORIGIN_PREFIX + name + '.git':
        raise ProjectError('origin_mismatch')
    branch = git(target, 'branch', '--show-current')
    head = git(target, 'rev-parse', '--verify', 'HEAD')
    if not branch or len(branch) > 255 or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ProjectError('invalid_git_state')
    return {'status': 'verified', 'workspace': name, 'scope': 'sandbox',
            'root': str(target), 'origin': origin, 'branch': branch, 'head': head,
            'verification_required_before_write': True}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != 'inspect':
        result = {'status': 'refused', 'reason': 'invalid_arguments'}
    else:
        try:
            result = inspect(sys.argv[2])
        except (ProjectError, OSError, UnicodeError) as exc:
            result = {'status': 'refused', 'reason': str(exc) if isinstance(exc, ProjectError) else 'operation_failed'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'verified' else 2


if __name__ == '__main__':
    raise SystemExit(main())
