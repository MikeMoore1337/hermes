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


def worktree_repository(root: Path, target: Path) -> str:
    """Accept only a reciprocal Git worktree link within this sandbox root."""
    link = target / '.git'
    if link.is_symlink() or not link.is_file() or link.stat().st_size > 4096:
        raise ProjectError('invalid_project')
    raw = link.read_text(encoding='utf-8').strip()
    if not raw.startswith('gitdir: '):
        raise ProjectError('invalid_project')
    path = Path(raw[8:])
    if not path.is_absolute():
        path = target / path
    metadata = path.resolve(strict=True)
    # Reject indirections in the repository, .git, worktrees, and entry.
    if (metadata != path.absolute() or metadata.name in ('', '.', '..') or metadata.parent.name != 'worktrees'
            or metadata.parent.parent.name != '.git'):
        raise ProjectError('invalid_project')
    base = metadata.parent.parent.parent
    if (base.parent != root.resolve() or not NAME.fullmatch(base.name)
            or base.is_symlink() or (base / '.git').is_symlink()
            or (base / '.git' / 'worktrees').is_symlink() or path.is_symlink()):
        raise ProjectError('invalid_project')
    backlink, common = metadata / 'gitdir', metadata / 'commondir'
    if (backlink.is_symlink() or common.is_symlink() or not backlink.is_file()
            or not common.is_file() or backlink.stat().st_size > 4096 or common.stat().st_size > 4096
            or common.read_text(encoding='utf-8').strip() != '../..'
            or Path(backlink.read_text(encoding='utf-8').strip()).resolve() != link.resolve()):
        raise ProjectError('invalid_project')
    return base.name


def inspect(name: str, root: Path = ROOT, *, git_timeout: float = 10) -> dict:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ProjectError('invalid_name')
    target = root / name
    if root.is_symlink() or not root.is_dir() or target.is_symlink() or not target.is_dir():
        raise ProjectError('project_not_found')
    if target.resolve().parent != root.resolve() or (target / '.git').is_symlink():
        raise ProjectError('invalid_project')
    repository = name if (target / '.git').is_dir() else worktree_repository(root, target)
    origin = git(target, 'remote', 'get-url', 'origin', timeout=git_timeout)
    if origin != ORIGIN_PREFIX + repository + '.git':
        raise ProjectError('origin_mismatch')
    branch = git(target, 'branch', '--show-current', timeout=git_timeout)
    head = git(target, 'rev-parse', '--verify', 'HEAD', timeout=git_timeout)
    if len(branch) > 255 or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ProjectError('invalid_git_state')
    return {'status': 'verified', 'workspace': name, 'repository': repository, 'scope': 'sandbox',
            'root': str(target), 'origin': origin, 'branch': branch or None, 'detached': not branch, 'head': head,
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
            try:
                remaining = max(0.05, min(1.0, deadline - time.monotonic()))
                projects.append(inspect(entry.name, root, git_timeout=remaining))
            except ProjectError as exc:
                gitdir = root / entry.name / '.git'
                if str(exc) in ('git_unavailable', 'git_failed') or gitdir.is_file() or gitdir.is_symlink():
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
