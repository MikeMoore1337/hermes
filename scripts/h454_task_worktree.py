"""Create isolated task worktrees in existing H-15 sandbox clones (#454).

No network, host access, new device privileges, checkout resets or cleanup.
Run in the approved Windows BRC sandbox (Python and Git installed).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

WORKSPACES = Path("/workspace/projects")
TASKS = Path("/workspace/task-worktrees")
PROJECTS = {
    "hermes": ("main", "hermes"),
    "your-fitness-coach": ("master", "your-fitness-coach"),
    "second-brain": ("main", "second-brain"),
    "ai-development-toolkit": ("main", "ai-development-toolkit"),
}
ALIASES = {
    "yfc": "your-fitness-coach",
    "toolkit": "ai-development-toolkit",
    "adt": "ai-development-toolkit",
    "second brain": "second-brain",
    "hermes agent": "hermes",
}
TASK_ID = re.compile(r"^[1-9][0-9]{0,5}$")
SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$")
SHA = re.compile(r"^[0-9a-f]{40}$")


class TaskDenied(ValueError):
    """Public, non-sensitive refusal reason."""


def deny(reason: str):
    raise TaskDenied(reason)


def git(root: Path, *args: str, timeout: int = 12) -> str:
    cmd = [
        "git", "-c", f"safe.directory={root}",
        "-c", "core.preloadIndex=false", "-c", "index.threads=1",
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "-c", "pack.threads=1",
        "-c", "submodule.recurse=false",
        "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false",
        "-C", str(root), *args,
    ]
    try:
        result = subprocess.run(
            cmd, text=True, capture_output=True, timeout=timeout, check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_LFS_SKIP_SMUDGE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TaskDenied("git_not_ready") from exc
    if result.returncode or len(result.stdout) > 8192:
        deny("git_operation_refused")
    return result.stdout.strip()


def strict_path(path: Path):
    """Reject any symlink in a path, including an existing leaf."""
    for item in (path, *path.parents):
        if item.is_symlink():
            deny("symlink_path_refused")


def project_name(alias: str) -> str:
    key = alias.strip().casefold()
    target = ALIASES.get(key, key)
    if target not in PROJECTS:
        deny("unapproved_project")
    return target


def registered(root: Path, target: Path) -> bool:
    output = git(root, "worktree", "list", "--porcelain")
    return f"worktree {target}" in output.splitlines()


def check_task(project: str, task: str, slug: str,
               *, workspace_root: Path = WORKSPACES,
               task_root: Path = TASKS, prepare: bool = False,
               sync: bool = False) -> dict:
    if sync and not prepare:
        deny("sync_requires_prepare")
    name = project_name(project)
    if not TASK_ID.fullmatch(task) or not SLUG.fullmatch(slug):
        deny("invalid_task_identifier")
    if workspace_root != WORKSPACES and workspace_root == task_root:
        deny("unsafe_test_roots")
    base = workspace_root / name
    parent = task_root / name
    target = parent / f"issue{task}-{slug}"
    strict_path(base)
    strict_path(parent)
    strict_path(target)
    if not base.is_dir() or not (base / ".git").is_dir() or (base / ".git").is_symlink():
        deny("missing_or_unsafe_checkout")
    branch, repository = PROJECTS[name]
    origin = f"https://github.com/MikeMoore1337/{repository}.git"
    if git(base, "remote", "get-url", "origin") != origin:
        deny("origin_mismatch")
    if git(base, "branch", "--show-current") != branch:
        deny("baseline_branch_mismatch")
    head = git(base, "rev-parse", "HEAD")
    if not SHA.fullmatch(head):
        deny("invalid_head")
    task_branch = f"work/issue{task}-{slug}"
    if target.exists() or target.is_symlink():
        if not target.is_dir() or not registered(base, target):
            deny("task_path_collision")
        if not (target / ".git").is_file() or (target / ".git").is_symlink():
            deny("untrusted_task_gitdir")
        if git(target, "branch", "--show-current") != task_branch:
            deny("task_branch_collision")
        if git(target, "remote", "get-url", "origin") != origin:
            deny("task_origin_mismatch")
        if git(target, "rev-parse", "--show-toplevel") != str(target):
            deny("task_root_mismatch")
        actual_head = git(target, "rev-parse", "HEAD")
        if not SHA.fullmatch(actual_head):
            deny("task_head_invalid")
        state = "reused"
        basis = "previously_created"
    elif not prepare:
        state = "not_created"
        actual_head = None
        basis = "local_checkout_not_remote_verified"
    else:
        strict_path(task_root)
        if task_root.exists() and not task_root.is_dir():
            deny("tasks_root_invalid")
        task_root.mkdir(mode=0o700, exist_ok=True)
        strict_path(task_root)
        parent.mkdir(mode=0o700, exist_ok=True)
        strict_path(parent)
        start_head = head
        basis = "local_checkout_not_remote_verified"
        if sync:
            # Verified fixed GitHub origin + exact default branch only. This
            # updates Git objects and remote refs, NOT the existing checkout.
            git(base, "fetch", "--no-tags", "--depth=1",
                "--no-recurse-submodules", "origin", f"refs/heads/{branch}", timeout=45)
            start_head = git(base, "rev-parse", "FETCH_HEAD")
            if not SHA.fullmatch(start_head) or git(base, "cat-file", "-t", start_head) != "commit":
                deny("fetched_head_invalid")
            if git(base, "rev-parse", "HEAD") != head:
                deny("baseline_moved_during_fetch")
            basis = "fetched_origin"
        # Git enforces ref exclusivity and checkout atomicity; we neither
        # change the original branch nor its tracked worktree.
        git(base, "worktree", "add", "-b", task_branch, str(target), start_head, timeout=30)
        if not registered(base, target):
            deny("new_task_not_registered")
        if git(target, "branch", "--show-current") != task_branch:
            deny("new_task_branch_mismatch")
        state = "created"
        actual_head = git(target, "rev-parse", "HEAD")
    return {
        "schema": 1, "status": state, "project": name, "task": task,
        "branch": task_branch, "root": str(target), "origin": origin,
        "head": actual_head, "baseline_head": head, "basis": basis,
        "scope": "sandbox", "baseline_unchanged": True,
        "network_called": bool(sync and state == "created"),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--prepare", action="store_true",
                        help="Create isolated local worktree; default only inspects.")
    parser.add_argument("--sync", action="store_true",
                        help="Fetch approved origin branch, without changing original checkout.")
    args = parser.parse_args(argv)
    try:
        result = check_task(args.project, args.task, args.slug,
                            prepare=args.prepare, sync=args.sync)
    except TaskDenied as exc:
        print(json.dumps({"schema": 1, "status": "refused", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
