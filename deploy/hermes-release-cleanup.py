#!/usr/bin/env python3
"""Owner-gated Hermes historical release cleanup; dry-run unless --apply.

This helper has no scheduler, bot reply handler, or remote deletion API.
It never touches Docker/containerd, live app trees, logs, databases or state.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

AGENT = Path("/opt/hermes-agent-owner/releases")
UI = Path("/opt/hermes-control-center/releases")
STATE = Path("/var/lib/hermes-main-deploy/last-success.sha")
LOCK = Path("/run/lock/hermes-main-deploy.lock")
MAIN = re.compile(r"main-([0-9a-f]{40})\Z")
BACKUP = re.compile(r"\.backup-([0-9a-f]{12})-\d{8}T\d{6}Z\Z")
REFERENCES = re.compile(r"main-([0-9a-f]{40})")


def config_pins() -> set[str]:
    paths = [str(p) for p in (
        Path("/etc/hermes"), Path("/etc/hermes-codex-scheduler"),
        Path("/etc/systemd/system"),
    ) if p.exists()]
    if not paths:
        raise RuntimeError("configuration paths not available")
    result = subprocess.run(
        ["grep", "-RhoE", r"main-[0-9a-f]{40}", *paths],
        capture_output=True, text=True, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("configuration scan failed")
    return set(REFERENCES.findall(result.stdout))


def live_pins() -> set[str]:
    keep = set()
    for root in (AGENT.parent, UI.parent):
        for p in root.iterdir():
            if p.is_symlink():
                keep.update(REFERENCES.findall(str(p.resolve(strict=True))))
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            links = [proc / "cwd", proc / "exe", *(proc / "fd").iterdir()]
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as exc:
            raise RuntimeError("process descriptors not readable") from exc
        for p in links:
            try:
                keep.update(REFERENCES.findall(os.readlink(p)))
            except OSError:
                pass
        try:
            keep.update(REFERENCES.findall(
                (proc / "cmdline").read_bytes()[:8192].decode(errors="ignore")
            ))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return keep


def candidates_for(agent: Path, ui: Path, protected: set[str],
                   current_backup: Path, retained: int = 12) -> tuple[list[Path], int]:
    keep = set(protected)
    for root in (agent, ui):
        children = list(root.iterdir())
        if any(p.name.startswith(".incoming-") for p in children):
            raise RuntimeError("incomplete release detected")
        releases = [p for p in children if MAIN.fullmatch(p.name)]
        if any(p.is_symlink() or not p.is_dir() for p in releases):
            raise RuntimeError("unsafe release directory")
        keep.update(p.name[5:] for p in sorted(
            releases, key=lambda p: p.stat().st_mtime, reverse=True
        )[:retained])
    candidates = []
    for root in (agent, ui):
        for p in root.iterdir():
            build = MAIN.fullmatch(p.name)
            backup = BACKUP.fullmatch(p.name) if root == agent else None
            if build and build.group(1) not in keep:
                candidates.append(p)
            elif (backup and p != current_backup and
                  not any(sha.startswith(backup.group(1)) for sha in keep)):
                candidates.append(p)
    for p in candidates:
        info = p.lstat()
        if (p.parent not in (agent, ui) or p.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or os.path.ismount(p)):
            raise RuntimeError("unsafe candidate " + p.name)
    mounts = [
        row.split()[4].replace("\\040", " ")
        for row in Path("/proc/self/mountinfo").read_text().splitlines()
    ]
    if any(m == str(p) or m.startswith(str(p) + "/")
           for p in candidates for m in mounts):
        raise RuntimeError("mounted path inside candidate")
    return sorted(candidates), len(keep)


def ask(count: int) -> bool:
    # /dev/tty opened for reading ONLY. "r+" raises non-seekable stream errors.
    if not sys.stdout.isatty():
        raise RuntimeError("interactive terminal required")
    print(f"Type DELETE {count} to confirm, or Enter to cancel: ",
          end="", flush=True)
    with open("/dev/tty", "rb", buffering=0) as tty:
        answer = tty.readline(64).decode("ascii", errors="replace").strip()
    return answer == f"DELETE {count}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Prompt for human confirmation and delete candidates")
    args = parser.parse_args()
    if (os.geteuid() != 0
            or os.uname().nodename.split(".")[0] != "vps1777112993"):
        raise RuntimeError("wrong host or user")
    if any(p.is_symlink() or not p.is_dir() for p in (AGENT, UI)):
        raise RuntimeError("invalid release roots")
    lockfd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(lockfd)
        raise RuntimeError("deployment in progress") from exc
    try:
        sha = STATE.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise RuntimeError("invalid current SHA")
        current = (UI.parent / "current").resolve(strict=True)
        if current != UI / ("main-" + sha):
            raise RuntimeError("current release mismatch")
        receipt = AGENT / ("main-" + sha) / ".deployment-receipt.txt"
        receipt_at_start = receipt.read_text()
        fields = dict(
            line.split("=", 1) for line in receipt_at_start.splitlines()
            if "=" in line
        )
        previous = Path(fields.get("PREVIOUS_UI", ""))
        backup = Path(fields.get("BACKUP", ""))
        if (fields.get("SHA") != sha or previous.parent != UI
                or not MAIN.fullmatch(previous.name) or not previous.is_dir()
                or backup.parent != AGENT or not BACKUP.fullmatch(backup.name)
                or not backup.is_dir()):
            raise RuntimeError("rollback references invalid")
        protected = {sha, previous.name[5:]} | config_pins() | live_pins()
        paths, keep_count = candidates_for(AGENT, UI, protected, backup)
        print("PROTECTED_RELEASE_SHAS=", keep_count)
        print("CANDIDATE_DIRECTORIES=", len(paths))
        if not paths:
            print("NOTHING_TO_CLEAN")
            return 0
        sizes = subprocess.run(
            ["du", "-scB1", "--", *map(str, paths)],
            capture_output=True, text=True, check=True,
        )
        total = int(sizes.stdout.splitlines()[-1].split()[0])
        print("ESTIMATED_FREE_GIB=", round(total / 1024**3, 2))
        print("EXAMPLE_CANDIDATES=", [p.name for p in paths[:8]])
        print("=== BEFORE ===", flush=True)
        subprocess.run(["df", "-hT", "/"], check=True)
        if not args.apply:
            print("DRY_RUN_ONLY: no files removed; use --apply to confirm")
            return 0
        if not ask(len(paths)):
            print("CANCELLED: no files removed")
            return 0
        if (STATE.read_text().strip() != sha
                or (UI.parent / "current").resolve(strict=True) != current):
            raise RuntimeError("active release changed")
        if receipt.read_text() != receipt_at_start:
            raise RuntimeError("active release receipt changed")
        latest_pins = {sha, previous.name[5:]} | config_pins() | live_pins()
        next_paths, _ = candidates_for(AGENT, UI, latest_pins, backup)
        if paths != next_paths:
            raise RuntimeError("cleanup candidates changed")
        removed = 0
        for p in paths:
            shutil.rmtree(p)
            removed += 1
        print("REMOVED_DIRECTORIES=", removed)
        print("=== AFTER ===")
        subprocess.run(["df", "-hT", "/"], check=True)
        return 0
    finally:
        os.close(lockfd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"STOP: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        raise SystemExit(2)
