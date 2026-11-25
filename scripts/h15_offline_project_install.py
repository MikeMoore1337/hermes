"""Install a verified Git bundle into an absent sandbox project directory."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def git(*args: str) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    result = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "credential.helper=", *args],
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise ValueError("git_failed")
    return result.stdout.decode("utf-8", "strict").strip()


def install(stage: Path, parent: Path, name: str, branch: str, head: str,
            checksum: str, size: int, origin: str, nonce: str) -> dict:
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name) or ".." in name
            or not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or origin != f"https://github.com/MikeMoore1337/{name}.git"):
        raise ValueError("arguments_invalid")
    if stage.is_symlink() or not stage.is_dir() or stage.parent.resolve() != parent.parent.resolve():
        raise ValueError("stage_invalid")
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent.absolute():
        raise ValueError("parent_invalid")
    if (stage / "marker").is_symlink() or (stage / "marker").read_text(encoding="utf-8") != nonce:
        raise ValueError("stage_marker_invalid")
    bundle = stage / "repo.bundle"
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size != size:
        raise ValueError("bundle_invalid")
    with bundle.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != checksum:
        raise ValueError("bundle_checksum_invalid")
    target = parent / name
    target.mkdir(mode=0o700)  # Existing projects are never overwritten.
    git("clone", "--branch", branch, "--config", "core.autocrlf=false", "--", str(bundle), str(target))
    git("-C", str(target), "remote", "set-url", "origin", origin)
    if (git("-C", str(target), "branch", "--show-current") != branch
            or git("-C", str(target), "rev-parse", "HEAD") != head
            or git("-C", str(target), "remote", "get-url", "origin") != origin
            or git("-C", str(target), "status", "--porcelain")):
        raise ValueError("verification_failed")
    bundle.unlink()
    (stage / "marker").unlink()
    return {"status": "INSTALLED", "name": name, "head": head, "branch": branch, "clean": True}


def main() -> int:
    try:
        args = json.loads(sys.argv[1])
        result = install(Path(args["stage"]), Path("/workspace/projects"), args["name"], args["branch"],
                         args["head"], args["sha256"], args["size"], args["origin"], args["nonce"])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc) if type(exc) is ValueError else type(exc).__name__}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
