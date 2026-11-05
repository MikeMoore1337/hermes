#!/usr/bin/env python3
"""H777: manage the ORIGINAL ECC adapter in an independently owned Hermes HOME.

Linux / owner-run opt-in CLI. This is not an active Hermes agent or a repair to
the upstream ECC uninstaller. Only a freshly allocated private HOME is mounted
in the networkless, pinned Node container. NEVER use on a shared Hermes HOME.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import uuid

from scripts.h777_ecc_native_uninstall_gate import (
    ECC_SHA, KNOWN_RESIDUAL, NODE_IMAGE, checked_checkout,
    sqlite_semantic_snapshot,
)

SCHEMA = "h777-owned-ecc-home-v1"
MARKER = ".h777-ecc-owned.json"
LOCK = ".h777-ecc.lock"
ROOT_FORMAT = re.compile(r"h777-ecc-[0-9a-f]{32}\Z")
CONTAINER_ROOT = PurePosixPath("/test-home/.hermes")
CANONICAL_STATE = ".hermes/ecc-install-state.json"
ALLOWED_STATE_TABLES = frozenset({
    "schema_migrations", "sessions", "skill_runs", "skill_versions",
    "decisions", "install_state", "governance_events", "work_items",
})
RESERVED = frozenset({MARKER, LOCK})


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lstat(path: Path) -> os.stat_result:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("Symlink in isolated lifecycle path")
    return st


def _ancestors_no_links(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    for candidate in (absolute, *absolute.parents):
        st = _lstat(candidate)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("Non-directory parent in isolated lifecycle path")
    return absolute


def validate_base(base: Path) -> Path:
    base = _ancestors_no_links(base)
    if (base == Path.home() or any(part in {
            ".hermes", ".claude", "second-brain", "your-fitness-coach",
            "yfc", "hermes", "hermes-agent",
        } for part in base.parts)):
        raise ValueError("Refusing shared runtime / project / HOME as sandbox base")
    st = _lstat(base)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise ValueError("Sandbox base must be owned by caller, not group/world-writable")
    if os.geteuid() == 0 or sys.platform != "linux":
        raise ValueError("Isolated lifecycle requires an unprivileged Linux account")
    return base


def _verify_home(home: Path) -> tuple[Path, dict]:
    home = _ancestors_no_links(home)
    if not ROOT_FORMAT.fullmatch(home.name):
        raise ValueError("Not an H777 generated isolated HOME")
    _ = validate_base(home.parent)
    st = _lstat(home)
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("Isolated HOME must be private and owned by caller")
    marker = home / MARKER
    marker_st = _lstat(marker)
    if not stat.S_ISREG(marker_st.st_mode) or marker_st.st_uid != os.geteuid():
        raise ValueError("Invalid H777 ownership marker")
    if (marker_st.st_nlink != 1 or marker_st.st_size > 2_000_000
            or marker_st.st_mode & 0o077):
        raise ValueError("Unsafe H777 ownership marker")
    fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev != marker_st.st_dev
                or opened.st_ino != marker_st.st_ino
                or opened.st_nlink != 1):
            raise ValueError("H777 marker identity changed")
        data = json.load(stream)
    if not isinstance(data, dict) or any((
        data.get("schema") != SCHEMA,
        data.get("root_name") != home.name,
        data.get("base") != str(home.parent),
        data.get("root_dev") != st.st_dev,
        data.get("root_ino") != st.st_ino,
        data.get("owner_uid") != st.st_uid,
        data.get("ecc_sha") != ECC_SHA,
        data.get("node_image") != NODE_IMAGE,
        data.get("phase") not in ("PREPARING", "READY", "RETIRING"),
        not isinstance(data.get("files"), dict),
        not isinstance(data.get("planned"), list),
        not isinstance(data.get("dirs"), list),
    )):
        raise ValueError("H777 marker provenance / scope mismatch")
    return home, data


@contextmanager
def exclusive_lock(home: Path):
    lock = home / LOCK
    st = _lstat(lock)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError("Unsafe H777 lock file")
    if st.st_uid != os.geteuid() or st.st_size != 0:
        raise ValueError("H777 lock was modified")
    fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fst = os.fstat(fd)
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ValueError("H777 lock inode changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise ValueError("H777 lifecycle already in progress") from e
        yield
    finally:
        os.close(fd)


def _write_marker(home: Path, marker: dict) -> None:
    temp = home / (".h777-" + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        data = (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode("utf-8")
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, home / MARKER)
    finally:
        if temp.exists():
            temp.unlink()


def _safe_file_digest(file: Path, expected_dev: int, uid: int) -> str:
    st = _lstat(file)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid
            or st.st_nlink != 1 or st.st_dev != expected_dev):
        raise ValueError("Unowned / hardlinked / unexpected file in isolated HOME")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(file, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev != st.st_dev or opened.st_ino != st.st_ino
                or opened.st_nlink != 1):
            raise ValueError("File identity changed during read")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        return checksum
    finally:
        os.close(fd)


def inventory(home: Path) -> tuple[dict[str, str], list[str]]:
    """Refuse links, hardlinks, special files, foreign ownership and devices."""
    root_st = _lstat(home)
    files: dict[str, str] = {}
    dirs: list[str] = []
    for directory, children, names in os.walk(home, topdown=True, followlinks=False):
        parent = Path(directory)
        dstat = _lstat(parent)
        if (not stat.S_ISDIR(dstat.st_mode) or dstat.st_uid != root_st.st_uid
                or dstat.st_dev != root_st.st_dev):
            raise ValueError("Unexpected directory in isolated HOME")
        for name in sorted(children):
            item = parent / name
            st = _lstat(item)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != root_st.st_uid
                    or st.st_dev != root_st.st_dev):
                raise ValueError("Unsafe directory or link in isolated HOME")
            dirs.append(item.relative_to(home).as_posix())
        for name in sorted(names):
            item = parent / name
            rel = item.relative_to(home).as_posix()
            digest = _safe_file_digest(item, root_st.st_dev, root_st.st_uid)
            if rel not in RESERVED:
                files[rel] = digest
            elif rel == LOCK and digest != sha256(b""):
                raise ValueError("Modified lock file")
    return files, sorted(dirs)


def planned_files(raw: str) -> set[str]:
    plan = json.loads(raw)
    ops = plan["plan"]["operations"]
    if not isinstance(ops, list) or not ops:
        raise ValueError("ECC installer returned empty plan")
    managed: set[str] = set()
    for entry in ops:
        full = PurePosixPath(entry["destinationPath"])
        if ".." in full.parts:
            raise ValueError("Installer plan contains traversal")
        try:
            rel = full.relative_to(CONTAINER_ROOT)
        except ValueError as e:
            raise ValueError("Installer plan crosses isolated Hermes root") from e
        if str(rel) == "." or not rel.parts:
            raise ValueError("Installer plan tries to replace Hermes root")
        managed.add(".hermes/" + rel.as_posix())
    if any(p in RESERVED for p in managed):
        raise ValueError("Installer plan overlaps lifecycle markers")
    return managed


def _native_command(ecc: Path, home: Path, tool: str, args: list[str]) -> list[str]:
    if tool not in ("install", "doctor", "uninstall"):
        raise ValueError("Unsupported original ECC entrypoint")
    source = checked_checkout(ecc)
    if source["upstream_ecc_sha"] != ECC_SHA:
        raise ValueError("Wrong ECC SHA")
    # Verify no tracked or untracked source modifications (node_modules is ignored).
    status = subprocess.run(["git", "-C", str(ecc), "status", "--porcelain",
                             "--untracked-files=normal"], capture_output=True,
                            text=True, check=True, timeout=15)
    if status.stdout.strip():
        raise ValueError("Original ECC checkout has unreviewed source changes")
    if tool == "install":
        entry, argv = "/bin/bash", ["./install.sh", "--target", "hermes",
                                     "--profile", "minimal", *args]
    elif tool == "doctor":
        entry, argv = "/usr/local/bin/node", ["scripts/doctor.js",
                                              "--target", "hermes", "--json"]
    else:
        entry, argv = "/usr/local/bin/node", ["scripts/uninstall.js",
                                              "--target", "hermes", "--json"]
    return [
        "docker", "run", "--rm", "--init", "--pull=never",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", f"{os.geteuid()}:{os.getegid()}", "--pids-limit", "64",
        "--memory", "1024m", "--cpus", "1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--mount", f"type=bind,src={ecc.resolve()},dst=/ecc,readonly",
        "--mount", f"type=bind,src={home},dst=/test-home",
        "--env", "HOME=/test-home", "--env", "HERMES_HOME=/test-home/.hermes",
        "--env", "HERMES_WRITE_SAFE_ROOT=/test-home/.hermes",
        "--workdir", "/ecc", "--entrypoint", entry, NODE_IMAGE, *argv,
    ]


def _native(ecc: Path, home: Path, tool: str, *args: str) -> str:
    proc = subprocess.run(_native_command(ecc, home, tool, list(args)),
                          capture_output=True, text=True, timeout=250,
                          check=False)
    if proc.returncode:
        raise RuntimeError(
            f"Original ECC {tool} exit={proc.returncode}, "
            f"stderr_sha256={sha256(proc.stderr.encode('utf-8'))}")
    return proc.stdout


def _ensure_original_store_is_only_cache(home: Path) -> None:
    db = home / KNOWN_RESIDUAL
    if not db.is_file() or db.is_symlink():
        return
    _safe_file_digest(db, home.stat().st_dev, os.geteuid())
    snap = sqlite_semantic_snapshot(db)
    counts = snap["table_counts"]
    if set(counts) - ALLOWED_STATE_TABLES:
        raise ValueError("Unreviewed SQLite tables; refusing to delete state.db")
    if "install_state" not in counts:
        raise ValueError("Missing expected ECC SQLite schema")
    if any(value for key, value in counts.items() if key != "schema_migrations"):
        raise ValueError("ECC SQLite contains non-cache data; refusing to delete")


def _allowed_dirs(files: set[str]) -> set[str]:
    result = {".hermes", ".claude", ".claude/ecc"}
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) not in (".", ""):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _ready_files(marker: dict, actual: dict, *, resuming: bool) -> None:
    expected = marker["files"]
    if marker["phase"] == "PREPARING":
        allow = set(marker["planned"]) | {CANONICAL_STATE, KNOWN_RESIDUAL}
    else:
        allow = set(expected)
    if set(actual) - allow:
        raise ValueError("New or unrelated files in managed HOME; refusing rollback")
    if marker["phase"] == "READY" and set(actual) != set(expected):
        raise ValueError("Missing managed files before native uninstall")
    if marker["phase"] == "READY":
        if any(actual[k] != expected[k] for k in actual):
            raise ValueError("Modified managed file or state.db; refusing rollback")
    elif resuming:
        if any(actual[k] != expected.get(k) for k in actual
               if k != KNOWN_RESIDUAL and k in expected):
            raise ValueError("Modified remaining managed file during interrupted rollback")


def provision(ecc: Path, base: Path) -> dict:
    checked_checkout(ecc)
    base = validate_base(base)
    home = base / ("h777-ecc-" + uuid.uuid4().hex)
    home.mkdir(mode=0o700)
    st = home.stat()
    lock_fd = os.open(home / LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(lock_fd)
    (home / ".hermes").mkdir(mode=0o700)
    record = {
        "schema": SCHEMA, "phase": "PREPARING", "root_name": home.name,
        "base": str(base), "root_dev": st.st_dev, "root_ino": st.st_ino,
        "owner_uid": st.st_uid, "ecc_sha": ECC_SHA, "node_image": NODE_IMAGE,
        "planned": [], "files": {}, "dirs": [".hermes"],
    }
    _write_marker(home, record)
    with exclusive_lock(home):
        raw = _native(ecc, home, "install", "--dry-run", "--json")
        planned = planned_files(raw)
        pre, _ = inventory(home)
        if pre:
            raise ValueError("Upstream dry-run wrote to isolated HOME")
        record["planned"] = sorted(planned)
        _write_marker(home, record)
        _native(ecc, home, "install", "--json")
        after, _ = inventory(home)
        expected = planned | {CANONICAL_STATE, KNOWN_RESIDUAL}
        if set(after) != expected:
            raise ValueError("Native install wrote an unreviewed path")
        _native(ecc, home, "install", "--json")
        again, _ = inventory(home)
        if set(again) != set(after):
            raise ValueError("Original reinstall changed file inventory")
        if any(after[k] != again[k] for k in planned):
            raise ValueError("Original reinstall changed managed skill/rule content")
        doctor = json.loads(_native(ecc, home, "doctor"))
        if doctor.get("summary", {}).get("errorCount") != 0:
            raise ValueError("Original ECC doctor reported failures")
        final, dirs = inventory(home)
        if set(final) != expected:
            raise ValueError("Original ECC doctor introduced unreviewed files")
        # The install_state projection must be removed by original uninstall.
        # During installation install_state contains the current target; only
        # retire after removing that projection using the original uninstaller.
        record.update({"files": final, "dirs": dirs, "phase": "READY"})
        _write_marker(home, record)
    return {"status": "PASS_ISOLATED_PROVISION", "home": str(home),
            "managed_count": len(planned), "ecc_sha": ECC_SHA,
            "resident_activation": "NOT_RUN"}


def inspect(home: Path) -> dict:
    home, rec = _verify_home(home)
    with exclusive_lock(home):
        actual, dirs = inventory(home)
        allowed = (
            set(rec["files"]) if rec["phase"] != "PREPARING"
            else set(rec["planned"]) | {CANONICAL_STATE, KNOWN_RESIDUAL})
        unexpected = sorted(set(actual) - allowed)
        modified = sorted(k for k in actual if k in rec["files"]
                          and actual[k] != rec["files"][k]
                          and not (rec["phase"] == "RETIRING"
                                   and k == KNOWN_RESIDUAL))
        missing = sorted(set(rec["files"]) - set(actual)) if rec["phase"] == "READY" else []
        unexpected_dirs = sorted(set(dirs) - (
            set(rec["dirs"]) | _allowed_dirs(set(rec["planned"])
                | {CANONICAL_STATE, KNOWN_RESIDUAL})))
        safe = not (unexpected or modified or missing or unexpected_dirs)
        status = ("BLOCKED_UNSAFE" if not safe else
                  "PASS_INVENTORY" if rec["phase"] == "READY" else
                  "INCOMPLETE_LIFECYCLE")
        return {"status": status,
                "home": str(home), "phase": rec["phase"],
                "file_count": len(actual), "unexpected": unexpected,
                "modified": modified, "missing": missing,
                "unexpected_dirs": unexpected_dirs,
                "ecc_sha": rec["ecc_sha"], "dir_count": len(dirs)}


def retire(ecc: Path, home: Path) -> dict:
    checked_checkout(ecc)
    home, rec = _verify_home(home)
    with exclusive_lock(home):
        actual, dirs = inventory(home)
        _ready_files(rec, actual, resuming=rec["phase"] == "RETIRING")
        allow_dirs = set(rec["dirs"]) | _allowed_dirs(
            set(rec["planned"]) | {CANONICAL_STATE, KNOWN_RESIDUAL})
        if set(dirs) - allow_dirs:
            raise ValueError("Unexpected directory in managed HOME")
        if rec["phase"] != "RETIRING":
            rec["phase"] = "RETIRING"
            _write_marker(home, rec)
        _native(ecc, home, "uninstall")
        after, remaining_dirs = inventory(home)
        if set(after) - {KNOWN_RESIDUAL}:
            raise ValueError("Native ECC uninstall left non-cache files; refusing cleanup")
        if set(remaining_dirs) - allow_dirs:
            raise ValueError("Native uninstall created unknown directories")
        _ensure_original_store_is_only_cache(home)
        native_exact = not after
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("Platform lacks safe fd-based rmtree")
        # Root is uniquely generated, private, marker/lock/contents checked,
        # and no user data was present before installation. Never rmtree a
        # shared ~/.hermes, ~/.claude, or any ancestor.
        verified, _ = _verify_home(home)
        if verified != home:
            raise ValueError("H777 owned-root identity changed")
        shutil.rmtree(home)
    return {"status": "PASS_ISOLATED_ROLLBACK", "home_removed": not home.exists(),
            "native_exact_rollback": native_exact,
            "native_residual_before_cleanup": sorted(after),
            "upstream_native_bug": not native_exact,
            "resident_activation": "NOT_RUN"}


def main() -> int:
    if not __debug__:
        print("Python assertions-disabled runtime refused", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="command", required=True)
    create = modes.add_parser("provision", help="Only a new owned isolated HOME")
    create.add_argument("--ecc-root", type=Path, required=True)
    create.add_argument("--base", type=Path, required=True)
    check = modes.add_parser("inspect")
    check.add_argument("--home", type=Path, required=True)
    remove = modes.add_parser("retire", help="Original uninstall plus owned-root rollback")
    remove.add_argument("--ecc-root", type=Path, required=True)
    remove.add_argument("--home", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "provision":
            result = provision(args.ecc_root, args.base)
        elif args.command == "retire":
            result = retire(args.ecc_root, args.home)
        else:
            result = inspect(args.home)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["status"].startswith("PASS") else 1
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": type(exc).__name__,
                          "detail": str(exc)[:160]}, ensure_ascii=False),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
