"""Opt-in serial scheduler tick. No public submission or inference by default.

An administrator supplies root-owned manifests outside the deploy archive.
The timer can only execute previously bound manifests; quotas are read from
the existing official Codex app-server collector (issue #255).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from .codex_scheduler import (
    Approval, DEFAULT_DB, Scheduler, QuotaWorker, ValidationError,
)
from .codex_scheduler_executor import OfficialCodexExecutor
from .codex_usage import DEFAULT_OUTPUT, read_snapshot

STATE_DIR = DEFAULT_DB.parent
ARTIFACT_DIR = STATE_DIR / "artifacts"
CONFIG_KEYS = frozenset({
    "schema", "enabled", "owner", "models", "repository_roots",
    "codex_binary", "codex_home", "grants_directory",
})
GRANT_KEYS = frozenset({"schema", "approval", "task", "instruction"})


def _trusted_file(path: Path, *, uid: int = 0, max_size: int = 65536) -> bytes:
    """Read only admin-owned non-symlink regular files, not arbitrary task paths."""
    if not path.is_absolute() or path.is_symlink():
        raise ValidationError("untrusted_file_path")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o027 or info.st_size > max_size):
        raise ValidationError("untrusted_file_permissions")
    return path.read_bytes()


def _trusted_directory(path: Path, *, uid: int = 0) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValidationError("untrusted_grants_directory")
    info = path.stat()
    if info.st_uid != uid or info.st_mode & 0o027:
        raise ValidationError("untrusted_grants_permissions")


def load_configuration(path: Path, *, uid: int = 0) -> dict:
    try:
        conf = json.loads(_trusted_file(path, uid=uid))
    except (ValueError, OSError, UnicodeError) as exc:
        raise ValidationError("invalid_worker_configuration") from exc
    if not isinstance(conf, dict) or set(conf) != CONFIG_KEYS or conf.get("schema") != 1:
        raise ValidationError("invalid_worker_schema")
    if type(conf["enabled"]) is not bool or conf["owner"] != "MikeMoore1337":
        raise ValidationError("worker_owner_gate")
    if (not isinstance(conf["models"], list) or not conf["models"]
            or any(type(v) is not str or not v or len(v) > 80 for v in conf["models"])
            or len(set(conf["models"])) != len(conf["models"])):
        raise ValidationError("worker_models_invalid")
    roots = conf["repository_roots"]
    if not isinstance(roots, dict) or not roots or any(
        not isinstance(repo, str) or type(value) is not str or
        not Path(value).is_absolute() or Path(value).is_symlink()
        for repo, value in roots.items()
    ):
        raise ValidationError("worker_repository_roots_invalid")
    for field in ("codex_binary", "codex_home", "grants_directory"):
        value = conf[field]
        if type(value) is not str or not Path(value).is_absolute():
            raise ValidationError("worker_path_invalid")
    _trusted_directory(Path(conf["grants_directory"]), uid=uid)
    return conf


def _load_manifests(directory: Path, *, uid: int = 0) -> list[tuple[Approval, dict, str, str]]:
    _trusted_directory(directory, uid=uid)
    parsed = []
    for path in sorted(directory.iterdir()):
        if path.suffix != ".json" or path.is_symlink():
            raise ValidationError("unexpected_grant_file")
        try:
            raw = _trusted_file(path, uid=uid, max_size=16000)
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != GRANT_KEYS or data["schema"] != 1:
                raise ValidationError("grant_schema_invalid")
            fields = {"approval_id", "initiator", "repository", "allowed_operations",
                      "model", "effort", "resource_limits", "expires_at"}
            a = data["approval"]
            if not isinstance(a, dict) or set(a) != fields:
                raise ValidationError("grant_approval_invalid")
            approval = Approval(**a)
            task = data["task"]
            prompt = data["instruction"]
            if (not isinstance(task, dict) or task.get("approval_id") != approval.approval_id
                    or type(prompt) is not str or not 1 <= len(prompt) <= 8000):
                raise ValidationError("grant_task_invalid")
            parsed.append((approval, task, prompt, hashlib.sha256(raw).hexdigest()))
        except (ValueError, TypeError, OSError, UnicodeError) as exc:
            raise ValidationError("grant_content_invalid") from exc
    if len({a.approval_id for a, _, _, _ in parsed}) != len(parsed):
        raise ValidationError("duplicate_grant_id")
    return parsed


def _bind_manifest(scheduler: Scheduler, approval: Approval,
                   task: dict, digest: str) -> None:
    """Persist immutable full manifest digest, including the prompt."""
    with scheduler._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS grant_bindings
                        (approval_id TEXT PRIMARY KEY, digest TEXT NOT NULL)""")
        row = conn.execute("SELECT digest FROM grant_bindings WHERE approval_id=?",
                           (approval.approval_id,)).fetchone()
        if row is not None and row["digest"] != digest:
            raise ValidationError("grant_manifest_changed")
        if row is None:
            conn.execute("INSERT INTO grant_bindings VALUES (?,?)",
                         (approval.approval_id, digest))
        conn.commit()
    scheduler.register_approval(approval, verified_owner=scheduler.owner_identity)
    scheduler.submit(task)


def _artifact_directory() -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if ARTIFACT_DIR.is_symlink() or ARTIFACT_DIR.stat().st_mode & 0o077:
        raise ValidationError("artifact_permissions")
    return ARTIFACT_DIR


def run_once(config_path: Path, *, uid: int = 0, run: bool = False) -> dict:
    conf = load_configuration(config_path, uid=uid)
    manifests = _load_manifests(Path(conf["grants_directory"]), uid=uid)
    if not run:
        return {"mode": "preflight", "manifest_count": len(manifests)}
    # Both --run and independently administered enabled=true are mandatory.
    if not conf["enabled"]:
        return {"mode": "disabled"}
    root_paths = {name: Path(value) for name, value in conf["repository_roots"].items()}
    if any(not root.is_dir() for root in root_paths.values()):
        raise ValidationError("repository_missing")
    binary, home = Path(conf["codex_binary"]), Path(conf["codex_home"])
    if binary.is_symlink() or not binary.is_file() or home.is_symlink() or not home.is_dir():
        raise ValidationError("codex_runtime_missing")
    scheduler = Scheduler(DEFAULT_DB, repositories=set(root_paths),
                          models=set(conf["models"]), group_readable=True)
    scheduler.initialize()
    # Check all manifest hashes BEFORE enrolling any job, to avoid partial
    # execution when a previously approved instruction was modified.
    with scheduler._connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS grant_bindings
                        (approval_id TEXT PRIMARY KEY, digest TEXT NOT NULL)""")
        for approval, _, _, digest in manifests:
            row = conn.execute("SELECT digest FROM grant_bindings WHERE approval_id=?",
                               (approval.approval_id,)).fetchone()
            if row is not None and row["digest"] != digest:
                raise ValidationError("grant_manifest_changed")
    instructions = {}
    for approval, task, prompt, digest in manifests:
        _bind_manifest(scheduler, approval, task, digest)
        instructions[approval.approval_id] = prompt
    # Recover ambiguous prior execution, but never replay it automatically.
    scheduler.recover()
    executor = OfficialCodexExecutor(
        repo_roots=root_paths, approved_instructions=instructions,
        binary=binary, codex_home=home, artifact_dir=_artifact_directory(),
        enabled=True)
    worker = QuotaWorker(scheduler,
                         snapshot=lambda: read_snapshot(DEFAULT_OUTPUT),
                         executor=executor)
    outcome = worker.tick()
    # Never expose task contents, instructions, provider tokens, or output.
    if outcome is None:
        return {"mode": "idle"}
    return {"mode": "tick", "decision": outcome["decision"],
            "reason": outcome.get("reason"), "job_id": outcome.get("job_id")}


def main() -> int:
    parser = argparse.ArgumentParser(description="H-15 restricted Codex task tick")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="requires root-owned enabled=true")
    args = parser.parse_args()
    try:
        result = run_once(args.config, run=args.run)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValidationError, sqlite3.Error, OSError, KeyError, TypeError):
        print("CODEX_SCHEDULER_BLOCKED=preflight_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
