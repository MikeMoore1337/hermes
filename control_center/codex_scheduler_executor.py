"""Disabled-by-default official Codex CLI adapter.

No fallback, gateway, API key, shell interpolation or account rotation.
A privileged operator must configure an isolated OS identity, repository roots,
a trusted approval_id-to-prompt mapping, and explicit live activation separately.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path, PurePosixPath
import resource
import signal
import subprocess
import tempfile

from .codex_scheduler import ValidationError, _limits, _ops

_CGROUP_ROOT = Path("/sys/fs/cgroup")
_PROC_CGROUP = Path("/proc/self/cgroup")


def _effective_cgroup_memory_max() -> int | None:
    """Effective Linux cgroup-v2 physical memory cap, including ancestors.

    RLIMIT_AS is unsuitable for Node/V8: it may reserve vast virtual address
    ranges without consuming equivalent RAM. Require a real cgroup memory.max.
    """
    try:
        records = [
            line.partition("::")[2]
            for line in _PROC_CGROUP.read_text(encoding="ascii").splitlines()
            if line.startswith("0::")
        ]
        if len(records) != 1 or not records[0].startswith("/"):
            return None
        parts = PurePosixPath(records[0]).parts[1:]
        if any(part in (".", "..") for part in parts):
            return None
        current = _CGROUP_ROOT
        if not current.is_dir() or current.is_symlink():
            return None
        ceiling = None
        for part in (None, *parts):
            if part is not None:
                current = current / part
                if current.is_symlink():
                    return None
            value = (current / "memory.max").read_text(encoding="ascii").strip()
            if value == "max":
                continue
            if not value.isdecimal() or int(value) <= 0:
                return None
            limit = int(value)
            ceiling = limit if ceiling is None else min(ceiling, limit)
        return ceiling
    except (OSError, UnicodeError, ValueError):
        return None


class OfficialCodexExecutor:
    def __init__(self, *, repo_roots: dict[str, Path],
                 approved_instructions: dict[str, str],
                 codex_home: Path, binary: Path,
                 enabled: bool = False, artifact_dir: Path | None = None):
        self.roots = dict(repo_roots)
        self.instructions = dict(approved_instructions)
        self.home = Path(codex_home)
        self.binary = Path(binary)
        self.enabled = enabled
        self.artifact_dir = Path(artifact_dir) if artifact_dir is not None else None

    def execute(self, job: dict) -> tuple[bool, str | None]:
        if self.enabled is not True:
            raise ValidationError("live_worker_not_authorized")
        repo = job["repository"]
        approval_id = job["approval_id"]
        root = self.roots.get(repo)
        prompt = self.instructions.get(approval_id)
        if (root is None or not root.is_dir() or root.is_symlink()
                or not isinstance(prompt, str) or not 1 <= len(prompt) <= 8000):
            raise ValidationError("trusted_execution_plan_missing")
        root = root.resolve(strict=True)
        if not self.binary.is_file() or self.binary.is_symlink():
            raise ValidationError("official_codex_cli_missing")
        if not self.home.is_dir() or self.home.is_symlink():
            raise ValidationError("isolated_codex_home_missing")
        ops = _ops(list(job["allowed_operations"]))
        limits = _limits(job["resource_limits"])
        if not ops or job["effort"] not in ("low", "medium", "high"):
            raise ValidationError("execution_scope_invalid")
        # Refuse to run if the actual RAM cgroup is absent or looser than
        # the immutable, owner-approved per-job memory budget.
        physical_ceiling = _effective_cgroup_memory_max()
        if (physical_ceiling is None or
                physical_ceiling > limits["max_memory_mb"] * 1024 * 1024):
            raise ValidationError("memory_cgroup_unverified")
        sandbox = "workspace-write" if "patch" in ops or "prepare_pr" in ops else "read-only"
        # No job JSON field is ever executed as a program or shell fragment.
        # Production CD uses immutable git-archive releases (no .git directory).
        # A read-only Codex canary may inspect those trusted sources; writes
        # still require a real Git checkout rather than bypassing the CLI gate.
        is_git_checkout = (root / ".git").exists()
        if sandbox != "read-only" and not is_git_checkout:
            raise ValidationError("writable_git_checkout_required")
        argv = [str(self.binary), "--ask-for-approval", "never",
                "exec", "--json", "--sandbox", sandbox,
                "--model", job["model"],
                "--config", "model_reasoning_effort=" + job["effort"]]
        if not is_git_checkout:
            argv.append("--skip-git-repo-check")
        argv.append("-")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(self.home),
               "CODEX_HOME": str(self.home), "LANG": "C.UTF-8"}
        def resources():
            resource.setrlimit(resource.RLIMIT_CPU,
                               (limits["max_runtime_seconds"] + 5,
                                limits["max_runtime_seconds"] + 5))
            # The trusted service's cgroup MemoryMax enforces physical RAM.
            # RLIMIT_AS would instead crash Node/V8 on virtual reservations.
            size = limits["max_output_bytes"]
            resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(
                argv, cwd=root, env=env, stdin=subprocess.PIPE, stdout=output,
                stderr=subprocess.DEVNULL, start_new_session=True,
                preexec_fn=resources, close_fds=True)
            try:
                proc.communicate(input=prompt.encode("utf-8"),
                                 timeout=limits["max_runtime_seconds"])
            except subprocess.TimeoutExpired as exc:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
                raise RuntimeError("codex_timeout_outcome_uncertain") from exc
            if output.tell() > limits["max_output_bytes"]:
                raise RuntimeError("codex_output_limit")
            output.seek(0)
            digest = hashlib.sha256(output.read()).hexdigest()
            if proc.returncode != 0:
                return False, None
            if self.artifact_dir is None:
                # Compatibility with offline fake-executor tests only.
                return True, "sha256:" + digest
            # Persist before the queue commits succeeded. A crash here is
            # intentionally uncertain and must never cause a second inference.
            jid = job.get("job_id")
            if not isinstance(jid, str) or not re.fullmatch(r"[a-zA-Z0-9-]{1,64}", jid):
                raise ValidationError("artifact_job_id_invalid")
            directory = self.artifact_dir
            if not directory.is_dir() or directory.is_symlink():
                raise ValidationError("artifact_directory_missing")
            if directory.stat().st_mode & 0o077:
                raise ValidationError("artifact_directory_permissions")
            name = jid + "-" + digest + ".jsonl"
            target = directory / name
            if target.exists() or target.is_symlink():
                raise ValidationError("artifact_already_exists")
            tmp_name = None
            try:
                with tempfile.NamedTemporaryFile(dir=directory, prefix=".artifact-",
                                                 delete=False) as result:
                    tmp_name = result.name
                    os.chmod(tmp_name, 0o600)
                    output.seek(0)
                    shutil.copyfileobj(output, result)
                    result.flush()
                    os.fsync(result.fileno())
                os.replace(tmp_name, target)
                dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            finally:
                if tmp_name and os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            return True, "artifact:" + jid + ":" + digest
