"""Disabled-by-default official Codex CLI adapter.

No fallback, gateway, API key, shell interpolation or account rotation.
A privileged operator must configure an isolated OS identity, repository roots,
a trusted approval_id-to-prompt mapping, and explicit live activation separately.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile

from .codex_scheduler import ValidationError, _limits, _ops


class OfficialCodexExecutor:
    def __init__(self, *, repo_roots: dict[str, Path],
                 approved_instructions: dict[str, str],
                 codex_home: Path, binary: Path,
                 enabled: bool = False):
        self.roots = dict(repo_roots)
        self.instructions = dict(approved_instructions)
        self.home = Path(codex_home)
        self.binary = Path(binary)
        self.enabled = enabled

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
        sandbox = "workspace-write" if "patch" in ops or "prepare_pr" in ops else "read-only"
        # No job JSON field is ever executed as a program or shell fragment.
        argv = [str(self.binary), "exec", "--json",
                "--sandbox", sandbox, "--ask-for-approval", "never",
                "--model", job["model"],
                "--config", "model_reasoning_effort=" + job["effort"], "-"]
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(self.home),
               "CODEX_HOME": str(self.home), "LANG": "C.UTF-8"}
        def resources():
            resource.setrlimit(resource.RLIMIT_CPU,
                               (limits["max_runtime_seconds"] + 5,
                                limits["max_runtime_seconds"] + 5))
            memory = limits["max_memory_mb"] * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
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
            # Digest/exit status are evidence, not a replayable model response.
            return proc.returncode == 0, "sha256:" + digest
