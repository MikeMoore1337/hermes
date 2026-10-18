"""Dormant POSIX-only bounded adapter for ADT Skill Evals (#349).

Not a service, remote shell or H-01 capability. External OS-level sandbox,
egress policy and provider HARD billing guard must be established separately.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time
from typing import Callable

from .fixed_plan import fixed_plan
from .protocol import AdmissionDenied
from .owner_spend_lock import assert_owner_real_execution_allowed


class LocalBoundedExecutor:
    """Explicitly disabled by default; callable only by trusted one-shot lane.

    No shell, remote command input, provider fallback or automatic retry.
    Only an isolated non-root *Linux* worker may ever be approved to call it.
    """

    def __init__(
        self, *, toolkit_root: Path, python_binary: Path, evidence_root: Path,
        isolated_home: Path, approved_models: frozenset[str],
        enabled: bool = False,
        isolation_probe: Callable[[], bool] | None = None,
        cancellation_requested: Callable[[], bool] | None = None,
    ):
        self.toolkit_root = Path(toolkit_root)
        self.python_binary = Path(python_binary)
        self.evidence_root = Path(evidence_root)
        self.isolated_home = Path(isolated_home)
        self.approved_models = approved_models
        self.enabled = enabled
        self.isolation_probe = isolation_probe
        self.cancellation_requested = cancellation_requested

    def _preflight(self) -> None:
        if self.enabled is not True:
            raise AdmissionDenied("local_execution_disabled")
        if os.name != "posix" or not hasattr(os, "getuid") or os.geteuid() == 0:
            raise AdmissionDenied("dedicated_nonroot_posix_identity_required")
        home = self.isolated_home
        if (not home.is_absolute() or not home.is_dir() or home.is_symlink()
                or home.stat().st_uid != os.getuid() or
                home.stat().st_mode & 0o077):
            raise AdmissionDenied("isolated_private_home_required")
        if self.isolation_probe is None or self.isolation_probe() is not True:
            raise AdmissionDenied("external_isolation_attestation_required")

    @staticmethod
    def _resources(job: dict) -> Callable[[], None]:
        limits = job["resource_limits"]
        def enforce() -> None:
            os.umask(0o077)  # All child-created oracle logs/evidence remain private.
            # These are SECONDARY limits; container cgroups and network ACL
            # must be enforced by a separately approved OS policy.
            cpu = limits["cpu_seconds"]
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            memory = limits["memory_mb"] * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
            size = limits["output_bytes"]
            resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return enforce

    def __call__(self, job: dict) -> dict:
        self._preflight()
        # Explicit owner NO-SPEND decision. Neither enabled=True, a signed
        # job, a forged owner gate nor environment variables may unlock this.
        # Keep this check outside _preflight: tests sometimes mock _preflight.
        assert_owner_real_execution_allowed()
        plan = fixed_plan(
            job, toolkit_root=self.toolkit_root,
            python_binary=self.python_binary, evidence_root=self.evidence_root,
            approved_models=self.approved_models,
        )
        if self.cancellation_requested is not None and self.cancellation_requested():
            raise AdmissionDenied("owner_cancelled_before_launch")
        wall = min(3600, 2 * job["trials"] * len(job["case_ids"])
                   * job["timeout_seconds"] + 60)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.isolated_home),
            "CODEX_HOME": str(self.isolated_home / ".codex"),
            "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "GOPROXY": "off",
            "GOSUMDB": "off",
        }
        # Discard top-level runner log; per-attempt evidence is PRIVATE and
        # reviewed manually before any export.
        process = subprocess.Popen(
            list(plan.argv), cwd=plan.cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True,
            start_new_session=True, preexec_fn=self._resources(job),
        )
        started = time.monotonic()
        try:
            while True:
                if (self.cancellation_requested is not None and
                        self.cancellation_requested()):
                    raise AdmissionDenied("owner_cancelled_during_execution")
                remaining = wall - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("skill_evals_total_wall_timeout")
                try:
                    status = process.wait(timeout=min(1.0, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise
        if status != 0:
            return {"outcome": "failed", "artifact_sha256": "0" * 64}
        root = plan.output_dir
        if (not root.is_dir() or root.is_symlink() or root.is_junction()
                or not root.resolve().is_relative_to(self.evidence_root.resolve())
                or root.stat().st_mode & 0o077):
            raise AdmissionDenied("execution_evidence_root_unsafe")
        record = root / "observations.json"
        if (not record.is_file() or record.is_symlink() or record.is_junction()
                or not record.resolve().is_relative_to(self.evidence_root.resolve())
                or record.stat().st_size > job["resource_limits"]["output_bytes"]):
            raise AdmissionDenied("execution_evidence_missing_or_unbounded")
        return {"outcome": "succeeded",
                "artifact_sha256": hashlib.sha256(record.read_bytes()).hexdigest()}
