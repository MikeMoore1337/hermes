"""Fixed argv builder for the disabled Hermes #349 Skill Evals lane.

Never executes argv; activation needs reviewed OS sandbox, enforced egress and
hard provider quota, in a disposable non-production executor identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from .protocol import AdmissionDenied, validate_job


@dataclass(frozen=True)
class FixedPlan:
    argv: tuple[str, ...]
    cwd: Path
    output_dir: Path


def pinned_toolkit(root: Path, required_sha: str) -> None:
    """Only a clean, exact-Git-SHA ADT checkout is eligible.

    No path from an untrusted job is used to discover this root.
    """
    if (not root.is_absolute() or root.is_symlink() or
            not root.is_dir() or not (root / "scripts" / "agent_eval_runner.py").is_file()):
        raise AdmissionDenied("trusted_toolkit_source_missing")
    git = root / ".git"
    if git.is_symlink() or not git.exists():
        raise AdmissionDenied("trusted_toolkit_checkout_required")
    try:
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdmissionDenied("unable_to_verify_toolkit_source") from exc
    if sha != required_sha or dirty:
        raise AdmissionDenied("toolkit_pin_or_cleanliness_mismatch")


def fixed_plan(job: dict, *, toolkit_root: Path, python_binary: Path,
               evidence_root: Path, approved_models: frozenset[str],
               clock: float | None = None) -> FixedPlan:
    """No shell, arbitrary args, repo path, environment or provider fallback."""
    checked = validate_job(job, clock=clock)
    if checked["model"] not in approved_models:
        raise AdmissionDenied("model_not_preapproved")
    if (not python_binary.is_absolute() or python_binary.is_symlink() or
            not python_binary.is_file()):
        raise AdmissionDenied("dedicated_python_binary_required")
    if (not evidence_root.is_absolute() or evidence_root.is_symlink() or
            not evidence_root.is_dir() or
            evidence_root.stat().st_mode & 0o077):
        raise AdmissionDenied("private_evidence_root_required")
    total_attempts = 2 * checked["trials"] * len(checked["case_ids"])
    if total_attempts * checked["timeout_seconds"] > 3600:
        raise AdmissionDenied("aggregate_runtime_limit")
    pinned_toolkit(toolkit_root, checked["toolkit_sha"])
    path = evidence_root / checked["job_id"]
    if path.exists() or path.is_symlink():
        raise AdmissionDenied("evidence_already_exists")
    argv = (
        str(python_binary), str(toolkit_root / "scripts" / "agent_eval_runner.py"),
        "--provider", checked["provider"], "--model", checked["model"],
        "--cases", *checked["case_ids"], "--trials", str(checked["trials"]),
        "--max-seconds", str(checked["timeout_seconds"]),
        "--output", str(path),
        "--execute", "--acknowledge-costs", "--acknowledge-isolation",
    )
    return FixedPlan(argv=argv, cwd=toolkit_root, output_dir=path)
