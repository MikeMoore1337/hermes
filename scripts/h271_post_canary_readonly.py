#!/usr/bin/env python3
"""H271: owner-only, read-only post-canary acceptance; never starts a service.

It only reads pinned production source, systemd metadata, private SQLite and
a bounded result artifact. This is NOT authorization to enable the timer.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

OLD_JOB_ID = "16adb6a7-9b7d-445e-9ba9-54c64f53af49"
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
ARTIFACT_RE = re.compile(r"artifact:([a-zA-Z0-9-]{1,64}):([a-f0-9]{64})\Z")
STATE = Path("/var/lib/hermes-codex-scheduler")
DB = STATE / "jobs.sqlite3"
RUNTIME = Path("/etc/hermes-codex-scheduler/runtime.json")
RECEIPT = Path("/var/lib/hermes-main-deploy/last-success.sha")
AGENT = Path("/opt/hermes-agent-owner/releases")
UI = Path("/opt/hermes-control-center")


def required(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def safe_unit_state(unit: str, prop: str) -> str:
    p = subprocess.run(
        ["systemctl", "show", "-P", prop, unit],
        capture_output=True, text=True, timeout=10, check=False,
    )
    required(p.returncode == 0, "systemd_query_unavailable")
    return p.stdout.strip()


def verify_jobs(rows: list[sqlite3.Row]) -> tuple[str, str]:
    """Assert precisely one historical blocked attempt and one delivered success."""
    required(len(rows) == 2, "unexpected_job_count")
    old = [r for r in rows if r["job_id"] == OLD_JOB_ID]
    new = [r for r in rows if r["job_id"] != OLD_JOB_ID]
    required(len(old) == 1 and len(new) == 1, "unexpected_job_identity")
    old, new = old[0], new[0]
    required(
        old["status"] == "blocked"
        and old["attempt_count"] == 1
        and old["invocation_state"] == "reviewed"
        and not old["result_ref"],
        "old_job_invariant",
    )
    required(
        new["status"] == "succeeded"
        and new["attempt_count"] == 1
        and new["invocation_state"] == "finished"
        and new["last_error_code"] is None
        and new["delivered"] is not None
        and new["lease_owner"] is None
        and new["cancellation_requested"] == 0,
        "success_invariant",
    )
    required(isinstance(new["result_ref"], str), "result_reference_missing")
    return new["job_id"], new["result_ref"]


def verify_artifact(job_id: str, result_ref: str, directory: Path) -> None:
    m = ARTIFACT_RE.fullmatch(result_ref)
    required(m is not None and m.group(1) == job_id, "artifact_reference_invalid")
    required(directory.is_dir() and not directory.is_symlink(), "artifact_dir_invalid")
    required(stat.S_IMODE(directory.stat().st_mode) == 0o700, "artifact_dir_mode")
    target = directory / (job_id + "-" + m.group(2) + ".jsonl")
    required(not target.is_symlink() and target.is_file(), "artifact_file_invalid")
    meta = target.stat()
    required(stat.S_IMODE(meta.st_mode) == 0o600 and 0 <= meta.st_size <= 8192,
             "artifact_file_mode_or_size")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    required(digest == m.group(2), "artifact_hash_mismatch")


def verify_installed_unit(source: Path, name: str) -> None:
    installed = Path("/etc/systemd/system") / name
    required(source.is_file() and not source.is_symlink(), "source_unit_missing")
    required(installed.is_file() and not installed.is_symlink(), "installed_unit_missing")
    meta = installed.stat()
    required(meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o644,
             "installed_unit_permissions")
    required(hashlib.sha256(source.read_bytes()).digest() ==
             hashlib.sha256(installed.read_bytes()).digest(), "installed_unit_changed")
    required(
        safe_unit_state(name, "FragmentPath") == str(installed)
        and safe_unit_state(name, "DropInPaths") == "",
        "unit_override_detected",
    )


def main() -> int:
    required(os.geteuid() == 0 and os.uname().nodename.split(".")[0] ==
             "vps1777112993", "owner_vps_root_required")
    sha = RECEIPT.read_text(encoding="ascii").strip()
    required(SHA_RE.fullmatch(sha) is not None, "deploy_sha_invalid")
    release = AGENT / ("main-" + sha)
    required(release.is_dir() and not release.is_symlink(), "release_missing")
    deployment_receipt = release / ".deployment-receipt.txt"
    required(("SHA=" + sha) in deployment_receipt.read_text().splitlines(),
             "deploy_receipt_mismatch")
    required((UI / "current").resolve(strict=True) ==
             (UI / "releases" / ("main-" + sha)), "current_ui_mismatch")

    service = "hermes-codex-scheduler.service"
    timer = "hermes-codex-scheduler.timer"
    verify_installed_unit(release / "deploy" / service, service)
    verify_installed_unit(release / "deploy" / timer, timer)
    required(safe_unit_state(service, "ActiveState") == "inactive"
             and safe_unit_state(service, "MainPID") == "0", "scheduler_active")
    required(safe_unit_state(timer, "UnitFileState") == "disabled"
             and safe_unit_state(timer, "ActiveState") == "inactive", "scheduler_timer_active")
    required(safe_unit_state("hermes-h01-ops-agent.timer", "ActiveState") == "active",
             "h01_not_active")

    from control_center.codex_scheduler_worker import load_configuration, _load_manifests
    from control_center.codex_scheduler import _utc
    conf = load_configuration(RUNTIME)
    required(conf["enabled"] is False, "worker_enabled")
    manifests = _load_manifests(Path(conf["grants_directory"]))
    uri = DB.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        rows = conn.execute("""SELECT job_id, approval_id, status, attempt_count,
                 invocation_state, result_ref, last_error_code, delivered,
                 lease_owner, cancellation_requested FROM jobs""").fetchall()
        job_id, result_ref = verify_jobs(rows)
        referenced = {r["approval_id"] for r in rows}
        now = time.time()
        active_unbound = sum(1 for grant, task, _, _ in manifests
                             if _utc(grant.expires_at) > now
                             and _utc(task["expires_at"]) > now
                             and grant.approval_id not in referenced)
        required(active_unbound == 0, "unbound_live_grants")
    verify_artifact(job_id, result_ref, STATE / "artifacts")

    print("DEPLOYED_SOURCE=VERIFIED")
    print("SERVICE_UNIT=VERIFIED_UNMODIFIED")
    print("TIMER_UNIT=VERIFIED_UNMODIFIED")
    print("SCHEDULER_SERVICE=INACTIVE")
    print("SCHEDULER_TIMER=DISABLED")
    print("H01_TIMER=ACTIVE")
    print("WORKER_DISABLED=True")
    print("TOTAL_JOBS=2")
    print("OLD_JOB=BLOCKED_REVIEWED_NO_RETRY")
    print("NEW_JOB=SUCCEEDED_ONCE")
    print("DURABLE_ARTIFACT_SHA256=PASS")
    print("DELIVERED_RESULT=PASS")
    print("ACTIVE_UNBOUND_GRANTS=0")
    print("POST_CANARY_READONLY_AUDIT=PASS")
    print("TIMER_ACTIVATION=HOLD_H01_AND_SEPARATE_OWNER_GATE")
    print("CHANGES_PERFORMED=NO")
    print("MODEL_CALLS_ADDED=0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError,
            KeyError, TypeError, ImportError) as exc:
        # No raw exception message: paths, task contents and grants are private.
        print("POST_CANARY_READONLY_AUDIT=HOLD_" + type(exc).__name__,
              file=sys.stderr)
        raise SystemExit(2)
