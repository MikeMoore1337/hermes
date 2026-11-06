#!/usr/bin/env python3
"""Hermes #795: unmodified ECC uninstall negatives in disposable GitHub Docker homes.

No user HOME, no shared database cleanup, no upstream patch, no resident service.
The H777 managed lifecycle is deliberately not imported or modified.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from scripts.h777_ecc_native_uninstall_gate import (
    ECC_SHA, KNOWN_RESIDUAL, checked_checkout, classify, fresh_home,
    original_command, seed_foreign_projection, sha, snapshot,
    sqlite_semantic_snapshot,
)

UNINSTALL = ["scripts/uninstall.js", "--target", "hermes", "--json"]


def require_runner() -> None:
    if (os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux"
            or os.geteuid() == 0
            or not os.environ.get("RUNNER_TEMP")):
        raise ValueError("H795 only executes on unprivileged GitHub-hosted Linux")


def new_home(stack: ExitStack, *, sentinel: bool = True,
             name: str = "preexisting-state") -> tuple[Path, Path]:
    temp = Path(stack.enter_context(tempfile.TemporaryDirectory(
        prefix="h777-h795-", dir=os.environ["RUNNER_TEMP"])))
    if sentinel:
        home = fresh_home(temp, name)
    else:
        home = temp / name
        home.mkdir(mode=0o700)
    return home, temp


def native(report: dict, name: str, ecc: Path, home: Path,
           args: list[str] = UNINSTALL, entry: str = "/usr/local/bin/node") -> tuple[int, dict]:
    proc = subprocess.run(original_command(ecc, home, entry, args),
                          capture_output=True, text=True, check=False, timeout=240)
    report["original_calls"].append({
        "name": name, "exit": proc.returncode,
        "stdout_sha256": sha(proc.stdout.encode("utf-8")),
        "stderr_sha256": sha(proc.stderr.encode("utf-8")),
    })
    if proc.returncode == 0 and entry != "/bin/bash":
        return proc.returncode, json.loads(proc.stdout)
    return proc.returncode, {}


def seed_session_and_decision(database: Path) -> None:
    db = sqlite3.connect(database)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute(
            "INSERT INTO sessions (id,adapter_id,harness,state,repo_root,"
            "started_at,ended_at,snapshot) VALUES (?,?,?,?,?,?,?,?)",
            ("h795-session", "hermes-home", "hermes", "ended", "/unrelated-h795-owner",
             "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "{}"),
        )
        db.execute(
            "INSERT INTO decisions (id,session_id,title,rationale,alternatives,"
            "supersedes,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("h795-decision", "h795-session", "keep", "owner fixture", "[]", None,
             "accepted", "2026-01-01T00:01:00Z"),
        )
        db.commit()
    finally:
        db.close()


def run(ecc: Path, out: Path) -> int:
    report = {
        "schema": "hermes-h795-native-negative-v1",
        "scope": "disposable-h777-homes-github-hosted-docker-only",
        "status": "INCOMPLETE", "upstream_native_exact_rollback": False,
        "original_calls": [], "abrupt_interruption": "NOT_RUN",
    }
    try:
        require_runner()
        report["provenance"] = checked_checkout(ecc)
        assert report["provenance"]["upstream_ecc_sha"] == ECC_SHA
        with ExitStack() as stack:
            # (A) Truly empty HOME. No .hermes sentinel or precreated .claude.
            blank, _ = new_home(stack, sentinel=False, name="never-installed")
            assert snapshot(blank) == {}
            code, _ = native(report, "strict-empty-home-uninstall", ecc, blank)
            empty_diff = classify({}, snapshot(blank))
            assert code == 0 and empty_diff["status"] == "FAIL_KNOWN_CACHE"
            report["strict_empty_home"] = {"exit": code, **empty_diff}
            unrelated = blank / ".claude" / "unrelated-owner.txt"
            unrelated.write_text("h795 synthetic owner file\n", encoding="utf-8")
            owner_before = snapshot(blank)
            code, _ = native(report, "repeat-uninstall-with-owner-file", ecc, blank)
            assert code == 0 and snapshot(blank) == owner_before
            report["repeat_uninstall"] = "PASS_IDEMPOTENT_OWNER_FILE_AND_CACHE_RETAINED"

            # Real unmodified install supplies the source SQLite fixture.
            installed, _ = new_home(stack, name="installed-then-uninstalled")
            code, _ = native(report, "original-install", ecc, installed,
                             ["./install.sh", "--target", "hermes", "--profile", "minimal", "--json"],
                             "/bin/bash")
            db_source = installed / KNOWN_RESIDUAL
            assert code == 0 and db_source.is_file()

            # (B) A different target root plus sessions/decisions must survive.
            foreign, _ = new_home(stack)
            db = foreign / KNOWN_RESIDUAL
            db.parent.mkdir(parents=True)
            shutil.copyfile(db_source, db)
            seed_foreign_projection(db)
            seed_session_and_decision(db)
            owner = foreign / ".hermes" / "unrelated-owner.txt"
            owner.write_text("keep this unrelated file\n", encoding="utf-8")
            before_files = snapshot(foreign)
            before_rows = sqlite_semantic_snapshot(db)
            assert before_rows["table_counts"]["sessions"] >= 1
            assert before_rows["table_counts"]["decisions"] >= 1
            code, _ = native(report, "foreign-sessions-decisions-uninstall", ecc, foreign)
            after_rows = sqlite_semantic_snapshot(db)
            preserved = (before_rows == after_rows and before_files == snapshot(foreign))
            assert code == 0 and preserved
            report["foreign_sqlite"] = {
                "status": "PASS_BYTES_AND_SEMANTICS_PRESERVED",
                "table_counts": after_rows["table_counts"],
                "semantic_sha256": sha(json.dumps(after_rows, sort_keys=True).encode("utf-8")),
            }

            # Symlink outside the test HOME must not be followed.
            linked, linked_base = new_home(stack, name="symlink-negative")
            external = linked_base / "external-owner-file"
            external.write_bytes(b"H795_OUTSIDE_OWNER_SENTINEL")
            external_hash = sha(external.read_bytes())
            link = linked / KNOWN_RESIDUAL
            link.parent.mkdir(parents=True)
            link.symlink_to(external)
            linked_before = snapshot(linked)
            code, result = native(report, "external-symlink-uninstall", ecc, linked)
            assert code == 0 and snapshot(linked) == linked_before
            assert sha(external.read_bytes()) == external_hash
            projection = result.get("installStateProjection", {})
            report["external_symlink"] = {
                "status": "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING" if
                projection.get("status") == "warning" else "CHECK_DIAGNOSTICS",
                "outside_bytes_preserved": True,
                "exit": code,
            }

            # Hardlink to outside test HOME: no external inode may be mutated.
            hard, hard_base = new_home(stack)
            external_db = hard_base / "synthetic-external.db"
            shutil.copyfile(db_source, external_db)
            external_hash = sha(external_db.read_bytes())
            hard_db = hard / KNOWN_RESIDUAL
            hard_db.parent.mkdir(parents=True)
            os.link(external_db, hard_db)
            assert hard_db.stat().st_nlink == 2
            code, _ = native(report, "external-hardlink-uninstall", ecc, hard)
            assert code == 0 and sha(external_db.read_bytes()) == external_hash
            link_still_shared = hard_db.stat().st_ino == external_db.stat().st_ino
            report["external_hardlink"] = {
                "status": "FAIL_HARDLINK_ACCEPTED_REPLACED" if code == 0
                and not link_still_shared else "CHECK_HARDLINK_BEHAVIOR",
                "outside_bytes_preserved": True,
                "link_still_shared": link_still_shared,
                "target_db_exists": hard_db.exists(),
            }

            # Unreadable/invalid projection can be logged as warning even with exit=0.
            corrupt, _ = new_home(stack)
            bad = corrupt / KNOWN_RESIDUAL
            bad.parent.mkdir(parents=True)
            bad.write_bytes(b"H795_INVALID_SQLITE_FIXTURE")
            bad_before = snapshot(corrupt)
            code, result = native(report, "corrupt-sqlite-uninstall", ecc, corrupt)
            assert snapshot(corrupt) == bad_before
            projection = result.get("installStateProjection", {})
            report["corrupt_sqlite"] = {
                "exit": code, "projection_status": projection.get("status", "not-reported"),
                "status": "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING" if code == 0 and
                projection.get("status") == "warning" else "CHECK_DIAGNOSTICS",
                "original_bytes_preserved": True,
            }

            denied, _ = new_home(stack)
            private = denied / ".claude" / "ecc"
            private.mkdir(parents=True)
            private.chmod(0o500)
            try:
                denied_before = snapshot(denied)
                code, result = native(report, "write-denial-uninstall", ecc, denied)
                assert snapshot(denied) == denied_before
                projection = result.get("installStateProjection", {})
                report["write_denial"] = {
                    "exit": code,
                    "projection_status": projection.get("status", "not-reported"),
                    "owner_files_unchanged": True,
                    "status": "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING" if code == 0
                    and projection.get("status") == "warning" else "CHECK_DIAGNOSTICS",
                }
            finally:
                private.chmod(0o700)

            # Native repeat after real installation, without manual DB cleanup.
            code, _ = native(report, "original-installed-uninstall", ecc, installed)
            assert code == 0 and not (installed / ".hermes/ecc-install-state.json").exists()
            after_first = snapshot(installed)
            assert KNOWN_RESIDUAL in after_first
            code, _ = native(report, "original-installed-repeat-uninstall", ecc, installed)
            assert code == 0 and snapshot(installed) == after_first
            report["installed_repeat"] = "PASS_IDEMPOTENT_BUT_CACHE_RETAINED"
            assert report["external_symlink"]["status"] == "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING"
            assert report["external_hardlink"]["status"] == "FAIL_HARDLINK_ACCEPTED_REPLACED"
            assert report["corrupt_sqlite"]["status"] == "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING"
            assert report["write_denial"]["status"] == "FAIL_ZERO_EXIT_WITH_PROJECTION_WARNING"
            report["status"] = "CONFIRMED_KNOWN_NATIVE_DEFECTS_OWNER_PRESERVED"
    except Exception as error:
        report["status"] = "FAIL_UNEXPECTED"
        report["error_class"] = type(error).__name__

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "native_exact_rollback": report["upstream_native_exact_rollback"],
        "original_calls": len(report["original_calls"]),
    }))
    return 0 if report["status"] == "CONFIRMED_KNOWN_NATIVE_DEFECTS_OWNER_PRESERVED" else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: h795_ecc_native_negative_regression.py ECC_ROOT JSON_OUT")
    sys.exit(run(Path(sys.argv[1]), Path(sys.argv[2])))
