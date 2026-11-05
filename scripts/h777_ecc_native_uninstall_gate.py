#!/usr/bin/env python3
"""H777: native, read-only upstream ECC uninstall acceptance in disposable Docker.

This script never repairs, deletes, or upgrades shared user state. All mutation
is restricted to fresh task-owned temp homes and is driven by original ECC
install/uninstall entrypoints in a pinned networkless Node image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote

ECC_SHA = "b38be6a7f6350964d59328b52f0624e1d1d552d1"
NODE_IMAGE = (
    "node:22.16.0-bookworm-slim@sha256:"
    "048ed02c5fd52e86fda6fbd2f6a76cf0d4492fd6c6fee9e2c463ed5108da0e34"
)
KNOWN_RESIDUAL = ".claude/ecc/state.db"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    """Read path hashes without following links or visiting external directories."""
    result: dict[str, str] = {}
    for item in root.rglob("*"):
        rel = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            result[rel] = "SYMLINK:" + os.readlink(item)
        elif stat.S_ISREG(info.st_mode):
            result[rel] = "SHA256:" + sha(item.read_bytes())
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("Unexpected special file in synthetic HOME")
    return result


def sqlite_semantic_snapshot(database: Path) -> dict:
    """Hash actual SQLite rows, without exporting private values or writing DB."""
    if database.is_symlink() or not database.is_file():
        raise ValueError("Expected regular SQLite database without symlinks")
    uri = "file:" + quote(str(database), safe="/") + "?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("Preexisting SQLite integrity failed")
        names = sorted(row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
        if "install_state" not in names:
            raise ValueError("Expected canonical ECC install-state schema missing")
        counts = {}
        fingerprints = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            rows = sorted(repr(tuple(row)) for row in db.execute("SELECT * FROM " + quoted))
            counts[name] = len(rows)
            fingerprints[name] = sha("\n".join(rows).encode("utf-8"))
    return {"table_counts": counts, "table_hashes": fingerprints}


def seed_foreign_projection(database: Path) -> None:
    """Re-scope only a disposable copied row to a truly unrelated target root.

    Both Docker HOME mounts are /test-home: copying the raw DB alone does not
    create a different install identity. Never modify an owner-owned DB.
    """
    if database.is_symlink() or not database.is_file():
        raise ValueError("Foreign projection fixture must be a regular copied DB")
    with sqlite3.connect(database) as db:
        existing = db.execute(
            "SELECT target_id, target_root FROM install_state").fetchall()
        if existing != [("hermes-home", "/test-home/.hermes")]:
            raise AssertionError("Unexpected original projection identity")
        updated = db.execute(
            "UPDATE install_state SET target_root=? WHERE target_id=? AND target_root=?",
            ("/unrelated-h777-owner/.hermes", "hermes-home", "/test-home/.hermes"))
        if updated.rowcount != 1:
            raise AssertionError("Foreign projection fixture must change exactly one row")
        db.commit()
    with sqlite3.connect("file:" + quote(str(database), safe="/")
                         + "?mode=ro&immutable=1", uri=True) as db:
        identities = db.execute(
            "SELECT target_id,target_root FROM install_state").fetchall()
        if identities != [("hermes-home", "/unrelated-h777-owner/.hermes")]:
            raise AssertionError("Foreign projection marker was not retained")


def classify(before: dict[str, str], after: dict[str, str]) -> dict:
    changed = sorted(k for k in before if after.get(k) != before[k])
    residual = sorted(k for k in after if k not in before)
    status = (
        "PASS_NATIVE_EXACT_ROLLBACK" if not residual and not changed
        else "FAIL_KNOWN_CACHE" if residual == [KNOWN_RESIDUAL] and not changed
        else "FAIL_UNEXPECTED_DELTA"
    )
    return {"status": status, "residual": residual, "owner_changed": changed}


def checked_checkout(ecc: Path) -> dict:
    if ecc.is_symlink() or not ecc.is_dir():
        raise ValueError("Missing or symlinked upstream source checkout")
    probe = subprocess.run(
        ["git", "-C", str(ecc), "rev-parse", "HEAD"],
        text=True, capture_output=True, check=True, timeout=10)
    if probe.stdout.strip() != ECC_SHA:
        raise ValueError("Unreviewed upstream source SHA")
    package = json.loads((ecc / "package.json").read_text(encoding="utf-8"))
    license_bytes = (ecc / "LICENSE").read_bytes()
    if package.get("license") != "MIT" or b"MIT License" not in license_bytes:
        raise ValueError("Upstream license mismatch")
    if not (ecc / "node_modules" / "sql.js").is_dir():
        raise ValueError("Exact upstream package dependencies not prepared")
    for name in ("install.sh", "scripts/uninstall.js",
                 "scripts/lib/install-state-store-sync.js"):
        if not (ecc / name).is_file():
            raise ValueError("Missing reviewed original upstream entrypoint")
    return {"upstream_ecc_sha": ECC_SHA, "license": "MIT",
            "installer_sha256": sha((ecc / "install.sh").read_bytes()),
            "uninstaller_sha256": sha((ecc / "scripts/uninstall.js").read_bytes())}


def original_command(ecc: Path, home: Path, entry: str, args: list[str]) -> list[str]:
    if (not home.is_dir() or home.is_symlink()
            or not home.parent.name.startswith("h777-")
            or home.name not in {
                "never-installed", "installed-then-uninstalled",
                "preexisting-state", "symlink-negative",
            }):
        raise ValueError("Unsafe disposable H777 HOME")
    return [
        "docker", "run", "--rm", "--init", "--pull=never",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", "64",
        "--memory", "1024m", "--cpus", "1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--mount", f"type=bind,src={ecc.resolve()},dst=/ecc,readonly",
        "--mount", f"type=bind,src={home.resolve()},dst=/test-home",
        "--env", "HOME=/test-home", "--env", "HERMES_HOME=/test-home/.hermes",
        "--env", "HERMES_WRITE_SAFE_ROOT=/test-home/.hermes",
        "--workdir", "/ecc", "--entrypoint", entry, NODE_IMAGE, *args,
    ]


def run_original(
    report: dict, name: str, ecc: Path, home: Path, entry: str, args: list[str],
) -> str:
    command = original_command(ecc, home, entry, args)
    proc = subprocess.run(command, text=True, capture_output=True, check=False,
                          timeout=240)
    report["original_calls"].append({
        "name": name, "exit": proc.returncode,
        "stdout_sha256": sha(proc.stdout.encode("utf-8")),
        "stdout_length": len(proc.stdout),
        "stderr_sha256": sha(proc.stderr.encode("utf-8")),
    })
    if proc.returncode:
        raise AssertionError(f"{name} returned exit={proc.returncode}")
    return proc.stdout


def fresh_home(temp: Path, name: str) -> Path:
    if not re.fullmatch(r"[a-z0-9-]+", name):
        raise ValueError("Unsafe disposable HOME label")
    home = temp / name
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    (home / ".hermes").mkdir(mode=0o700)
    (home / ".hermes" / "owner-sentinel.txt").write_text(
        "H777_SYNTHETIC_OWNER_STATE_UNTOUCHED\n", encoding="utf-8")
    return home


def planned_paths(raw: str) -> set[str]:
    plan = json.loads(raw)
    ops = plan["plan"]["operations"]
    result: set[str] = set()
    root = PurePosixPath("/test-home/.hermes")
    if not ops or len(ops) < 1:
        raise AssertionError("Original installer produced no operations")
    for op in ops:
        target = PurePosixPath(op["destinationPath"])
        try:
            rel = target.relative_to(root)
        except ValueError as exc:
            raise AssertionError("Plan crosses isolated Hermes root") from exc
        if str(rel) == "." or ".." in rel.parts:
            raise AssertionError("Unsafe managed destination")
        result.add(".hermes/" + rel.as_posix())
    return result


def run(ecc: Path, out: Path, expectation: str) -> int:
    if not __debug__:
        raise RuntimeError("H777 refuses Python -O assertions-disabled runtime")
    report = {
        "schema": "hermes-h777-upstream-native-rollback-v1",
        "scope": "disposable-h777-homes-github-hosted-docker-only",
        "expectation": expectation,
        "status": "INCOMPLETE",
        "native_exact_rollback": False,
        "original_calls": [],
    }
    try:
        report["provenance"] = checked_checkout(ecc)
        with tempfile.TemporaryDirectory(
            prefix="h777-", dir=os.environ.get("RUNNER_TEMP") or None
        ) as folder:
            temp = Path(folder)
            clean = fresh_home(temp, "never-installed")
            before_clean = snapshot(clean)
            run_original(report, "virgin-original-uninstall", ecc, clean,
                         "/usr/local/bin/node",
                         ["scripts/uninstall.js", "--target", "hermes", "--json"])
            virgin = classify(before_clean, snapshot(clean))
            report["virgin_uninstall"] = virgin

            home = fresh_home(temp, "installed-then-uninstalled")
            baseline = snapshot(home)
            install_args = ["./install.sh", "--target", "hermes", "--profile", "minimal"]
            plan_raw = run_original(report, "original-install-dry-run", ecc, home,
                                    "/bin/bash", install_args + ["--dry-run", "--json"])
            planned = planned_paths(plan_raw)
            if snapshot(home) != baseline:
                raise AssertionError("Dry-run modified synthetic owner state")
            run_original(report, "original-install", ecc, home,
                         "/bin/bash", install_args + ["--json"])
            installed = snapshot(home)
            if not all(p in installed for p in planned):
                raise AssertionError("Native install did not install all planned files")
            if not (home / ".hermes/ecc-install-state.json").is_file():
                raise AssertionError("Original installation state missing")
            if not (home / KNOWN_RESIDUAL).is_file():
                raise AssertionError("Expected original ECC state store missing")

            run_original(report, "original-reinstall", ecc, home,
                         "/bin/bash", install_args + ["--json"])
            again = snapshot(home)
            if set(again) != set(installed):
                raise AssertionError("Original reinstall changed destination inventory")
            run_original(report, "original-doctor", ecc, home,
                         "/usr/local/bin/node",
                         ["scripts/doctor.js", "--target", "hermes", "--json"])

            # Preserve an existing valid ECC SQLite database with a scoped
            # projection for a different HOME. This is NOT proof of all
            # unrelated memory records, but it catches indiscriminate unlink.
            other = fresh_home(temp, "preexisting-state")
            database = other / KNOWN_RESIDUAL
            database.parent.mkdir(mode=0o700, parents=True)
            shutil.copyfile(home / KNOWN_RESIDUAL, database)
            seed_foreign_projection(database)
            other_before = snapshot(other)
            semantic_before = sqlite_semantic_snapshot(database)
            run_original(report, "uninstall-with-preexisting-store", ecc, other,
                         "/usr/local/bin/node",
                         ["scripts/uninstall.js", "--target", "hermes", "--json"])
            other_diff = classify(other_before, snapshot(other))
            semantic_after = sqlite_semantic_snapshot(database)
            semantically_preserved = semantic_before == semantic_after
            report["preexisting_store"] = {
                "status": (
                    "PASS_BYTE_IDENTICAL" if other_diff["status"] == "PASS_NATIVE_EXACT_ROLLBACK"
                    else "WARN_BYTE_REWRITE_NO_ROW_CHANGE" if semantically_preserved
                    else "FAIL_OWNER_SQLITE_ROWS_CHANGED"),
                "bytes_unchanged": other_diff["status"] == "PASS_NATIVE_EXACT_ROLLBACK",
                "semantic_rows_unchanged": semantically_preserved,
                "table_counts": semantic_after["table_counts"],
                "previous_table_hashes": semantic_before["table_hashes"],
                "result_table_hashes": semantic_after["table_hashes"],
            }
            if not semantically_preserved:
                raise AssertionError("Uninstall mutated preexisting cross-scope SQLite rows")

            run_original(report, "original-uninstall-dry-run", ecc, home,
                         "/usr/local/bin/node",
                         ["scripts/uninstall.js", "--target", "hermes",
                          "--dry-run", "--json"])
            run_original(report, "original-uninstall", ecc, home,
                         "/usr/local/bin/node",
                         ["scripts/uninstall.js", "--target", "hermes", "--json"])
            uninstalled = snapshot(home)
            if planned & set(uninstalled):
                raise AssertionError("Original uninstall left installed managed files")
            if (home / ".hermes/ecc-install-state.json").exists():
                raise AssertionError("Original uninstall left canonical install-state")
            installed_diff = classify(baseline, uninstalled)
            report["installed_uninstall"] = installed_diff
            report["removed_managed_paths"] = len(planned)
            report["original_reinstall_idempotent"] = True

            # An outside-facing symlink to synthetic owner data must never be
            # followed or destroyed even if projection open emits a warning.
            linked = fresh_home(temp, "symlink-negative")
            guard = linked / ".hermes/owner-sentinel.txt"
            original_bytes = guard.read_bytes()
            db_link = linked / KNOWN_RESIDUAL
            db_link.parent.mkdir(mode=0o700, parents=True)
            db_link.symlink_to("../../.hermes/owner-sentinel.txt")
            linked_before = snapshot(linked)
            run_original(report, "uninstall-with-symlink-denial", ecc, linked,
                         "/usr/local/bin/node",
                         ["scripts/uninstall.js", "--target", "hermes", "--json"])
            linked_after = snapshot(linked)
            if linked_after != linked_before or guard.read_bytes() != original_bytes:
                raise AssertionError("Original uninstall followed or altered symlink")
            report["symlink_negative"] = "PASS_NO_LINK_FOLLOW"

            if not all(d["status"] in (
                "PASS_NATIVE_EXACT_ROLLBACK", "FAIL_KNOWN_CACHE")
                for d in (virgin, installed_diff)):
                raise AssertionError("Unexpected state mutation beyond known cache")
            if virgin["status"] != installed_diff["status"]:
                raise AssertionError("Native uninstall differs between fresh and virgin HOME")

            report["native_exact_rollback"] = (
                virgin["status"] == installed_diff["status"]
                == "PASS_NATIVE_EXACT_ROLLBACK"
                and report["preexisting_store"]["bytes_unchanged"])
            report["status"] = (
                "PASS_NATIVE_EXACT_ROLLBACK"
                if report["native_exact_rollback"] else "FAIL_KNOWN_CACHE")
    except Exception as exc:
        report["status"] = "FAIL_UNEXPECTED"
        report["diagnostic"] = type(exc).__name__ + ": " + str(exc)[:180]

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                   encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "native_exact_rollback": report["native_exact_rollback"],
        "removed_managed_paths": report.get("removed_managed_paths"),
        "original_calls": len(report["original_calls"]),
    }))
    if expectation == "known-failure":
        return 0 if report["status"] == "FAIL_KNOWN_CACHE" else 1
    return 0 if report["status"] == "PASS_NATIVE_EXACT_ROLLBACK" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecc-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expectation", choices=("known-failure", "candidate-pass"),
                        default="known-failure")
    args = parser.parse_args()
    return run(args.ecc_root, args.out, args.expectation)


if __name__ == "__main__":
    sys.exit(main())
