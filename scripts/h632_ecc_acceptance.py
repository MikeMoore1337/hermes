#!/usr/bin/env python3
"""H-632: real, offline ECC installer lifecycle against an isolated HOME.

This is a harness, not a replacement for any upstream ECC tool or skill.
Designed for ephemeral GitHub-hosted runners; no production mounts or secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile

ECC_SHA = "25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b"
HERMES_IMAGE = "nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05"
NODE_IMAGE = "node:22.16.0-bookworm-slim@sha256:048ed02c5fd52e86fda6fbd2f6a76cf0d4492fd6c6fee9e2c463ed5108da0e34"
HERMES_SOURCE_SHA = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
EXPECTED_PROFILE = {"rules-core", "agents-core", "commands-core", "platform-configs", "workflow-quality"}
SKILLS = ("verification-loop", "tdd-workflow")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {str(p.relative_to(root)): digest(p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}



def cleanup_ephemeral_ecc_cache(home: Path, baseline: dict[str, str],
                                observed: dict[str, str]) -> dict[str, str]:
    """Remove only the new ECC cache file from a disposable H-632 test HOME.

    This is NOT part of upstream ECC uninstall, nor safe for a shared HOME.
    No directories are deleted. A pre-existing file, symlink or hard link fails
    closed. The original uninstaller verdict remains separate in the report.
    """
    if not home.is_absolute() or home.name != "home":
        raise ValueError("Expected an absolute H-632 home path")
    if not home.parent.name.startswith("h632-"):
        raise ValueError("Not an H-632 disposable HOME")
    key = ".claude/ecc/state.db"
    if key in baseline or key not in observed:
        raise ValueError("Cache is not exclusively test-created")
    for parent in (home, home / ".claude", home / ".claude" / "ecc"):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Unsafe cache parent path")
    cache = home / key
    metadata = cache.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("Unsafe cache file")
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("File cleanup requires OS-level O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptor = os.open(cache, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("Cache identity changed during open")
        checksum = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                checksum.update(chunk)
        if checksum.hexdigest() != observed[key]:
            raise ValueError("Cache bytes changed after snapshot")
        latest = cache.lstat()
        if (latest.st_dev, latest.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Cache identity changed before unlink")
    finally:
        os.close(descriptor)
    cache.unlink()
    return {"path": key, "deleted_sha256": observed[key], "scope": "disposable-H632-HOME-only"}


def validate_plan(payload: dict) -> dict:
    assert payload.get("dryRun") is True, "Original installer did not emit dry-run plan"
    p = payload["plan"]
    assert p["target"] == "hermes"
    assert p["targetRoot"] == "/test-home/.hermes", p.get("targetRoot")
    assert p["installStatePath"] == "/test-home/.hermes/ecc-install-state.json"
    modules = set(p.get("selectedModuleIds", []))
    assert EXPECTED_PROFILE.issubset(modules), sorted(modules)
    assert "hooks-runtime" not in modules and "hermes-hooks" not in modules
    targets = set()
    for op in p["operations"]:
        dest = PurePosixPath(op["destinationPath"])
        assert dest.is_relative_to(PurePosixPath("/test-home/.hermes")), str(dest)
        relative = dest.relative_to(PurePosixPath("/test-home/.hermes"))
        assert not any(x in ("..", ".") for x in relative.parts)
        assert relative.parts and relative.parts[0] not in ("cron", "plugins", "hooks", "secrets")
        assert str(relative) not in ("config.yaml", ".env", ".mcp.json", "mcp.json")
        targets.add(str(relative))
    assert len(targets) == len(p["operations"]), "Destination collision in original plan"
    assert any(x.startswith("skills/") for x in targets), "No skills in actual plan"
    return {"selected_modules": sorted(modules), "operations": len(p["operations"]), "destinations": len(targets)}


def exec_capture(cmd: list[str], *, cwd: Path | None = None, timeout: int = 210) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, "", type(e).__name__ + ": " + str(e)[:200]


def preflight(ecc: Path) -> dict:
    assert ecc.resolve().is_dir(), "Missing ECC checkout"
    rc, out, _ = exec_capture(["git", "rev-parse", "HEAD"], cwd=ecc)
    assert rc == 0 and out.strip() == ECC_SHA, "Unpinned ECC checkout"
    assert "MIT License" in (ecc / "LICENSE").read_text(encoding="utf-8")
    pkg = json.loads((ecc / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ecc / "package-lock.json").read_text(encoding="utf-8"))
    assert pkg["version"] == lock["version"] == "2.2.3"
    assert pkg["license"] == "MIT"
    manifest = json.loads((ecc / "manifests/install-profiles.json").read_text(encoding="utf-8"))
    assert set(manifest["profiles"]["minimal"]["modules"]) == EXPECTED_PROFILE
    wrapper = (ecc / "install.sh").read_text(encoding="utf-8")
    assert "npm install --ignore-scripts --no-audit --no-fund" in wrapper
    assert "exec node" in wrapper
    assert not (ecc / "ecc-install.json").exists(), "Unreviewed default install config"
    assert "hermes" in (ecc / "scripts/lib/install-targets/hermes-home.js").read_text(encoding="utf-8")
    return {"sha": ECC_SHA, "version": pkg["version"], "license": "MIT", "lockfile": True,
            "wrapper_sha256": digest((ecc / "install.sh").read_bytes()),
            "install_apply_sha256": digest((ecc / "scripts/install-apply.js").read_bytes())}


def container_cmd(image: str, entry: str, argv: list[str], ecc: Path, home: Path, *, hermes: bool = False) -> list[str]:
    home_name = "/test-home/.hermes" if hermes else "/test-home"
    cmd = ["docker", "run", "--rm", "--init", "--pull=never", "--network", "none", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}",
           "--pids-limit", "64", "--memory", "1024m", "--cpus", "1",
           "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
           "--mount", f"type=bind,src={ecc.resolve()},dst=/ecc,readonly",
           "--mount", f"type=bind,src={home.resolve()},dst=/test-home",
           "--env", "HOME=/test-home", "--env", f"HERMES_HOME={home_name}",
           "--env", "HERMES_WRITE_SAFE_ROOT=/test-home/.hermes",
           "--workdir", "/opt/hermes" if hermes else "/ecc", "--entrypoint", entry, image]
    return cmd + argv


def attempt(report: dict, name: str, cmd: list[str], *, expect: int | None = 0, timeout: int = 210) -> str:
    rc, stdout, stderr = exec_capture(cmd, timeout=timeout)
    report["calls"].append({"name": name, "exit": rc, "stdout_sha256": digest(stdout.encode()),
                            "stdout_bytes": len(stdout), "stderr_excerpt": stderr.strip()[:250]})
    if expect is not None and rc != expect:
        raise AssertionError(f"{name}: exit={rc}, expected={expect}, stderr={stderr[:300]}")
    return stdout


def run(ecc: Path, output: Path) -> int:
    report = {"schema": "hermes-h632-original-ecc-acceptance-v1", "ecc_sha": ECC_SHA,
              "hermes_image": HERMES_IMAGE, "node_image": NODE_IMAGE,
              "calls": [], "checks": {}, "status": "INCOMPLETE", "original_skill_execution": "BLOCKED_BY_OWNER_POLICY"}
    try:
        report["provenance"] = preflight(ecc)
        with tempfile.TemporaryDirectory(prefix="h632-", dir=os.getenv("RUNNER_TEMP", None)) as temp:
            home = Path(temp) / "home"
            home.mkdir(mode=0o777)
            home.chmod(0o777)
            h = home / ".hermes"
            (h / "policies").mkdir(parents=True)
            h.chmod(0o777)
            (h / "skills" / "owner-unrelated").mkdir(parents=True)
            (h / "config.yaml").write_text("# synthetic config, not production\n", encoding="utf-8")
            (h / "policies" / "owner-gate.txt").write_text("OWNER_APPROVAL_REQUIRED\n", encoding="utf-8")
            (h / "skills" / "owner-unrelated" / "SKILL.md").write_text("# Synthetic owner skill\n", encoding="utf-8")
            for p in h.rglob("*"):
                if p.is_dir():
                    p.chmod(0o777)
                elif p.is_file():
                    p.chmod(0o666)
            before = snapshot(home)
            node = lambda entry, args: container_cmd(NODE_IMAGE, entry, args, ecc, home)
            args = ["./install.sh", "--target", "hermes", "--profile", "minimal"]
            plan_out = attempt(report, "original-dry-run", node("/bin/bash", args + ["--dry-run", "--json"]))
            original_plan = json.loads(plan_out)
            report["plan"] = validate_plan(original_plan)
            planned = {
                ".hermes/" + str(PurePosixPath(op["destinationPath"]).relative_to("/test-home/.hermes"))
                for op in original_plan["plan"]["operations"]
            }
            assert snapshot(home) == before, "Dry-run changed HOME"
            report["checks"]["original_plan_safe"] = True
            attempt(report, "original-install", node("/bin/bash", args + ["--json"]))
            after = snapshot(home)
            assert set(before).issubset(after), "Original install deleted unrelated files"
            assert all(after[k] == v for k, v in before.items()), "Original install altered unrelated files"
            side_effect_paths = sorted(p for p in after if not p.startswith(".hermes/"))
            report["cross_home_state_paths"] = side_effect_paths
            assert side_effect_paths == [".claude/ecc/state.db"], f"Unreviewed cross-home writes: {side_effect_paths}"
            added_files = set(after) - set(before)
            expected_added = planned | {".hermes/ecc-install-state.json", ".claude/ecc/state.db"}
            report["checks"]["installed_files_match_original_plan"] = added_files == expected_added
            assert report["checks"]["installed_files_match_original_plan"], (
                f"Unplanned files added={sorted(added_files - expected_added)[:5]} "
                f"missing={sorted(expected_added - added_files)[:5]}")
            report["checks"]["unrelated_files_preserved"] = True
            for name in SKILLS:
                skill = h / "skills" / name / "SKILL.md"
                assert skill.is_file(), f"Expected upstream skill not installed: {name}"
            report["installed_skill_sources"] = {name: digest((ecc / "skills" / name / "SKILL.md").read_bytes()) for name in SKILLS}
            report["installed_skill_outputs"] = {name: digest((h / "skills" / name / "SKILL.md").read_bytes()) for name in SKILLS}
            report["checks"]["original_installer_installed_skills"] = True
            installed_count = len(after)
            attempt(report, "original-reinstall", node("/bin/bash", args + ["--json"]))
            again = snapshot(home)
            metadata_paths = {".hermes/ecc-install-state.json", ".claude/ecc/state.db"}
            report["reinstall_metadata_updated"] = sorted(k for k in metadata_paths if after.get(k) != again.get(k))
            assert all(again[k] == v for k, v in after.items() if k not in metadata_paths), "Reinstall changed managed content"
            assert len(again) == installed_count, "Reinstall duplicates or removes files"
            report["checks"]["reinstall_idempotent_files"] = True
            lifecycle_before = snapshot(home)
            for name, executable in (
                ("original-doctor", ["scripts/doctor.js", "--target", "hermes", "--json"]),
                ("original-repair-dry-run", ["scripts/repair.js", "--target", "hermes", "--dry-run", "--json"]),
                ("original-update-dry-run", ["scripts/auto-update.js", "--target", "hermes",
                                              "--repo-root", "/ecc", "--dry-run", "--json"]),
            ):
                raw_result = attempt(report, name, node("/usr/local/bin/node", executable))
                parsed = json.loads(raw_result)
                assert parsed.get("summary", {}).get("errorCount") == 0, f"{name} reported errors"
                assert snapshot(home) == lifecycle_before, f"{name} changed HOME"
            report["checks"]["original_doctor_repair_update_preview"] = True
            bad_before = snapshot(home)
            rc, stdout, stderr = exec_capture(node("/bin/bash", ["./install.sh", "--target", "hermes", "--profile", "not-a-real-profile", "--json"]))
            report["calls"].append({"name": "unsupported-profile", "exit": rc, "stdout_sha256": digest(stdout.encode()),
                                    "stderr_excerpt": stderr.strip()[:120]})
            assert rc != 0 and snapshot(home) == bad_before, "Unsupported profile not rejected atomically"
            report["checks"]["unsupported_profile_refused"] = True
            # Attribute native Hermes init files separately from ECC installer output.
            pre_native_files = snapshot(home)
            pre_native_hooks_dir = (h / "hooks").is_dir()
            # The pinned real NousResearch image exposes the real skills_list implementation.
            probe = ('import json; from pathlib import Path; from tools.skills_tool import skills_list,skill_view; '
                     'stamp=json.loads(Path("/opt/hermes/install-stamp.json").read_text()); '
                     'x=json.loads(skills_list()); '
                     'names=[z.get("name", "") for z in x.get("skills", [])]; '
                     'views={s:json.loads(skill_view(s, preprocess=False)) '
                     'for s in ("verification-loop","tdd-workflow")}; '
                     'print(json.dumps({"success":x.get("success"),"count":len(names),'
                     '"source_sha":stamp.get("commit"),'
                     '"found":{s:s in names for s in views},'
                     '"viewed":{s:(v.get("success") is True and v.get("name")==s and '
                     'v.get("content", "").startswith("---")) for s,v in views.items()}}))')
            discovery_out = attempt(report, "real-hermes-skills-list",
                                    container_cmd(HERMES_IMAGE, "/opt/hermes/.venv/bin/python", ["-c", probe], ecc, home, hermes=True))
            discovery = json.loads(discovery_out.strip().splitlines()[-1])
            assert discovery["success"] is True and all(discovery["found"].values()), discovery
            assert discovery["source_sha"] == HERMES_SOURCE_SHA, "Wrong native NousResearch Hermes source"
            assert all(discovery["viewed"].values()), "Native skill_view could not load ECC originals"
            post_native_files = snapshot(home)
            native_new_files = set(post_native_files) - set(pre_native_files)
            report["native_runtime_new_files"] = sorted(native_new_files)
            report["native_runtime_changed_files"] = sorted(
                k for k in pre_native_files if pre_native_files[k] != post_native_files.get(k))
            report["native_runtime_created_empty_hooks_dir"] = (
                not pre_native_hooks_dir and (h / "hooks").is_dir()
                and not any(p.is_file() for p in (h / "hooks").rglob("*")))
            report["native_hermes_discovery"] = discovery
            report["checks"]["real_hermes_skill_discovery"] = True
            report["checks"]["real_hermes_skill_view_invoked"] = True
            # Negative runtime probes use only a disposable HOME and a network-less container.
            denial = ('const fs=require("node:fs"),net=require("node:net");'
                      'let out=false;try{fs.writeFileSync("/forbidden-outside-home.txt","x");}catch(e){out=true}'
                      'if(!out)process.exit(14);'
                      'if(fs.existsSync("/private-second-brain")||fs.existsSync("/private-yfc")||fs.existsSync("/run/secrets"))process.exit(15);'
                      'const s=net.connect({host:"1.1.1.1",port:80,timeout:1500});'
                      's.on("connect",()=>process.exit(16));'
                      's.on("error",()=>{console.log("OUTSIDE_WRITE_AND_NETWORK_DENIED");process.exit(0)});'
                      's.on("timeout",()=>{s.destroy();console.log("NETWORK_TIMEOUT_DENIED");process.exit(0)});')
            attempt(report, "os-file-network-deny", node("/usr/local/bin/node", ["-e", denial]), timeout=15)
            report["checks"]["os_network_and_outside_write_denied"] = True
            report["installed_runtime_config"] = {
                "root_hooks_dir": (h / "hooks").is_dir(),
                "root_hook_paths": sorted(str(p.relative_to(h)) for p in (h / "hooks").rglob("*") if p.is_file()) if (h / "hooks").is_dir() else [],
                "mcp_root_file": (h / ".mcp.json").is_file(),
                "mcp_root_config": (h / "mcp.json").is_file(),
            }
            report["checks"]["no_active_hooks_or_mcp"] = not any((
                bool(report["installed_runtime_config"]["root_hook_paths"]),
                report["installed_runtime_config"]["mcp_root_file"],
                report["installed_runtime_config"]["mcp_root_config"],
            ))
            attempt(report, "original-uninstall-dry-run", node("/usr/local/bin/node", ["scripts/uninstall.js", "--target", "hermes", "--dry-run", "--json"]))
            attempt(report, "original-uninstall", node("/usr/local/bin/node", ["scripts/uninstall.js", "--target", "hermes", "--json"]))
            uninstalled = snapshot(home)
            assert all(uninstalled.get(k) == v for k, v in before.items()), "Uninstall altered unrelated state"
            report["rollback_residual_paths"] = sorted(set(uninstalled) - set(before))
            report["rollback_native_runtime_files"] = sorted(
                (set(uninstalled) - set(before)) & native_new_files)
            report["rollback_non_runtime_residual_files"] = sorted(
                (set(uninstalled) - set(before)) - native_new_files)
            report["checks"]["exact_snapshot_rollback"] = (uninstalled == before)
            report["checks"]["only_known_original_ecc_cache_residual"] = (
                report["rollback_non_runtime_residual_files"] == [".claude/ecc/state.db"])
            assert not (h / "ecc-install-state.json").exists(), "Uninstall left ECC state"
            report["checks"]["original_managed_files_removed"] = not bool(planned & set(uninstalled))
            assert report["checks"]["original_managed_files_removed"], "Uninstall left original planned files"
            report["checks"]["upstream_uninstall_preserves_unrelated"] = True
            assert report["checks"]["only_known_original_ecc_cache_residual"], "Unexpected non-native residue"
            report["test_only_cache_cleanup"] = cleanup_ephemeral_ecc_cache(home, before, uninstalled)
            cleaned = snapshot(home)
            expected_cleaned = {**before, **{k: uninstalled[k] for k in native_new_files}}
            report["checks"]["ecc_owned_files_fully_reverted_in_test_scope"] = cleaned == expected_cleaned
            assert report["checks"]["ecc_owned_files_fully_reverted_in_test_scope"], "Unsafe test cleanup"
            report["checks"]["hermes_runtime_files_preserved"] = all(
                cleaned[k] == uninstalled[k] for k in native_new_files)
            assert report["checks"]["hermes_runtime_files_preserved"]
            report["file_counts"] = {"before": len(before), "installed": len(after), "reinstalled": len(again), "uninstalled": len(uninstalled)}
            # Synthetic collision: a resident owner policy must never be overwritten.
            collision_home = Path(temp) / "collision"
            collision_home.mkdir(mode=0o777)
            collision_home.chmod(0o777)
            (collision_home / ".hermes").mkdir(mode=0o777)
            (collision_home / ".hermes").chmod(0o777)
            policy = collision_home / ".hermes" / "AGENTS.md"
            policy.write_text("SYNTHETIC_EXISTING_OWNER_POLICY_DO_NOT_OVERWRITE\n", encoding="utf-8")
            policy.chmod(0o666)
            collision_before = digest(policy.read_bytes())
            collision_cmd = container_cmd(NODE_IMAGE, "/bin/bash", args + ["--json"], ecc, collision_home)
            rc, stdout, stderr = exec_capture(collision_cmd, timeout=210)
            report["calls"].append({"name": "owner-agents-collision", "exit": rc,
                                    "stdout_sha256": digest(stdout.encode()), "stderr_excerpt": stderr.strip()[:160]})
            report["checks"]["existing_owner_agents_preserved"] = (digest(policy.read_bytes()) == collision_before)
            report["status"] = ("PASS_INSTALL_DISCOVERY_ROLLBACK_SKILL_EXECUTION_BLOCKED"
                                if all((report["checks"]["exact_snapshot_rollback"],
                                        report["checks"]["no_active_hooks_or_mcp"],
                                        report["checks"]["existing_owner_agents_preserved"]))
                                else "PARTIAL_ORIGINAL_INSTALL_SECURITY_OR_ROLLBACK")
    except Exception as e:
        report["status"] = "FAIL_OR_BLOCKED"
        report["error"] = type(e).__name__ + ": " + str(e)[:480]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": report["checks"],
                      "error": report.get("error"), "report": str(output)}, ensure_ascii=False))
    return 0 if report["status"].startswith("PASS") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ecc-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--preflight", action="store_true")
    args = ap.parse_args()
    if args.preflight:
        print(json.dumps(preflight(args.ecc_root)))
        return 0
    return run(args.ecc_root, args.out)


if __name__ == "__main__":
    sys.exit(main())
