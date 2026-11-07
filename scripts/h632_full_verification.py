#!/usr/bin/env python3
"""H632 synthetic six-phase verification. This is a guided fixture, NOT ECC code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROOF = "H632_GUIDED_SIX_ACTUAL_PHASES_PASS"
JS = """/** @param {number} a @param {number} b @returns {number} */
exports.add = (a, b) => a + b;
"""
TEST = """const { test } = require('node:test');
const assert = require('node:assert/strict');
const { add } = require('../src/math.js');
test('positive', () => assert.equal(add(20,22),42));
test('negative', () => assert.equal(add(-2,3),1));
"""
BUILD = """const fs=require('node:fs'), cp=require('node:child_process');
const p=cp.spawnSync(process.execPath,['--check','src/math.js'],{stdio:'inherit'});
if(p.status!==0)process.exit(1);
fs.mkdirSync('dist',{recursive:true});
fs.copyFileSync('src/math.js','dist/math.js');
"""
LINT = """const fs=require('node:fs'),s=fs.readFileSync('src/math.js','utf8');
if(!s.endsWith('\\n')||s.split('\\n').some(l=>l.length>100||/[ \\t]+$/.test(l)))process.exit(2);
if(/\\b(eval|console\\.log)\\s*\\(/.test(s))process.exit(3);
console.log('H632_JS_PROJECT_LINT=PASS');
"""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def root_checked(path: Path) -> Path:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Unsafe symlink in H632 fixture root")
    root = path.resolve(strict=True)
    if root.name != "h632-sixphase" or root.parent.name != "fixture" or not root.is_dir():
        raise ValueError("Not an isolated H632 fixture")
    return root


def call(args: list[str], cwd: Path, timeout: int = 40):
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
             "HUSKY": "0", "npm_config_offline": "true", "npm_config_audit": "false"})


def prepare(path: Path):
    root = root_checked(path)
    if any(root.iterdir()):
        raise ValueError("Fixture must be empty before preparation")
    files = {
        "package.json": json.dumps({
            "name": "h632-disposable", "version": "0.0.0", "private": True,
            "scripts": {"build": "node scripts/build.cjs", "lint": "node scripts/lint.cjs",
                        "test": "node --experimental-test-coverage --test tests/math.test.cjs"}}) + "\n",
        "tsconfig.json": json.dumps({"compilerOptions": {
            "allowJs": True, "checkJs": True, "noEmit": True, "strict": True,
            "target": "ES2022", "module": "commonjs", "types": [], "skipLibCheck": True},
            "include": ["src/**/*.js"]}) + "\n",
        ".gitignore": "dist/\n",
        "src/math.js": JS,
        "tests/math.test.cjs": TEST,
        "scripts/build.cjs": BUILD,
        "scripts/lint.cjs": LINT,
    }
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ValueError("Unexpected existing fixture path: " + name)
        target.write_text(content, encoding="utf-8")
    commands = (
        ["git", "init", "--quiet", "--initial-branch=main"],
        ["git", "-c", "user.name=H632 Fixture", "-c", "user.email=h632@invalid.test",
         "-c", "core.hooksPath=/dev/null", "add", "."],
        ["git", "-c", "user.name=H632 Fixture", "-c", "user.email=h632@invalid.test",
         "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "synthetic baseline"],
    )
    for cmd in commands:
        p = call(cmd, root)
        if p.returncode:
            raise RuntimeError("Synthetic git setup failed: " + p.stderr[-200:])
    (root / "src/math.js").write_text(JS + "// synthetic diff review\n", encoding="utf-8")
    return {"status": "PREPARED", "source_sha256": sha((root / "src/math.js").read_bytes())}


def checked_node_coverage(output: str) -> float:
    """Accept genuine node:test counts on Node 22 (#) and newer (info sign)."""
    prefix = r"(?:#|ℹ)"
    for key in ("tests", "pass"):
        if not re.search(rf"(?m)^\s*{prefix}\s*{key}\s+2\s*$", output):
            raise AssertionError("Actual 2/2 node:test execution missing: " + key)
    coverage = re.search(
        rf"(?m)^\s*{prefix}\s*all files\s*\|\s*(\d+(?:\.\d+)?)", output)
    if not coverage or float(coverage.group(1)) < 80:
        raise AssertionError("Measured line coverage less than 80%")
    return float(coverage.group(1))


def security_scan(root: Path):
    source = root / "src/math.js"
    if source.is_symlink() or not source.is_file():
        raise ValueError("Unsafe source path")
    data = source.read_text(encoding="utf-8")
    if re.search(r"sk-[A-Za-z0-9_-]{8,}|api[_-]?key|BEGIN .*PRIVATE KEY", data, re.I):
        raise AssertionError("Security scan rejected synthetic source")
    return {"phase": 5, "name": "Security scan", "files_scanned": 1, "issues": 0, "exit": 0}


def run(path: Path, tsc: str = "/opt/hermes/node_modules/typescript/lib/tsc.js"):
    root = root_checked(path)
    receipt = root / "h632-six-phase-receipt.json"
    marker = root / "h632-six-phase-proof.txt"
    if receipt.exists() or marker.exists():
        raise ValueError("No reuse of six-phase evidence")
    if not (root / ".git").is_dir() or not (root / "src/math.js").is_file():
        raise ValueError("Fixture was not prepared")
    stages = {}

    def stage(n, name, args, check=None):
        p = call(args, root)
        stages[str(n)] = {
            "phase": n, "name": name, "command": args, "exit": p.returncode,
            "output_sha256": sha((p.stdout + "\n" + p.stderr).encode()),
            "stdout_tail": p.stdout[-350:], "stderr_tail": p.stderr[-350:],
        }
        if p.returncode:
            raise AssertionError(f"Phase {n} failed with exit {p.returncode}: {p.stderr[-180:]}")
        if check is not None:
            check(p)
        return p

    try:
        stage(1, "Build", ["npm", "run", "build"])
        stage(2, "Typecheck", ["node", tsc, "--project", "tsconfig.json", "--noEmit"])
        stage(3, "Lint", ["npm", "run", "lint"],
              lambda p: "H632_JS_PROJECT_LINT=PASS" in p.stdout or
              (_ for _ in ()).throw(AssertionError("Missing lint proof")))

        def tests_verified(p):
            stages["4"]["coverage_line_percent"] = checked_node_coverage(p.stdout)
        stage(4, "Tests with measured coverage", ["npm", "test"], tests_verified)
        stages["5"] = security_scan(root)
        stage(6, "Diff review", ["git", "diff", "--name-only"],
              lambda p: p.stdout.splitlines() == ["src/math.js"] or
              (_ for _ in ()).throw(AssertionError("Unexpected changed path")))
        diffcheck = call(["git", "diff", "--check"], root)
        stat = call(["git", "diff", "--stat"], root)
        changed = call(["git", "status", "--porcelain", "--untracked-files=all"], root)
        if diffcheck.returncode or stat.returncode or "src/math.js" not in stat.stdout:
            raise AssertionError("Diff or whitespace review failed")
        if changed.returncode or changed.stdout.splitlines() != [" M src/math.js"]:
            raise AssertionError("Unexpected or untracked file in synthetic git repository")
        stages["6"]["diff_stat_sha256"] = sha(stat.stdout.encode())
        result = {
            "schema": "hermes-h632-six-phase-guided-fixture-v1",
            "scope": "MODEL_DISPATCHED_PREAUTHORED_SIX_PHASE_FIXTURE",
            "autonomous_phase_planning": False,
            "completed_phases": [1, 2, 3, 4, 5, 6],
            "stages": stages, "status": "PASS",
        }
        receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        marker.write_text(PROOF, encoding="utf-8")
        return result
    except Exception as exc:
        receipt.write_text(json.dumps({
            "schema": "hermes-h632-six-phase-guided-fixture-v1",
            "status": "FAIL", "stages": stages,
            "error": type(exc).__name__ + ": " + str(exc)[:200]}, indent=2) + "\n",
            encoding="utf-8")
        raise


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("/test-home/fixture/h632-sixphase"))
    p.add_argument("--tsc", default="/opt/hermes/node_modules/typescript/lib/tsc.js")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--run", action="store_true")
    args = p.parse_args()
    print(json.dumps(prepare(args.root) if args.prepare else run(args.root, args.tsc)))


if __name__ == "__main__":
    main()
