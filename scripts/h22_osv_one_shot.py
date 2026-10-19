"""One-off H-22 experiment: public synthetic fixtures, no project lockfiles or secrets.

This script is *not* a CI scanner integration. Delete it with the temporary workflow
after documenting the observed outcome. Raw JSON stays in the ephemeral runner.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PINNED_BINARY_SHA = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"
BINARY_BYTES = 57_725_088
MAX_ZIP = 300_000_000
URL_BINARY = "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64"
URL_DB = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"


def out(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def download(url: str, target: Path, limit: int) -> tuple[str, int, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "Hermes-H22-offline-pilot-v2.7.0"})
    digest = hashlib.sha256()
    total = 0
    start = time.monotonic()
    with urllib.request.urlopen(request, timeout=90) as response, target.open("wb") as sink:
        date = response.headers.get("Last-Modified")
        while True:
            if time.monotonic() - start > 180:
                raise RuntimeError("download_timeout")
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RuntimeError("download_size_limit")
            sink.write(chunk)
            digest.update(chunk)
    if total == 0:
        raise RuntimeError("download_empty")
    return digest.hexdigest(), total, date


def command(args: list[str], *, timeout: int = 120):
    result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return result


def write_uv(target: Path, version: str):
    target.write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n'
        '[[package]]\nname = "requests"\nversion = "' + version + '"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )


def write_npm(target: Path, version: str):
    target.write_text(json.dumps({
        "name": "h22-synthetic", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {"": {"name": "h22-synthetic", "version": "1.0.0"},
                     "node_modules/lodash": {"version": version}},
    }), encoding="utf-8")


def parse_report(raw: bytes, target_ids: set[str]) -> tuple[bool, int, int]:
    report = json.loads(raw)
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise RuntimeError("bad_report_shape")
    entries = 0
    findings = 0
    found = False
    for result in report["results"]:
        for item in result.get("packages", []):
            entries += 1
            pkg = item.get("package") or {}
            if isinstance(pkg, dict) and pkg.get("name") in {"requests", "lodash"}:
                # Synthetic public package names only.
                print(json.dumps({"step": "extraction_identity", "package": pkg.get("name"),
                                  "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem")}))
            for vuln in item.get("vulnerabilities", []):
                findings += 1
                ids = {vuln.get("id"), *(vuln.get("aliases") or [])}
                if ids.intersection(target_ids):
                    found = True
    return found, findings, entries


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("linux_amd64_required")
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="h22-ephemeral-") as name:
        root = Path(name)
        binary = root / "osv-scanner"
        db = root / "db" / "osv-scanner"
        fixtures = root / "fixtures"
        fixtures.mkdir()
        db.mkdir(parents=True)
        digest, n, last = download(URL_BINARY, binary, BINARY_BYTES)
        if digest != PINNED_BINARY_SHA or n != BINARY_BYTES:
            raise RuntimeError("official_binary_digest_mismatch")
        binary.chmod(0o555)
        out(step="binary_acquired", version="2.7.0", sha256=digest, size=n,
            publisher_identity_verified=False)
        metadata = {}
        for ecosystem in ("PyPI", "npm"):
            directory = db / ecosystem
            directory.mkdir()
            sha, size, modified = download(URL_DB.format(ecosystem), directory / "all.zip", MAX_ZIP)
            metadata[ecosystem] = {"sha256": sha, "size": size, "last_modified": modified}
        out(step="db_acquired", at_utc=datetime.now(timezone.utc).isoformat(),
            metadata=metadata, db_snapshot_verified=False)
        # OSV v2's local DB extractor creates cache entries under its DB root.
        # Keep downloaded ZIPs immutable and give it only a disposable scratch copy.
        cache = root / "scratch-db"
        shutil.copytree(root / "db", cache)
        # GitHub runner UID is non-root and owns only the disposable cache copy.
        out(step="db_scratch_prepared", disposable=True, source_archives_readonly=True)
        image = command(["docker", "pull", "ubuntu:24.04"], timeout=180)
        if image.returncode:
            raise RuntimeError("sandbox_image_unavailable")
        inspect = command(["docker", "image", "inspect", "--format={{.Id}}", "ubuntu:24.04"])
        if inspect.returncode:
            raise RuntimeError("sandbox_image_digest_missing")
        image_id = inspect.stdout.decode("utf-8").strip()
        out(step="sandbox_image_prepared", docker_image_id=image_id)
        base = [
            "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=64", "--cpus=1.0",
            "--memory=1536m", "--user=" + str(os.getuid()) + ":" + str(os.getgid()),
            "--tmpfs=/tmp:rw,nosuid,nodev,size=96m,mode=1777",
            "--env=HOME=/tmp", "--env=XDG_CACHE_HOME=/tmp/osv-cache",
            "--env=TMPDIR=/tmp",
            "--env=OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db",
            "--mount=type=bind,src=" + str(binary) + ",dst=/osv-scanner,readonly",
            "--mount=type=bind,src=" + str(root / "db") + ",dst=/db-source,readonly",
            "--mount=type=bind,src=" + str(cache) + ",dst=/db",
            "--mount=type=bind,src=" + str(fixtures) + ",dst=/input,readonly",
        ]
        boundary = command(base + ["--entrypoint=/bin/sh", image_id, "-c",
                                 'test "$(tail -n +3 /proc/net/dev | awk -F: \'{gsub(/ /,"",$1);print $1}\')" = "lo"'])
        if boundary.returncode:
            raise RuntimeError("network_boundary_unverified")
        out(step="network_boundary", status="PASS", network="none", interfaces="lo_only")
        # Diagnose the binary without ever mounting real project content or secrets.
        probe = command(base + ["--entrypoint=/bin/sh", image_id, "-c",
                                'ls -l /osv-scanner; head -c 4 /osv-scanner | od -An -tx1'])
        out(step="binary_mount_probe", status="PASS" if probe.returncode == 0 else "INCONCLUSIVE",
            exit_code=probe.returncode, readable=probe.returncode == 0)
        version_probe = command(base + ["--entrypoint=/osv-scanner", image_id, "--version"])
        version_err = version_probe.stderr.decode("utf-8", errors="replace").lower()
        category = ("exec_not_found" if "no such file or directory" in version_err
                    else "access_denied" if "permission denied" in version_err
                    else "dynamic_link_failure" if "shared librar" in version_err
                    else "unclassified")
        out(step="binary_execution_probe",
            status="PASS" if version_probe.returncode == 0 else "INCONCLUSIVE",
            exit_code=version_probe.returncode, reason=category,
            stderr_bytes=len(version_probe.stderr))

        cases = [
            ("python-vulnerable", "uv.lock", "2.19.0", {"CVE-2018-18074", "GHSA-x84v-xcm2-53pg"}, True),
            ("python-fixed", "uv.lock", "2.32.5", {"CVE-2018-18074", "GHSA-x84v-xcm2-53pg"}, False),
            ("npm-vulnerable", "package-lock.json", "4.17.15", {"GHSA-p6mc-m468-83gw", "CVE-2020-8203"}, True),
            ("npm-fixed", "package-lock.json", "4.17.23", {"GHSA-p6mc-m468-83gw", "CVE-2020-8203"}, False),
        ]
        all_ok = True
        for name, lock, version, ids, expected in cases:
            sub = fixtures / name
            sub.mkdir()
            if lock == "uv.lock":
                write_uv(sub / lock, version)
            else:
                write_npm(sub / lock, version)
            started = time.monotonic()
            scan = command(
                ["timeout", "100s", *base, "--entrypoint=/osv-scanner", image_id,
                 "scan", "source", "--offline", "-L", "/input/" + name + "/" + lock,
                 "--format=json", "--all-packages"],
                timeout=115,
            )
            elapsed = round(time.monotonic() - started, 2)
            if scan.returncode not in (0, 1):
                # Synthetic fixtures only. Replace filesystem paths and constrain diagnostics.
                diagnostic = scan.stderr.decode("utf-8", errors="replace")
                match = re.search(r"mkdir (/[^\\s:]+)", diagnostic)
                if match:
                    target = match.group(1)
                    location = ("db" if target.startswith("/db/") or target == "/db" else
                                "tmp" if target.startswith("/tmp/") or target == "/tmp" else
                                "root-home" if target.startswith("/root/") else
                                "fs-root" if target.startswith("/.") else "other")
                else:
                    location = "unknown"
                diagnostic = re.sub(r"/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]*", "<path>", diagnostic)
                diagnostic = "".join(ch if ch.isprintable() else " " for ch in diagnostic)[:1200]
                out(step="scan", case=name, status="INCONCLUSIVE", exit_code=scan.returncode,
                    duration_s=elapsed, stderr_bytes=len(scan.stderr), stderr_hint=diagnostic,
                    mkdir_location=location)
                all_ok = False
                continue
            try:
                detected, findings, entries = parse_report(scan.stdout, ids)
            except (ValueError, TypeError, RuntimeError):
                out(step="scan", case=name, status="INCONCLUSIVE", reason="invalid_osv_json",
                    exit_code=scan.returncode, stdout_bytes=len(scan.stdout),
                    stderr_bytes=len(scan.stderr))
                all_ok = False
                continue
            ok = detected is expected and entries >= 1
            all_ok &= ok
            out(step="scan", case=name, ecosystem="PyPI" if lock == "uv.lock" else "npm",
                version=version, target_advisory_detected=detected,
                expected_detected=expected, findings=findings, packages_with_entries=entries,
                exit_code=scan.returncode, duration_s=elapsed, status="PASS" if ok else "INCONCLUSIVE")
        out(step="summary", status="PASS" if all_ok else "INCONCLUSIVE",
            elapsed_s=round(time.monotonic() - start, 1), files_mutated=False,
            dependency_upgrade=False, full_db_coverage_verified=False,
            project_lockfiles_scanned=False, secrets_used=False)
        return 0 if all_ok else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # No exception messages with URLs, paths or raw reports are logged.
        out(step="fatal", status="INCONCLUSIVE", reason=type(exc).__name__)
        sys.exit(2)
