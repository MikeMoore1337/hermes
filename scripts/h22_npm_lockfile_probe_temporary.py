"""Disposable H-22: compare real npm-generated lockfiles against the pinned offline OSV v2."""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

SHA = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"
SIZE = 57_725_088
TARGET = "GHSA-p6mc-m468-83gw"
BINARY = "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64"
DB_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"


def emit(**data):
    print(json.dumps(data, sort_keys=True), flush=True)


def fetch(url: str, path: pathlib.Path, max_size: int):
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Hermes-H22-experiment"}), timeout=90) as response, path.open("wb") as file:
        for _ in range(2000):
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > max_size:
                raise ValueError("download_too_large")
            digest.update(block)
            file.write(block)
        else:
            raise ValueError("download_limit")
    return digest.hexdigest(), size


def run(args, timeout=120, cwd=None):
    return subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)


def extract_info(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        files = [n for n in z.namelist() if n.endswith("/" + TARGET + ".json") or n == TARGET + ".json"]
        if len(files) != 1:
            return {"status": "MISSING_OR_MULTIPLE_ADVISORY", "records": len(files)}
        raw = z.read(files[0])
        entry = json.loads(raw)
    affected = [x for x in entry.get("affected", []) if x.get("package", {}).get("name") == "lodash" and x.get("package", {}).get("ecosystem") == "npm"]
    return {"status": "FOUND", "exact_name_match": len(affected) > 0, "affected_count": len(affected),
            "semver_ranges": sum(len(x.get("ranges", [])) for x in affected),
            "explicit_versions": sum(len(x.get("versions", [])) for x in affected)}


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() == 0:
        raise ValueError("nonroot_linux_amd64_required")
    with tempfile.TemporaryDirectory(prefix="h22-npm-") as temp:
        root = pathlib.Path(temp)
        executable = root / "osv"
        digest, length = fetch(BINARY, executable, SIZE)
        if digest != SHA or length != SIZE:
            raise ValueError("binary_hash_or_size_mismatch")
        executable.chmod(0o555)
        dbroot = root / "db"
        d = dbroot / "osv-scalibr" / "npm"
        d.mkdir(parents=True)
        zip_path = d / "all.zip"
        dbsha, dbbytes = fetch(DB_URL, zip_path, 300_000_000)
        emit(step="prepared", binary_verified=True, database_sha256=dbsha, database_bytes=dbbytes,
             publisher_signature_verified=False, db_snapshot_verified=False)
        adv = extract_info(zip_path)
        emit(step="advisory", **adv)
        if adv["status"] != "FOUND":
            raise ValueError("advisory_missing")
        # Runtime only reads DB from a disposable local filesystem copy; no network.
        cases = [("vulnerable", "4.17.15", True), ("fixed", "4.17.23", False)]
        fixture_dir = root / "fixtures"
        fixture_dir.mkdir()
        for label, version, _ in cases:
            folder = fixture_dir / label
            folder.mkdir()
            (folder / "package.json").write_text(json.dumps({
                "name": "h22-public-npm-example", "private": True, "version": "1.0.0"
            }), encoding="utf-8")
            npm = run(["npm", "install", "lodash@" + version, "--package-lock-only",
                       "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact"], timeout=100, cwd=folder)
            if npm.returncode:
                raise ValueError("npm_lockfile_generation_failed")
            lock = json.loads((folder / "package-lock.json").read_text(encoding="utf-8"))
            if lock.get("packages", {}).get("node_modules/lodash", {}).get("version") != version:
                raise ValueError("npm_lockfile_version_mismatch")
            emit(step="fixture", case=label, lockfile_version=lock.get("lockfileVersion"),
                 package_count=len(lock["packages"]), package_version=version)
        pull = run(["docker", "pull", "ubuntu:24.04"], timeout=180)
        if pull.returncode:
            raise ValueError("base_image_unavailable")
        image = run(["docker", "image", "inspect", "--format={{.Id}}", "ubuntu:24.04"])
        if image.returncode:
            raise ValueError("image_digest_unavailable")
        image_id = image.stdout.decode().strip()
        base = ["docker", "run", "--rm", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--pids-limit=64", "--cpus=1", "--memory=1536m",
                "--user=" + str(os.getuid()) + ":" + str(os.getgid()),
                "--tmpfs=/tmp:rw,nosuid,nodev,size=96m,mode=1777",
                "--env=HOME=/tmp", "--env=TMPDIR=/tmp",
                "--env=OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db",
                "--mount=type=bind,src=" + str(executable) + ",dst=/osv,readonly",
                "--mount=type=bind,src=" + str(dbroot) + ",dst=/db",
                "--mount=type=bind,src=" + str(fixture_dir) + ",dst=/input,readonly"]
        proof = run(base + ["--entrypoint=/bin/sh", image_id, "-c",
                            'test "$(ls /sys/class/net | tr -d "[:space:]")" = "lo"'])
        if proof.returncode:
            raise ValueError("network_isolation_unverified")
        emit(step="isolation", status="PASS", no_network=True, root_readonly=True, nonroot=True)
        overall = True
        for label, version, expected in cases:
            result = run(base + ["--entrypoint=/osv", image_id, "scan", "source",
                                 "--offline", "-L", "/input/" + label + "/package-lock.json",
                                 "--format=json", "--all-packages"], timeout=120)
            if result.returncode not in (0, 1):
                emit(step="scan", case=label, status="INCONCLUSIVE", exit=result.returncode,
                     stderr_bytes=len(result.stderr))
                overall = False
                continue
            parsed = json.loads(result.stdout)
            packages = [p for group in parsed.get("results", []) for p in group.get("packages", [])]
            matched = []
            for p in packages:
                if p.get("package", {}).get("name") != "lodash":
                    continue
                for vuln in p.get("vulnerabilities", []):
                    if TARGET in {vuln.get("id"), *(vuln.get("aliases") or [])}:
                        matched.append(TARGET)
            detected = len(matched) > 0
            passed = detected == expected
            overall &= passed
            emit(step="scan", case=label, package_version=version,
                 expected_target_advisory=expected, detected_target_advisory=detected,
                 packages_in_report=len(packages), total_findings=sum(
                     len(x.get("vulnerabilities", [])) for x in packages),
                 exit=result.returncode, status="PASS" if passed else "INCONCLUSIVE")
        # Read-only, public lockfile comparison. Source refs are exact immutable SHAs.
        public = [
            ("Hermes", "79104b83136e03f33fec0a23494cd042848d3d0a",
             "control_center/frontend/package-lock.json", "npm"),
            ("YFC", "bc48d09c3415c4b146a0400efc18cb9031413d18",
             "uv.lock", "PyPI"),
            ("YFC", "bc48d09c3415c4b146a0400efc18cb9031413d18",
             "frontend/package-lock.json", "npm"),
            ("YFC", "bc48d09c3415c4b146a0400efc18cb9031413d18",
             "frontend/scheduled-report/package-lock.json", "npm"),
        ]
        pypi_zip = dbroot / "osv-scalibr" / "PyPI" / "all.zip"
        pypi_zip.parent.mkdir(parents=True)
        pysha, pybytes = fetch(
            "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
            pypi_zip, 90_000_000)
        emit(step="pypi_db", sha256=pysha, bytes=pybytes, snapshot_verified=False)
        for index, (project, sha, path, ecosystem) in enumerate(public):
            owner_repo = "MikeMoore1337/hermes" if project == "Hermes" else "MikeMoore1337/your-fitness-coach"
            url = f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}"
            folder = fixture_dir / ("public-" + str(index))
            folder.mkdir()
            source = folder / pathlib.Path(path).name
            lock_digest, lock_bytes = fetch(url, source, 8_000_000)
            command = base + ["--entrypoint=/osv", image_id, "scan", "source",
                              "--offline", "-L",
                              "/input/" + folder.name + "/" + source.name,
                              "--format=json", "--all-packages"]
            scanned = run(command, timeout=120)
            if scanned.returncode not in (0, 1):
                overall = False
                emit(step="project_scan", project=project, relative_path=path,
                     source_sha=sha, status="INCONCLUSIVE", exit=scanned.returncode,
                     lock_sha256=lock_digest, lock_bytes=lock_bytes)
                continue
            try:
                report = json.loads(scanned.stdout)
                results = report["results"]
                packages = [p for group in results for p in group.get("packages", [])]
                if not packages:
                    raise ValueError("no_packages_extracted")
                findings = []
                for pkg in packages:
                    p = pkg.get("package") or {}
                    for v in pkg.get("vulnerabilities", []):
                        names = [v.get("id"), *(v.get("aliases") or [])]
                        ids = sorted({i for i in names if isinstance(i, str) and
                                      (i.startswith("CVE-") or i.startswith("GHSA-"))})
                        findings.append({"package": p.get("name"), "version": p.get("version"),
                                         "ids": ids[:5]})
                emit(step="project_scan", project=project, relative_path=path,
                     source_sha=sha, lock_sha256=lock_digest, lock_bytes=lock_bytes,
                     ecosystem=ecosystem, status="RESULTS_RECORDED",
                     packages_with_result_entries=len(packages),
                     vulnerability_entries=len(findings), sample_findings=findings[:12],
                     exit=scanned.returncode)
            except (KeyError, ValueError, TypeError):
                overall = False
                emit(step="project_scan", project=project, relative_path=path,
                     source_sha=sha, status="INCONCLUSIVE",
                     reason="invalid_or_empty_scan_output", exit=scanned.returncode)
        emit(step="summary", status="PASS" if overall else "INCONCLUSIVE",
             ephemeral=True, prod_touched=False, public_lockfiles_only=True, private_lockfiles_read=False)
        return 0 if overall else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        emit(step="fatal", status="INCONCLUSIVE", category=type(error).__name__)
        sys.exit(2)
