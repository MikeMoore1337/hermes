# H-22 / #189 - OSV-Scanner: bounded offline evidence pilot

**State:** repository-only experimental reviewer. No OSV binary, local OSV database or real project lockfile was used in this PR. **No finding count, package safety, scanning success or vulnerability remediation is claimed.** Production, CI security checks and external credentials unchanged.

## Why this is separate from Trivy

- Hermes immutable OCI image v0.22.2: #185 and #199 already use Syft/Trivy, so OSV lockfile scan **does not substitute** OCI SBOM or source-to-image attestation.
- YFC: existing CodeQL/Trivy/dependency-audit controls; general OSV addition now would duplicate work without a proven gap.
- Second Brain: `uv.lock` exists and dependency SCA coverage might be missing. It is a *candidate* for a separate approved code-repository-only pilot, never for private vault or source upload.
- Hermes itself: exact pinned upstream image plus private runtime must keep #33 resident **NO-GO**.

## Authoritative upstream contracts

- [OSV-Scanner v2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0) (released 2026-10-12) is the fixed version chosen for future execution; **publisher binary signature and archive SHA256 are not verified**.
- [Offline mode](https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md): `--offline` prohibits vulnerability API queries and local database updates; the database must already exist. With missing or stale database, no clean PASS is permitted. `--offline-vulnerabilities` **is not equivalent**: other features may access the network.
- [JSON format](https://github.com/google/osv-scanner/blob/main/docs/output.md): `results[].source.type=lockfile`, `results[].packages[].package`, `vulnerabilities[].id/aliases`; absolute source paths and package names may be present and must not be published.
- [Source scan](https://github.com/google/osv-scanner/blob/main/docs/usage.md): supported `-L <lockfile>`; no `fix` subcommand, autofix, registry resolution or vulnerability DB downloads in restricted execution.

## Implemented in Hermes (no scanner execution)

`scripts/review_osv_offline_scan.py` is a Python stdlib-only **input evidence reviewer**, not an OSV implementation or a wrapper that executes `osv-scanner`. It accepts a locally supplied OSV JSON report, the lockfile and an unsigned operator manifest. Schema `hermes-h22-osv-evidence-v1` requires:

- exact claimed scanner version `2.7.0`, SHA256 for scanner executable, selected ecosystem DB archive, report and lockfile;
- ecosystem/lockfile limited to `PyPI/uv.lock` or `npm/package-lock.json`, `scan_offline=true`, recorded scan exit code, UTC DB snapshot timestamp;
- valid bounded JSON, duplicate-key refusal, matching report/lockfile hashes, lockfile-type source and package ecosystem checks.

Every valid report returns `INCONCLUSIVE` (exit 2): a *self-reported* scanner hash, DB hash, timestamp and scan exit code are **not independently attested**, and an empty vulnerabilities array says nothing about the completeness/freshness of a database or extractor. The sanitized machine-readable result contains only counts of observed affected package entries / vulnerability records / CVE-GHSA aliases, not raw paths, package names, lockfile contents, text, CVSS claims, fixes or tokens. Invalid input also exits 2 with a **fixed error code**.

The flag `--execute` means **read the three supplied evidence files**, not run any binary or a scanner. Without it, CLI returns `NOT_EXECUTED`. This distinction prevents accidental project scans.

### Local verification (no network)

```bash
python3 -m unittest discover -s tests -p 'test_h22_osv_evidence.py' -v
python3 scripts/review_osv_offline_scan.py
# Prints NOT_EXECUTED; no files read.
```

Tests use only fictional dependencies and vulnerability IDs. Negatives cover hash mismatch, unsupported ecosystem, online mode, unknown scanner version, malformed and duplicate-key JSON, missing evidence, leaking a hypothetical private package name/path, output sanitization and the prohibition against a false PASS.

### Future opt-in external scan, NOT performed

A standalone, non-production Linux sandbox would need vetted exact v2.7.0 binary + independent SHA256/signatures, OS network isolation, **pre-downloaded and hash-pinned** PyPI or npm offline database, a synthetic lockfile, locked-down user/storage, no secret mounts, and explicit approval for the external binary:

```bash
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/absolute/path/to/prepared-readonly-db
osv-scanner --offline scan -L /absolute/path/to/synthetic/uv.lock --format json > /isolated-private/report.json
# Never use --download-offline-databases in the scan sandbox.
```

Capture the real exit code and external evidence manifest **outside this verifier**. Compare findings with Trivy/CodeQL and existing dependency-audit signals. Audit severity, false negatives and fixed versions via authoritative advisories manually; do not equate absence of reported vulnerabilities with safety. Do not publish raw vulnerability output (source path may identify private files).

## Decision

**Pilot code only; OSV binary/DB and real private project access NOT_RUN.** No new CI job or scanner runtime dependency is justified until there is a confirmed incremental detection gap and authorized, pinned isolated scan. #189 remains OPEN; no implementation of a production hard-stop or release GO.
