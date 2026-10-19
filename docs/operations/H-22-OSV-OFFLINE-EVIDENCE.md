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


## 19 October 2026 - pinned binary / DB preflight (no scanner run)

The independently consulted official [v2.7.0 release metadata](https://github.com/google/osv-scanner/releases/tag/v2.7.0) lists the Linux amd64 executable asset `osv-scanner_linux_amd64` (57,725,088 bytes) with SHA256
`160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`.
Release metadata also exposes `multiple.intoto.jsonl`, but its attestation signature and subject identity have **not** been verified: `PUBLISHER_PROVENANCE_NOT_VERIFIED`. A GitHub-supplied digest is useful for pinning; it is not independent publisher provenance. Do not claim successful supply-chain verification.

`scripts/preflight_osv_offline_scan.py` is a *separate* opt-in, stdlib-only, **read-only prerequisite check**, never an OSV runner. It:

1. Checks the explicit Linux amd64 executable's exact length, ELF architecture, and digest against pinned release metadata. Does **not** execute this binary.
2. Reads only the explicitly named `uv.lock` or `package-lock.json`; validates TOML/JSON and counts entries independently of OSV, without claiming complete scanner extraction.
3. Checks the `<db-root>/osv-scanner/PyPI/all.zip` or `.../npm/all.zip` local ZIP, bounds entry sizes and aggregate expanded size, forbids traversal/encryption, parses **one** JSON advisory sample, and computes an archive digest. This does **not** validate all advisory records, database coverage, provenance or freshness.
4. Emits only sanitized counts/digests and fixed-status fields. A successfully prepared input set still returns `INCONCLUSIVE` (exit 2, `pilot_inputs_ready=true`) and explicitly records `scanner_executed=false`, `db_freshness_verified=false`, `db_completeness_verified=false`, `offline_network_boundary_verified=false` and `resident_agent_allowed=false`. Invalid/missing data also return `INCONCLUSIVE` with `pilot_inputs_ready=false`.

Without `--check`, the preflight prints `NOT_EXECUTED` without opening any files. Test without network or dependency installs:

```bash
python3 -m unittest discover -s tests -p 'test_h22_osv_preflight.py' -v
python3 -m unittest discover -s tests -p 'test_h22_osv_evidence.py' -v
python3 scripts/preflight_osv_offline_scan.py
```

**Future authorized pilot only, not executed in this change.** Preparation and scan must remain separate. On a dedicated non-production machine obtain exact v2.7.0 asset and independent verification material through a reviewed process, then fetch official PyPI/npm `all.zip` archives into private storage, record source URLs, acquisition UTC time, archive hashes and available publisher attestations. An acquisition timestamp alone does not prove DB snapshot time. No networked download is attempted by the preflight:

```bash
python3 scripts/preflight_osv_offline_scan.py --check \
  --binary /private/prepared/osv-scanner_linux_amd64 \
  --db-root /private/prepared/db \
  --lockfile /private/public-fixtures/uv.lock
# Exit 2 with sanitized INCONCLUSIVE, including readiness of the inputs only.
```

In a **separate** bounded and independently isolated scan stage, mount the prepared executable, DB and selected lockfile read-only, mount only a private writable report directory, and require an OS-enforced `--network none` / equivalent boundary, non-root UID, dropped capabilities, no Docker socket/secrets, read-only root FS, explicit CPU/RAM/PID limits and timeout. Set `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to the *mounted* parent of `osv-scanner/PyPI` and `osv-scanner/npm`; use `osv-scanner scan source --offline --lockfile /input/uv.lock --format=json`. Do not use `--offline-vulnerabilities` as a network-isolation guarantee or `--download-offline-databases` during the scan. Record exit code 0/1, exact binary/DB/lockfile hashes, actual report, runtime, extraction warnings and egress-denial test in **private** evidence storage, then review with the existing sanitized reviewer. The reviewer deliberately remains `INCONCLUSIVE` until separate independently checked execution, DB and extraction evidence exists. No live machine, VPS, CI job or dependencies are modified here.

### Verified public repository scope (GitHub tree / workflow inspection)

| Project | Files present | Existing SCA evidence | Provisional decision |
| --- | --- | --- | --- |
| Hermes (main `ca540d07a2c2bf3fe1dc8f035c914250f23349d6`) | `control_center/frontend/package-lock.json`; no top-level `uv.lock` | #185 handles pinned OCI/Syft/Trivy; lockfile scanning would be separate frontend coverage | `DEFER` targeted OSV until measured gap |
| Your Fitness Coach (master tree `42a75a5f1fbea025204c5d1e1a928bfd6581b1a1`) | `uv.lock`, `frontend/package-lock.json`, `frontend/scheduled-report/package-lock.json` | `.github/workflows/security-audit.yml`: scheduled CodeQL, dependency-audit, Trivy FS | `KEEP_TRIVY_DEPENDENCY_AUDIT` unless OSV gives distinct confirmed findings |
| Second Brain (main tree `e70cc82b4aa592909a74dbf66da3c88fed5ec90a`) | `uv.lock`, `web/package-lock.json` | Inspected `.github/workflows/ci.yml`: `uv sync --locked`, Ruff, mypy, pytest and frontend checks; no independent CVE job found | `DEFER_OWNER_GO` for real scan; public tree review is not access to vault |

None of these conclusions claims that package versions were scanned or that any CVE is absent. The Second Brain private vault and production runtime were never accessed. For YFC, a side-by-side package/version/advisory comparison with the actual Trivy/dependency-audit artifacts remains **NOT_RUN**. No new security CI gate is justified without measured incremental value.

**Environment limitations observed 2026-10-19:** isolated ChatGPT container has no scanner binary/DB and cannot resolve public download hosts; no local Docker or Podman executable is present. All linked Remote Desktop Commander devices were offline. Therefore `scanner_execution=NOT_RUN`, `DB_available=NOT_VERIFIED`, `DB_freshness=NOT_VERIFIED`, `actual_findings=NOT_VERIFIED`, and `CI_performance=NOT_MEASURED`. OSV v2.7.0 offline behaviour is described in the [upstream guide](https://github.com/google/osv-scanner/blob/v2.7.0/docs/offline-mode.md); those descriptions are not proof that a local scan took place.

**Decision:** `KEEP_OFFLINE` preparation, `REJECT_BROAD_ADOPTION` for now. Issue #189 remains open pending real isolated scanner/DB execution, effectiveness comparison, and the distinct Second Brain owner gate. The new preflight is *not* a complete implementation of #189.
