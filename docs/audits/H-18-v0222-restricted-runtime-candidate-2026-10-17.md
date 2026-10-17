# H-18 / #199 - restricted v0.22.2 derivative, 17 October 2026

**Status: PARTIAL / LOCAL_RESTRICTED_DERIVATIVE_VERIFIED / RESIDENT NO-GO.**
This report describes an opt-in *non-production* image with SSH support deliberately removed.
It does not authorize deploying or enabling Hermes AI Agent. No registry push, provider
request, cloud proxy, production container mutation or credential/volume transfer occurred.
The VPS check below was read-only.

## Source, integrity, and local build

- Original base: `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`, Linux/AMD64, upstream tag v0.22.2 source commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`. A signed **source-to-image** correspondence has not been established.
- Parent recipe: `docker/v0222-pyjwt-fixed-candidate/Dockerfile`; new, separate opt-in recipe: `docker/v0222-restricted-runtime-candidate/Dockerfile`. The default staging recipe remains unchanged.
- PyJWT 2.15.1 wheel: SHA256 `42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193`, matched official PyPI. Existing tool patch: SHA256 `e7157fd4831b32670d418a5eec675a8cab8318a49e5c1df94e33da7e9d3a2016`, checked before staging.
- Local preparation: `python -m scripts.prepare_v0222_pyjwt_candidate --execute --recipe restricted --wheel <verified-wheel> --output-dir <new-external-stage>` returned intentional exit **2**, `OFFLINE_CONTEXT_PREPARED_NO_GO`; three files only; staged Dockerfile SHA256 `fa33ec787e8994ad00482ba4ce1d62b35ce9001f608c1630172fa97d69b046cc`.
- Docker Desktop Linux/AMD64 `docker build --pull=false --network none --platform linux/amd64 --no-cache` succeeded. BuildKit fetched/resolved **base metadata** in 12.6s; `--network none` restricts RUN steps, not necessarily all builder metadata traffic. No unapproved source downloads in RUN; base image already present locally.
- New local OCI index/image ID **`sha256:6195a57a79ab8bdd020f0a4b6648e2ef4843c902903fcf25b2c9d8556cbc93f5`**, build manifest `sha256:6e297d6e666574d58ba47da99e1397dfbdbd75f3825aeda779204be5b42cd046`. These are **local**, not publisher-signed/registry-origin attestations. BuildKit emitted an unsigned attestation manifest `sha256:91577fc29b3272de5215f8d401bf76b7a74126a64dec472342a5a7ca6fd982c4`; independent source/build provenance and byte-for-byte cross-builder reproducibility remain unverified.

## Scope of native package removal

At the exact base digest, the locked preflight observed:
`openssh-client 1:10.0p1-7+deb13u4`,
`linux-libc-dev 6.12.111-1`,
`libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3`.

The candidate performs an offline `apt-get -s purge openssh-client linux-libc-dev`, sorts the exact removal names and compares them against a **closed 14-package list** before running `apt-get --yes --no-download purge`. The actual build removed `openssh-client`, `linux-libc-dev`, `g++`, `g++-14`, `g++-14-x86-64-linux-gnu`, `g++-x86-64-linux-gnu`, `libc6-dev`, `libexpat1-dev`, `libpython3-dev`, `libpython3.13-dev`, `libstdc++-14-dev`, `python3-dev`, `python3.13-dev`, `zlib1g-dev`. No `autoremove` or distribution mixing.

**Compatibility limitation:** SSHEnvironment and any user flow requiring a system SSH executable, C/C++ compilers, or Python development headers will no longer work. This is a restricted research candidate, **not** a general-purpose upstream replacement. `libxml2` remains installed and potentially reachable through native/transitive libraries; do not claim it is unused.

## Independent offline measurements (same flags and DB)

- Verified official release archives: Trivy **0.76.0** Windows SHA256 `7b4762a5a5326cb4b83dfd2bb5d9aaf15a1ed867c75cad7dd8b38840a28e7be6`; Syft **1.54.1** Windows SHA256 `8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f`.
- Trivy DB `UpdatedAt=2026-10-16T01:13:54.947090392Z`, downloaded 2026-10-17, database file SHA256 `bf1f1b29d76cae9ff085d418cb4bfdb3906b6069f837abdef06558b8102dd1db`.
- Three **fresh** rechecks on the same Windows Docker Desktop daemon, with identical `trivy image --skip-db-update --offline-scan --scanners vuln` settings. Same local DB, no suppression/waiver.

| Severity | Original exact v0.22.2 | PyJWT 2.15.1 derivative (#216) | Restricted derivative |
| --- | ---: | ---: | ---: |
| CRITICAL | 4 | 3 | **1** |
| HIGH | 270 | 265 | **184** |
| MEDIUM | 1173 | 1165 | **347** |
| LOW | 1055 | 1055 | 830 |
| UNKNOWN | 20 | 20 | 18 |
| Total records | 2522 | 2508 | **1380** |

Remaining CRITICAL: **CVE-2026-6653 / libxml2**. Trivy is a dependency scanner, not an exploitation test; removing a package eliminates its scanner record but does not prove that other execution paths are safe. HIGH findings are still **184** and not hidden.

- Syft CycloneDX JSON SHA256 `29415ba8db04419459db55ff3dded420d596830e2d8ed0a117029e7e44eafb27` (4,174 component entries); SPDX JSON SHA256 `ebe28fb72d113b38fdc02fcb72b4d3b344a309b6fa0094a7ea5c5eac31ed5bd2` (2,074 package entries). Different schema counts are **not** interchangeable with Trivy vulnerability records.
- Sanitized Trivy report SHA256 `6c39766afcdd5f986f5242e74d58c9e2a55067a9e7d3f3d3a702060b2c6b93d2`. Raw SBOM and scanner JSON remain on the isolated Windows machine; they are not committed.

## Runtime and denial checks

- 17 Python unit tests for default and opt-in staging behavior: **PASS**; errors fail closed; no Docker required for these tests.
- Actual new restricted image, Docker `--pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534`, bounded CPU/memory/PIDs, no volume/secrets: existing H-18 mocked native dispatch inspector returned `NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS`, `connect_ex(TEST-NET-1:22)=101 (ENETUNREACH)`; neither native dispatcher nor `subprocess.Popen` reached, no real SSH executed. **Only the mocked paths**, no complete OS/MCP proof.
- In same restricted container the existing synthetic RSA-2048 PyJWT smoke accepted valid RS256, rejected altered payload, reported **PyJWT 2.15.1**, exit 0; no stored private keys or real tokens.
- Runtime package check found `libxml2` installed at original version and `ssh` executable absent. The Python interpreter is still **3.14.7**; independent compatibility/burn-in tests for every Hermes feature remain outstanding.

## CVE decision matrix (exact scope)

| CVE | Original package | Restricted candidate | Runtime applicability | Fix status | Evidence / caveat |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-102268 | PyJWT 2.13.0 | PyJWT 2.15.1 | AFFECTED as vulnerable dependency originally; exact auth exploit path not proven | REMEDIATED (package) | PyPI SHA, actual RS256/tamper test, Trivy 0 package findings |
| CVE-2026-60002 | openssh-client 1:10.0p1-7+deb13u4 | Absent | NOT_APPLICABLE to this exact restricted candidate **via removed OpenSSH binary**; other transports/MCP unverified | REMEDIATED by removal, not by upstream patch | dpkg purge, no ssh command, bounded network-none negative test |
| CVE-2026-43185 | linux-libc-dev 6.12.111-1 | Absent | NOT_APPLICABLE to userspace headers in this candidate; host kernel is **separate** | REMEDIATED by package removal, not a kernel fix | exact 14-package removal and read-only host observations |
| CVE-2026-6653 | libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Same vulnerable version | INCONCLUSIVE; possible native/transitive XML paths | **UNREMEDIATED** | Debian Trixie no-DSA, no Debian 13 fixed package; no runtime negative proof for all native XML |

Vendor information checked 17 October 2026: [Debian libxml2](https://security-tracker.debian.org/tracker/CVE-2026-6653),
[Debian openssh](https://security-tracker.debian.org/tracker/CVE-2026-60002),
[Canonical ksmbd](https://ubuntu.com/security/CVE-2026-43185), and
[PyJWT GHSA](https://github.com/advisories/GHSA-ffc3-869f-jxw9).
Debian Trixie has no verified stable patched package for these libxml2/openssh CVEs at this snapshot; no-DSA **does not mean not affected**. Avoid unreviewed Debian unstable binaries in stable images.

Authorized read-only VPS observation on 17 October 2026: `uname -r=6.8.0-146-generic`, `ksmbd` absent from `/proc/modules` and `/sys/module/ksmbd`, **0 TCP 445 listeners**. Canonical lists the Ubuntu Noble `linux` CVE fix at **6.8.0-134.134**. This is specific point-in-time scope evidence, not continuous module/host attestation or proof for future hosts. The container's Debian `linux-libc-dev` was **not the actual host kernel**.

## Remaining security gates

- **#199 OPEN / PARTIAL:** libxml2 CRITICAL unremediated, 184 HIGH, no trusted Debian 13 backport, broad runtime/XML/native reachability incomplete, Python 3.14.7 unchanged, full product compatibility and owner signoff outstanding.
- **#185 OPEN:** signed source-to-build-to-OCI attestation, independently validated publisher provenance, full SBOM/license coverage and cross-builder reproducibility absent.
- **#33 resident NO-GO:** OS/native/MCP enforcement, paid-provider hard stop, resource burn-in, and owner GO incomplete. No production deploy, resident agent, Cloudflare proxy or third-party model usage is authorized by this candidate.
