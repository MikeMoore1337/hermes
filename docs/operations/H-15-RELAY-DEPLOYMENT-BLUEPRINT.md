# H-15: self-hosted relay deployment blueprint (NOT ACTIVE)

Related issues: #371 (relay security), #372 (OAuth + owner devices).
See also docs/operations/H-15-SELFHOSTED-REMOTE-MCP.md.

## Verified Hermes VPS baseline (2026-10-19)

- Public https://mcp.mikemoore.top/healthz: HTTP 200, MCP_TLS_READY.
  Public GET/POST /mcp: HTTP 503 (intentionally closed).
- Cloudflare Origin Rule points the MCP hostname only to Caddy TLS port
  8444; Configuration Rule uses SSL Strict. Xray/443 and MTProxy/8443
  remain unchanged.
- Cloudflare Origin CA TLS is at /etc/caddy/certs/mcp-origin.pem and
  mcp-origin.key (root:caddy 0640).
- Dedicated Docker bridge hermes-brc-internal: 172.29.251.0/28,
  internal=true, gateway .1, reserved relay IP 172.29.251.2.
  Owner tested bridge reachability from the host, zero connected devices,
  zero published ports and no successful probe of external egress.
  Disposable smoke containers were cleaned up.
- Dedicated non-login OS account hermes-brc-relay UID 979/GID 975.
  State: /var/lib/hermes-brc-relay, service-owned 0700.
  Secrets: /etc/hermes-brc-relay/relay.env, root-owned 0600.
  Backups: /var/backups/hermes-brc-relay, root-owned 0700.
  **No permanent relay container or SQLite data exists yet.**
- Already imported OCI image with Docker runtime ID
  sha256:4f0da80149db3670c3b0d14462e5609225b3718c09872f48e9ba584a4de0a7e6
  is **EVALUATION ONLY**. It cannot be used by the new launcher.

## Dormant deployment code

deploy/h15/owner-relay.sh provides modes: preflight, start, status, stop.

The operator must supply a separately approved, **locally loaded exact
sha256 image ID**; OCI image labels and upstream SHA are sanity checks,
**not cryptographic evidence** of trusted build provenance. Before
approval, verify the new production release independently (OS-layer
SBOM, provenance, vulnerability review, pinned archive/manifest digest).

The script checks the dedicated state owner/group and 0700 directory,
root-only secrets, non-login identity, correct labeled and empty internal
bridge, Caddy health, and that the PUBLIC MCP endpoint is still HTTP
503 over a validated TLS connection.

A start additionally requires explicit owner acknowledgement via
H15_BRC_OWNER_APPROVED_OAUTH_ONLY=YES_OAUTH_ONLY_NO_AGENTS. This is a
manual confirmation, not a security mechanism. It does not change Caddy,
Cloudflare, firewall settings or device-pairing records.

The runtime uses the actual host service account UID/GID (979:975 here),
not the evaluation image's 65534:65534. Only /state is persistent and
writable. Root filesystem read-only, private tmpfs, no extra capabilities,
no-new-privileges, memory 512MiB, CPU 0.5, 80 PIDs, and no published
ports. The fixed bridge IP is 172.29.251.2:3000. Public OAuth issuer is
https://mcp.mikemoore.top; TRUST_PROXY=false by default.

After opt-in start, the script checks: zero paired devices, local health,
OAuth issuer and S256 metadata, unauthorized /mcp HTTP 401, public /mcp
still HTTP 503. Failed launch removes only its own labeled container;
existing services remain untouched. Approved stop requires a separate
H15_BRC_OWNER_APPROVED_STOP=YES and leaves SQLite intact.

**Credential limitation:** upstream BRC accepts admin/session secrets
through process environment. Docker administrators can read them via
daemon inspection; a root-only env file does not prevent that. Keep
Docker daemon access strictly privileged; production hardening should
support reading secret files without putting secrets in environment.

## Atomic SQLite backups

python3 deploy/h15/backup-relay.py uses the built-in SQLite online
backup API and quick_check; snapshots are atomically renamed with
root-only permissions (0600) under the protected backup directory.
It neither prunes old files nor creates a timer. Unit tests verify
correct restoration of test records and reject bad source or directories.

Backups contain authentication and device data. Off-host encrypted
storage, retention policy, a tested WAL-aware restore and key rotation
remain mandatory. For restore, stop the relay, preserve the existing
SQLite DB and -wal/-shm as a rollback set, verify backup integrity,
restore owner:group 0600, avoid replaying stale WAL/SHM, then validate
OAuth/device status before enabling the public reverse proxy.

## Disposable SQLite backup restore rehearsal (dormant)

`deploy/h15/rehearse-restore.py` validates one **already-created**
`relay-*.sqlite3` backup without touching the active relay SQLite or
its WAL/SHM files. The operator supplies both a snapshot path and a
**separate 0700 scratch directory** owned by the calling account.
The backup file must be a regular, non-symlinked owner-only file with
no adjacent WAL/SHM sidecars.

The script checks SQLite integrity and application tables, restores
the snapshot **only** into a throwaway private directory using the
SQLite online backup API, reopens the restored file independently,
and compares schema/page metadata and the untouched source's SHA-256.
The scratch copy is automatically deleted. Only PASS/NO-GO labels
and the snapshot SHA-256 are printed; authentication/device records,
table names and secret data are never printed. It does **not** perform
the eventual production restore, select which owner backup to use,
or modify Caddy.

Read-only operator invocation **after a separate approval to inspect
the snapshot**, while keeping the relay disabled:

```bash
python3 deploy/h15/rehearse-restore.py \
  --snapshot /var/backups/hermes-brc-relay/<reviewed-relay-backup>.sqlite3 \
  --scratch-dir /root/<private-0700-empty-scratch-dir>
```

This is deliberately not scheduled and not called by source-only CI
on owner data. Offline tests use synthetic credentials and verify
uncheckpointed SQLite WAL changes survive an atomic backup + restore,
corrupted snapshots fail closed, no existing files are replaced,
and scratch copies disappear on success or failure. A passing
rehearsal is necessary but **not sufficient** for release:
retention, encrypted off-host backup, owner-approved credential
rotation, rollout rollback, and actual OAuth access tests remain.

## Actual OCI OS inventory and dedicated UID acceptance (next CI stage)

The pinned H-15 candidate workflow now launches the actual patched BRC
relay under UID 979/GID 975 in an isolated, ephemeral container with a
nonpersistent scratch SQLite and no published ports or host volumes.
The test verifies the process and database ownership, empty device list
and service health. It does **not** run as the owner's host user, touch
their persistent SQLite or authorize remote command execution.

The same exact image is interrogated with Debian dpkg-query under
network=none, read-only filesystem and no capabilities. The result is
converted into a deterministic CycloneDX 1.5 OS-package inventory at
os-packages.cdx.json. A fail-closed validator checks package records,
duplicates, image digest, amd64 platform and pinned upstream source.
The OS inventory is published alongside the existing pnpm dependency
CycloneDX BOM and bound to an offline transfer manifest by SHA-256.

New offline bundles use IMAGE_BUNDLE.json schema 2 and require the
matching OS inventory. Legacy schema 1 bundles are still independently
verifiable against their originally observed CI archive/image/source
pins, but **carry no OS inventory**. Neither schema is production
authorization: the OCI receipt explicitly says NOT_DEPLOYABLE.

**The OS package inventory is NOT a CVE scanner or a signed build
attestation.** Full CVE/fix review and verified release provenance are
separate prerequisites. CI green validates integrity and sandbox
behavior only for the disposable runner.

## CVE evidence from the actual BRC image (CI; not approval)

The exact-pinned H-15 workflow runs Trivy v0.70.0 via pinned
`aquasecurity/trivy-action` v0.36.0 commit
`ed142fd0673e97e23eac54620cfb913e5ce36c25`.
The scanner reads the **actually built local OCI image** from the
ephemeral GitHub runner; it includes OS and application-package
vulnerabilities and populates package extraction evidence. The
untrusted vulnerability database is downloaded by the scanner on
the CI runner, without credentials, deployment tokens, image
publication or a separate paid service. The scanner must complete
successfully; vulnerabilities are **not silently ignored** and do
not cause test-result fabrication.

A local, stdlib-only reviewer
`scripts/h15_brc_trivy_review.py` verifies that the Trivy JSON is
well-formed, reports a Debian container image with the **exact Docker
image ID**, and contains actual extracted OS packages. It produces
sanitized `trivy-review.json`: vulnerability counts by severity,
OS/library extraction coverage and the raw Trivy report SHA-256.
The raw report and summary are preserved in the existing H-15 CI
evidence artifact and hashed into `SHA256SUMS`.
No usernames, paths, CVE descriptions or secrets are copied into
GitHub step summaries.

**Interpreting results:**
- `REVIEW_REQUIRED` means at least one finding. Each high/critical
  record requires a version/fix/risk decision before an image can
  be approved. Scans are not automatic patch commands.
- `NO_FINDINGS_OBSERVED` means only no findings were reported by
  this scanner and DB snapshot. It is **not** signed database
  provenance, proof of completeness, or a production release GO.
- `INCONCLUSIVE` (missing report, wrong image ID, malformed or
  absent OS inventory, download failure) blocks CI evidence.
- The relay image remains `CI_IMAGE_VERIFIED_NOT_DEPLOYABLE`
  until a distinct release acceptance process and owner decision.
  Neither scanning nor a merged PR authorizes a permanent container,
  public Caddy reverse proxy, devices or command execution.

## First narrow dependency security patch (CI only)

The real Trivy run on BRC 2.0.2 found 80 HIGH/CRITICAL package
records: 64 Debian and 16 Node. A first minimally scoped mitigation
updates **only** two high-impact JS libraries in a disposable upstream
checkout, preserving the exact pinned git source revision:

- `proxy-addr` 2.0.7 → **2.0.8**, to address the reported critical
  advisory in the HTTP/proxy parsing chain.
- `@modelcontextprotocol/sdk` 1.30.0 → **1.31.0**, addressing the
  reported HIGH MCP library advisory.

`scripts/h15_brc_patch_dependencies.py` requires the original pinned
checkout and the exact known pnpm-workspace.yaml contents. It adds
fixed-version pnpm overrides and refuses unknown source changes.
The isolated CI regenerates the lock with pnpm 11.24.0, then verifies
a frozen re-install and **absence of the original vulnerable versions**
before rebuilding or testing the relay. Updated lock/SBOM, source
patches, full native OAuth MCP tests and actual rebuilt image Trivy
scan remain tied to the CI receipt. The upstream git SHA stays the
same, but the **derived patched build is not identical to upstream**.

No broad npm audit --fix, unconstrained latest/upstream switching,
automatic release approval, installed Docker image on owner VPS,
public ingress or connected owner agents. The new image is still
evaluation-only pending CVE triage, independently verified provenance,
OAuth/device safeguards, and scoped owner authorization. OS package
updates and additional Node packages require a separate reviewed
step after the new scan.

## Follow-on remediation: image-processing and transitive packages

The baseline Trivy report on the exact disposable OCI image
from H-15 CI #39300310663 showed 78 HIGH/CRITICAL records,
including 14 JavaScript/library findings. The next reproducible
**CI-only** patch retains the earlier SDK 1.31.0 and proxy-addr 2.0.8,
and changes only the disposable dependency graph and runtime Docker stage:

- The `undici` 6.28.0 finding is **not in the BRC pnpm lockfile**.
  The Trivy package path is
  `/usr/local/lib/node_modules/npm/node_modules/undici/package.json`.
  The runtime Docker stage now removes unused bundled npm/npx and that
  subtree; the builder keeps npm/pnpm for reproducibility. Real OCI
  scanning and relay startup tests verify this. No deceptive
  `undici` pnpm override is added.
- `brace-expansion` has **three** installed major branches, so the
  overrides are version-selector specific: 1.1.18 → 1.1.21,
  2.1.4 → 2.1.7, 5.0.9 → 5.0.12. A global 5.x override could
  break consumers that require 1.x or 2.x.
- `sharp` 0.34.5 → 0.35.5. This upgrade has **breaking changes**,
  so a successful lock regeneration alone is insufficient: actual
  builds and image/file native sandbox tests must pass.

`scripts/h15_brc_patch_dependencies.py --check-lock` requires
all expected patched versions and rejects the known superseded
versions. Offline patch replay must contain the complete regenerated
pnpm-lock.yaml and pnpm-workspace.yaml. The existing full-H-15
CI verifies OAuth, WSS, per-device native tools, the OCI image,
actual Trivy findings and strict offline import/rollback.

The remediation patch modifies *only* disposable upstream build
inputs and does not touch current owner VPS runtime or images.
No implicit production release promotion, Caddy change, device
pairing, shell access or new paid services. Any unexpected CI
regression requires fixing/reverting the specific package before
merge.

## Debian 12 perl-base security fix (next disposable OCI review)

The successful H-15 OCI Trivy report from CI #39307078505
is 65 HIGH/CRITICAL records: 64 Debian and one Node (braces).
The perl-base package inside the immutable Node 24 Bookworm base
is 5.36.0-7+deb12u3; Debian LTS advisory DLA-4821-1 dated
2026-10-05 confirms **5.36.0-7+deb12u4** fixes multiple
Perl vulnerabilities:

- https://lists.debian.org/debian-lts-announce/2026/10/msg00013.html
- https://packages.debian.org/bookworm/perl-base

The **evaluation-only** Docker runtime stage now installs this
**exact** Debian security package version using Debian signed APT
repositories, before switching to non-root. Failure to obtain that
version aborts the image build. The builder stage remains pinned
and untouched. No wildcard `apt-get upgrade`, no mutation of owner
host packages, and no Docker privilege escalation.

The actual OCI image is queried as UID 65534 with network=none,
read-only root filesystem and dropped Linux capabilities; its
`perl-base` version must match the pinned fix. Existing OAuth,
native agent sandbox, protected path denial, OS SBOM and real Trivy
checks still apply. A successful **CI-only** image build is not a
production image signature, CVE waiver or approval to expose the
relay. The remaining Debian advisories with no fixed package
version remain subject to a separate risk decision.

## Explicit NO-GO until separately approved

- Test-only OCI image must be replaced by a provenance-verified
  production release; no unsigned mutable tag.
- Real VPS kernel/network protection and secret-handling acceptance.
- Full public OAuth 2.1 PKCE login/consent, resource audience, token
  refresh/revocation and negative client/CSRF tests through Caddy.
- Caddy reverse_proxy activation only *after* public OAuth checks.
- Dedicated least-privilege Windows/Linux device identity + approved
  disposable workspaces; native OS negative shell/file tests.
- Actual user-visible ChatGPT custom MCP calls and tool permissions.
- SQLite backup automation and tested restoration.

This PR provides **source-controlled dormant tooling only**.
Its merge, if approved, must never auto-start the relay, expose /mcp,
reuse existing device presence credentials or enable shell access.
