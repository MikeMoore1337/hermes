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
