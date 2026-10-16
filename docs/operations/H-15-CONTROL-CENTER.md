# Hermes Control Center - русскоязычный read-only MVP

## Scope

Issue #163, parent #67. Current milestone is a local-only independent operator view and an optional plugin for official Hermes Web Dashboard. The resident agent remains P0 **NO-GO** per #33. Never enable the native Hermes runtime merely to use this dashboard.

- `control_center/`: Python standard-library server fixed to `127.0.0.1:9133`, no AI dependencies, no write endpoints.
- `control_center.snapshot`: root-owned one-shot collector invoking only a hardcoded `systemctl show` allowlist (seven units, 3s timeout). Returns static status metadata, not private logs, SQLite, secrets, personal data or research results.
- `/var/lib/hermes-control-center/overview.json`: atomic output, `0640 root:hermes-control`; directory `0750 root:hermes-control`.
- `plugins/hermes-control-center/dashboard/`: native Web Dashboard tab and fixed-path, read-only FastAPI backend for use only after upstream runtime admission.
- `deploy/hermes-control-center*.service/.timer`: systemd sandboxed, non-root web process, 100MB cap, 25% CPU, no outgoing external network. Existing Hermes/YFC timers unchanged.

Statuses reflect timers and service units, *not* application-level results, delivery ACKs, research verification or CI logs. Unknown/missing units are not shown as healthy. Unexpected resident agent activity must be flagged. Snapshot older than 3 minutes raises a warning.

## Validation

```sh
python3 -m unittest tests.test_control_center -v
node --check control_center/web/app.js
node --check plugins/hermes-control-center/dashboard/dist/index.js
python3 scripts/validate_repo.py
```

## Safe local-only deployment

From a verified exact release archive unpacked on the VPS:

```sh
sh deploy/install-control-center.sh /path/to/exact-release
systemctl is-active hermes-control-center.service
systemctl is-active hermes-control-center-snapshot.timer
curl -fsS http://127.0.0.1:9133/healthz
curl -fsS http://127.0.0.1:9133/api/overview
ss -ltn | grep 9133
```

The installer does not alter Caddy or DNS. The backend requires an authenticated TLS reverse proxy for public use. Do NOT expose port 9133.

## HTTPS and authentication: hermes.mikemoore.top

### Verified VPS facts (2026-10-16)

- Caddy v2.11.4 serves Second Brain on the existing HTTPS origin listener :8444; VPS :443 is a separate xray service. Never replace or take :443 from xray, or overwrite the existing brain Caddy snippet.
- Added separate `/etc/caddy/sites.d/hermes.mikemoore.top.caddy` as an HTTPS virtual host on :8444; it proxies only to 127.0.0.1:9133. Caddy `basic_auth` runs before the proxy; Authorization is stripped before upstream. Another :80 site redirects the hostname to the portless HTTPS URL.
- Login: `hermes`. A unique random password is stored **only** on the VPS at `/etc/caddy/auth/hermes-control-center.password`, `0600 root:root`. To retrieve it on the authorized server, use `sudo cat /etc/caddy/auth/hermes-control-center.password`. Never paste it into GitHub/CI or command-line arguments.
- Generated the bcrypt hash by piping password to stdin of `caddy hash-password --algorithm bcrypt --bcrypt-cost 12` via a subprocess, rather than passing it as an argv argument. Caddy 2.11.4 does **not** offer the documented `--password-file` flag.
- Local origin-only HTTPS verified: unauthenticated `/` and `/api/overview` return 401; authenticated requests return 200; other routes 404. `brain.mikemoore.top` still returns HTTP 303 through Cloudflare. The regular read-only listener is strictly `127.0.0.1:9133`; all seven source units are returned, with resident Agent `blocked`.
- Current Caddy `tls internal` is **staging only**. This local CA is not a Cloudflare-trusted Origin CA, so public `Full (strict)` cannot be declared operational. Never weaken the SSL/TLS zone mode to `Full` or `Flexible` merely to bypass this problem.
- An ECDSA P-256 private key was generated **on the VPS**, `0640 root:caddy`, at `/etc/caddy/certs/hermes.mikemoore.top.key`. The public CSR is `/etc/caddy/certs/hermes.mikemoore.top.csr`, includes only SAN `hermes.mikemoore.top`.

### Required Cloudflare changes

1. `DNS → Records`: DNS A record `hermes` must point to the actual **origin** IPv4 `111.88.215.204`, proxy status **Proxied** (orange cloud), TTL Auto. Remove an incorrect target using a Cloudflare edge/restricted address and any conflicting AAAA/CNAME for that hostname. At the time of the test, edge request responded with Cloudflare **1034 Edge IP Restricted**, not the origin site.
2. `Rules → Origin Rules`: add or verify a hostname-specific rule `http.host eq "hermes.mikemoore.top"` with **Destination port = 8444**. This is required because the normal public URL uses 443 at the Cloudflare edge but Caddy on this VPS listens on 8444. Do not affect the existing brain rule.
3. `SSL/TLS → Origin Server → Create Certificate → Use my private key and CSR`: paste the public CSR from the VPS file and issue a signed **Origin CA** certificate covering `hermes.mikemoore.top`. User supplies only the **signed certificate** to VPS as `/etc/caddy/certs/hermes.mikemoore.top.pem`, not another private key. Never post the private key.
4. Check certificate SAN and key match before activation. Replace only the new Hermes site `tls internal` with `tls /etc/caddy/certs/hermes.mikemoore.top.pem /etc/caddy/certs/hermes.mikemoore.top.key`. Validate Caddy and reload, preserving the existing brain config. Keep Cloudflare `Full (strict)`.
5. Verify public HTTPS returns **401 without authentication and 200 after authentication**. Confirm `brain.mikemoore.top` still operates, and no external inbound access to localhost port 9133 is possible. Until then, status is `PUBLIC_NO_GO`.

Docs: https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1034/ ,
https://developers.cloudflare.com/rules/origin-rules/ ,
https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/

Only after resident Agent P0 #33 passes, separately install native Dashboard plugin into an approved isolated Hermes profile. The official Dashboard includes high-privilege APIs and requires independent authorization and runtime security review. No automatic resident restart is part of this deployment.

## Rollback

Stop/disable only `hermes-control-center.service` and `hermes-control-center-snapshot.timer`. Remove only this optional Caddy route if present; validate and reload Caddy. Do not touch existing YFC news or Hermes Ops/QA/Research units.
