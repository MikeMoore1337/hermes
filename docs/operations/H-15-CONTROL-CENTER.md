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

1. Owner creates `hermes` DNS in Cloudflare and verifies resolution plus Cloudflare origin routing/port settings.
2. Generate a unique secret outside the repository (mode 0600 root); hash with `caddy hash-password --password-file`. No secrets or password hashes in PR/CI.
3. Add a dedicated, checked Caddy site under its existing import (example; never commit a real hash):

```caddyfile
hermes.mikemoore.top {
    basic_auth {
        hermes $2a$REPLACE_WITH_REAL_BCRYPT_HASH
    }
    reverse_proxy 127.0.0.1:9133
}
```

4. Before declaring public deployment: `caddy validate`, healthy TLS, unauthenticated **401**, authenticated **200**, no direct remote access to `:9133`, test `brain.mikemoore.top` unchanged.
5. Only after #33 runtime GO: separately install native dashboard plugin into the approved Hermes profile, configure its built-in Russian locale `ru` and verify auth for all privileged APIs. No resident restart or token config is implied here.

## Rollback

Stop/disable only `hermes-control-center.service` and `hermes-control-center-snapshot.timer`. Remove only this optional Caddy route if present; validate and reload Caddy. Do not touch existing YFC news or Hermes Ops/QA/Research units.
