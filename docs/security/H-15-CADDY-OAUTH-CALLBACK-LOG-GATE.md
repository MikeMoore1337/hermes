# H-15 OAuth callback: Caddy access-log redaction gate

**Security finding, 2026-10-16:** Before any OAuth activation, a synthetic request to
`https://hermes.mikemoore.top:8444/auth/github/callback?code=H15_SYNTHETIC&state=H15_SYNTHETIC`
returned 401 (Basic Auth), **but** Caddy `http.log.access` wrote the full `request.uri`
including the artificial `code` and `state`. This is a concrete security regression
even though real OAuth is currently disabled. Do not claim OAuth production GO.

Official Caddy reference: https://caddyserver.com/docs/caddyfile/directives/log_skip

## Minimal remediation

In **both** Hermes HTTPS :8444 and HTTP redirect site blocks, add:

```caddyfile
log_skip /auth/github/callback*
```

Match **only** the callback path. This intentionally omits logs for this one sensitive route,
including invalid/unauthenticated callback attempts; system-level errors may still log some
metadata. Do not remove the `basic_auth` stanza, add provider secrets to Caddy, or touch
`brain.mikemoore.top`, SSH, Xray, or the resident Agent.

Generate a candidate with
`python3 scripts/h15_caddy_callback_log_guard.py --source /etc/caddy/sites.d/hermes.mikemoore.top.caddy --candidate /tmp/h15-hermes-caddy-callback.candidate`.
The tool is read-only with respect to production, and refuses ambiguous layouts or preexisting
log policies. The candidate contains the current Basic Auth hash, **so never commit or print it**.

### Atomic rollout / fallback (operations)

1. Securely back up the current site **outside** `/etc/caddy/sites.d/*.caddy` so duplicate
   site blocks are not loaded. Use root-only storage and `0600` permissions.
2. After reviewing the patch (only two `log_skip` lines), replace the site atomically.
3. Run `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`; if invalid,
   immediately restore the backup without reloading.
4. Run `systemctl reload caddy` (not restart) only after validation; on any failure restore
   backup, validate and reload. Do not change Caddy's Origin CA, Full (strict), Origin Rule,
   or Basic Auth.
5. Synthetic negative test on both HTTPS :8444 and local HTTP 80 with a fresh artificial
   random marker in `code` and `state`. Verify 401/308 and **absence** of the marker in
   `journalctl -u caddy` and any active access log targets. Don't send real OAuth codes.
6. Check `https://hermes.mikemoore.top` still returns 401 without credentials and 200
   with existing authorized Basic Auth; `https://brain.mikemoore.top` remains available;
   `hermes-control-center.service`, snapshot timer and Caddy remain active.

Do not claim Cloudflare edge request logging redaction without independent Cloudflare
configuration/audit evidence; this is a **separate** owner gate. Use the OAuth App's exact
HTTPS callback, wildcard matching OFF. Resident Agent #33 NO-GO remains unchanged.

## Audit receipts

Record Caddy validate status, changed directive count, synthetic marker excluded from logs,
source file hash, rollback backup path (without credentials) and health test outcomes in #208.
No secret fields or actual callback URL queries should be copied into issues.
