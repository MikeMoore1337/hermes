# Hermes GitHub OAuth - direct owner login

Second Brain-style deployment: Control Center exchanges OAuth code with GitHub
directly over HTTPS. No separate active Unix OAuth broker in production.
Unlike Second Brain, Hermes retains PKCE S256 and strict provider JSON parsing.

## Credential migration

The two original root-only credential files remain independent and are loaded
into **the same web service** by systemd `LoadCredential`:
`/etc/hermes-control-center/oauth/web.env` and `broker.env`.
No secret rotation, copying into repo, CLI arguments, environment variable or
logging is necessary. Startup fails closed if either file is absent or if
client ID / numeric owner ID do not match.

On the authorized VPS, **before merging direct-OAuth code**:

```bash
cd <reviewed-source-checkout>
sudo python3 -m scripts.h15_migrate_direct_oauth --stage
systemctl show hermes-control-center.service -p IPAddressDeny -p IPAddressAllow
```

Stage removes web unit dependency on the broker, adds second LoadCredential and
removes the earlier systemd outbound IP deny/allow lists. The web service stays
bound to 127.0.0.1; Caddy/Cloudflare, TLS, Origin, cookies, ownership and
existing hostname allowlists are unchanged. Host network access for the web
service becomes broader; this is the accepted security tradeoff for reliability.
The OAuth HTTP client still exclusively calls fixed TLS provider endpoints,
rejects redirects and does not honor environment proxy variables.

Deploy the reviewed exact `main` SHA only after required tests pass, check
`/healthz`, browser login as the pinned numeric owner ID, callback denial for
another identity and no callback code/state in Caddy/systemd logs.
Only after owner acceptance:

```bash
sudo python3 -m scripts.h15_migrate_direct_oauth --finalize
```

Finalize disables and stops the legacy broker. Do not delete existing root-only
credentials or rollback backup during the first release. If new release fails,
restore the prior `/opt/hermes-control-center/current` exact release, copy the
root-only `web-service-dropin.before-direct-auth` back to the drop-in path,
`systemctl daemon-reload`, start the broker, restart the old web service, and
retest login. Never use real OAuth codes in smoke tests or logs.

## Security and diagnosability

- GitHub owner ID pinned, state+cookie anti-CSRF and PKCE S256.
- Scope: `read:user` only; no `repo` or org access; token never persisted.
- HMAC-signed, revocable HTTP-only Secure SameSite=Lax session cookie.
- HTTP status-only `github_direct_rejection` log categories omit tokens/codes.
- Keep the default proxy mode fail-closed: direct credentials required only when
  explicit production GitHub mode is enabled.
