# Hermes H-15: hardened GitHub identity broker (security stage only)

Issue: [#208](https://github.com/MikeMoore1337/hermes/issues/208). Parent: #180.
**Status: NOT DEPLOYED / NO-GO to enable.** Owner's OAuth App exists, but the server must not handle its secret directly.

## Isolation architecture

```text
Cloudflare HTTPS --> Caddy Basic Auth (unchanged)
                      |
              read-only Hermes web :9133
              IPAddressDeny=any
              IPAddressAllow=localhost
                      |
         /run/hermes-oauth/broker.sock
         AF_UNIX, 0660 hermes-oauth:hermes-control
         SO_PEERCRED checks hermes-control UID
                      |
               hermes-oauth broker
               own minimal systemd service
               exact actions: identify(code, PKCE verifier)
               no arbitrary URL, no user-supplied HTTP method or scopes
                      |
       github.com/login/oauth/access_token POST
       api.github.com/user GET
       TLS hostname and certificate verification
       IPAddressDeny=any; only reviewed /32 provider endpoints
```

The broker validates the GitHub numerical owner ID (`42142321`) and returns only `{"ok":true,"id":42142321}`. Token, client secret and other GitHub profile attributes never cross back to the read-only web server. It drops access tokens after `/user`. Both services retain separate `systemd LoadCredential` files. The main web process has **no client secret** and cannot use `https` egress under its unchanged systemd IP restrictions.

The broker's standard unit template is [deploy/hermes-oauth-broker.service](../../deploy/hermes-oauth-broker.service). It **deliberately denies all remote IPs**, including GitHub. Do not start it for production until specific, verified GitHub addresses are approved and staged.

## Secure local credential setup (once approved)

A fully interactive root-only helper is [scripts/provision_h15_oauth.py](../../scripts/provision_h15_oauth.py). It asks on the VPS terminal for Client ID, numeric owner ID and hidden Client Secret. It generates the independent session signing secret using `secrets.token_urlsafe`; it writes two files (root-only 0600) under `/etc/hermes-control-center/oauth` with the directory mode 0700. It refuses to overwrite existing credentials. **Never paste the secret into chat, terminal CLI arguments, shell history, GitHub Issues or CI.**

The owner must verify the separate GitHub OAuth App before using the helper. Its exact callback is `https://hermes.mikemoore.top/auth/github/callback`, wildcard matching and Device Flow OFF, scopes none.

Web credentials (`web.env`): authentication mode, exact origin, public client ID, numeric owner ID, independent session secret, Unix broker socket path. **No Client Secret.**

Broker credentials (`broker.env`): Client ID, Client Secret, numeric owner ID and Unix broker socket path. Neither `LoadCredential` source file is committed to Git or baked into an image.

Suggested activation plan, **not automated by this PR**:
1. Owner manually approves GitHub provider IP allowlist from DNS **cross-checked against officially published GitHub IP ranges** (GitHub metadata API), based on current endpoint DNS. Generate only /32 IPv4 and /128 IPv6 host exceptions, never `0.0.0.0/0`, `::/0`, broad ranges or generic Squid/Danted proxy access. If DNS changes outside approved IPs, fail closed.
2. Test the broker's systemd cgroup IP policy with `systemd-run` negative probes: allowed endpoints only, denied external hosts, public SSH/caddy/snapshot services unaffected. Validate systemd eBPF IP restrictions are actually enforced on this host. Do not rely only on Python host strings or DNS.
3. Stage broker with an **isolated** reversible release and no secrets in logs; validate exact IPC caller credentials, fake provider responses and real handshake only after owner approval.
4. Ensure Caddy and Cloudflare request access logs omit all callback query parameters (including `code` and `state`) before public browser login.
5. Enable web `LoadCredential=web.env:/etc/hermes-control-center/oauth/web.env` **only in staging**, verify denied account, callback replay, expiry, CSRF, logout and snapshots. Keep existing Basic Auth until successful owner-browser OAuth tests.
6. Only after owner GO, remove Hermes-specific Basic Auth via a separate Caddy change with tested rollback. No changes to Second Brain, xray :443, other Hermes services or #33 resident agent.

## Negative test matrix

- Unknown broker operations, arbitrary URLs, headers or methods are denied; requests larger than 2048 bytes denied.
- Unix peer identity mismatch denied, session cookies replay/tamper/expiry denied.
- Provider failure, token missing or returned owner ID mismatch denied, bounded attempts.
- Invalid or duplicate credential env keys, weak/missing credentials or incorrect socket path denied.
- Owner's actual GitHub OAuth App credentials are **never used by offline tests**.

## Known gates

- Local Windows testing cannot exercise Linux `SO_PEERCRED`; Linux CI and on-VPS staging must test it independently.
- The broker unit template does not list live IP exceptions; that omission is intentional. Starting it now would block provider exchange.
- The app's existing login preview remains under Basic Auth, and the security status remains **OAuth production NO-GO**.
