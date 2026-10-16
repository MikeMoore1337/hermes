# H-15 / #208 — OAuth security gates and VPS evidence, 2026-10-16

**Outcome:** offline and sandbox gates substantially advanced; **public GitHub OAuth stays NO-GO** pending Cloudflare edge audit and real owner browser verification. Resident Hermes Agent #33 is separately NO-GO. No owner tokens/client secrets are committed, echoed, sent through CI, or logged.

## Evidence: credentials and segregated identities

- Dedicated GitHub OAuth App created by owner with precise callback `https://hermes.mikemoore.top/auth/github/callback`, wildcard/device flow disabled.
- `/etc/hermes-control-center/oauth`: root-owned mode 0700; `web.env` and `broker.env`: root-owned 0600. The two client IDs and allowed numeric owner ID `42142321` match. The **OAuth Client Secret exists only in broker.env**, not web.env.
- Created OS account `hermes-oauth`: non-root, primary group `hermes-control`, no home or interactive login shell.
- Real `systemd-run` transient units under `hermes-control` and `hermes-oauth` successfully loaded only their corresponding `LoadCredential` sources, under the intended cgroup IP restrictions. No secrets printed.

## Evidence: actually enforced network deny / narrow egress

- Under `IPAddressDeny=any` + `IPAddressAllow=localhost`, transient `hermes-control` service reached localhost:9133 but was blocked from 1.1.1.1 and a GitHub IP.
- Retrieved `https://api.github.com/meta` using ordinary verified TLS (metadata ~165 KiB, not a bearer-token exchange); resolved A records for `github.com` and `api.github.com`, checked each resolved address against the official corresponding `web` and `api` ranges.
- Separate temporary systemd cgroup with only the resulting per-address **/32 pins** (and localhost) completed TLS/hostname validation to `github.com` and `api.github.com`; 1.1.1.1 and 8.8.8.8 remained blocked.
- Repeated this exact test under the actual `hermes-oauth` UID while loading its systemd broker credentials: **PASS**. These are point-in-time addresses; **never hardcode them as permanent stable GitHub IPs**. The validator added in [PR #219](https://github.com/MikeMoore1337/hermes/pull/219) deliberately only generates candidate allow rules and does not modify networking.

## Evidence: Unix RPC and authentication rejection

- Combined isolated release `/opt/hermes-control-center/releases/h15-pwa-broker-offline-20261016` assembled from installed PWA assets + reviewed broker source, **without changing the live release pointer**.
- Fake-provider broker ran under `User=hermes-oauth`, `Group=hermes-control`, `RuntimeDirectory=hermes-oauth`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`. Socket mode 0660, correct group; actual SO_PEERCRED allowed `hermes-control` to resolve a synthetic owner ID and rejected an otherwise equivalent root-UID request. Service stopped immediately after testing.
- A separate stage web service on loopback port 9134 with `LoadCredential=web.env` and `IPAddressDeny=any` returned unauthenticated session status, API 401, 303 GitHub authorize URL with S256 PKCE/no extra scopes/no client secret, refused wrong OAuth state 403 and logout with wrong Origin 403. This was tested via a **non-redirecting HTTP client**: no real provider code exchange. Stage service stopped.

## Security incident: Caddy callback query logging

- Initial synthetic GET `/auth/github/callback?code=<synthetic>&state=<synthetic>` behind Basic Auth produced 401 **and leaked those synthetic query parameters** into `http.log.access.request.uri` in `journalctl -u caddy`.
- [PR #222](https://github.com/MikeMoore1337/hermes/pull/222) implemented a narrow `log_skip /auth/github/callback*` for **both** Hermes HTTPS:8444 and HTTP redirect blocks. Source CI and actual candidate `caddy validate` PASS. Applied to production after a root-only backup outside the Caddy glob import:
  `/etc/caddy/rollback/hermes.mikemoore.top.20261016.before-oauth-log-skip`.
- After `systemctl reload caddy`, a fresh synthetic HTTPS 401 / HTTP 308 callback probe was **absent from Caddy journal**, where it was previously observable. Public Hermes Basic Auth 401 unauthenticated and 200 authenticated; read-only API similarly 401/200; Second Brain available; Caddy, web service, snapshot timer active.
- **Important limitation:** a negative search through `journalctl -u caddy` does not prove upstream Cloudflare HTTP request logs or analytics sanitize callback query parameters. Cloudflare edge logging is still a separate gate.

## Active installation (not switched to OAuth)

- Public `https://hermes.mikemoore.top` serves the approved PWA release `/opt/hermes-control-center/releases/h15-pwa-0f7f1ded`, with **Caddy Basic Auth** and application `proxy` mode.
- Permanent broker service **has not been enabled**; isolated staging tests were stopped. Cgroup egress allow entries have **not** been installed as broad or standing permissions.
- Source code is opt-in, not authorization: none of the tests above represents actual owner-browser GitHub OAuth sign-in.

## Remaining explicit owner security gates

1. Inspect Cloudflare zone and request logging rules (e.g. Logpush/analytics/security events) to establish that callback `code` and `state` are never stored verbatim. If this cannot be guaranteed, block public login until a suitable sanitized architecture/edge policy is adopted.
2. Review/approve a reversible, non-broad systemd per-IP egress allowlist for the broker with DNS drift handling and repeat denied-host TLS checks. DNS matched against `/meta` by itself does not prevent future address movement.
3. Build a unified provenance-verified release containing the broker and PWA; install an owner-reviewable, opt-in service unit. Keep web `IPAddressDeny=any` and Caddy Basic Auth.
4. Stage a **real owner-browser** GitHub OAuth login with the actual OAuth App (not synthetic), verify denial for a non-owner GitHub identity, signature/session logout/expiry, callback logging, XSS/CSRF defenses and rollback from a failed provider call.
5. Only after the owner explicitly approves results and rollback, cut over from Basic Auth to GitHub OAuth; if any check fails, roll back as one unit. No effect on YFC/Second Brain/Xray or #33.

This is an auditable snapshot, **not** a declaration of finished #208 or owner GO.
