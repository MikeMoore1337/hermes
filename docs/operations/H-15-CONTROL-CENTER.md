# Hermes Control Center - актуальная эксплуатация (17.10.2026)

Production: https://hermes.mikemoore.top. Issue #163, parent #67. Принятый дизайн Operations Atlas (C+B, шрифты C+A) на React/Vite, локальные HD-ассеты, адаптивный русский интерфейс, PWA. Вход работает через owner-only GitHub OAuth (#180); Basic Auth и постоянный OAuth broker - только исторические этапы.

## Архитектура

- Backend: control_center/server.py, loopback 127.0.0.1:9133. Внешний TLS: Cloudflare -> отдельный виртуальный хост Caddy -> loopback. Не изменять порт 443/xray, общие настройки Cloudflare и Second Brain.
- Read-only защищённые API: /api/overview, /api/providers/codex. Без owner-сессии HTTP 401. Авторизация: /api/auth/session, /auth/github/start, /auth/github/callback, POST /auth/logout. Cookie защищённые; ответы API не кэшируются.
- Снимок: control_center/snapshot.py, systemd-allowlist, research_scout.report_view. Active timer - факт расписания, не успешного business job. Просроченный снимок (>3 минут) отвергается.
- AI #33: отдельно разрешён ограниченный event-driven H-01 Ops AI (hermes-h01-ops-agent.timer, oneshot service). Полный hermes-agent-sandbox.service не допущен. Окончание 24-часовой проверки #33 ожидается отдельно. Не заявлять успешный полезный цикл без доказательств.
- Codex #255: независимый VPS Codex CLI с ChatGPT OAuth, hermes-codex-usage.timer, очищенный снимок квот и виджет. Квоты Codex не смешивать с Workers AI Free и не восстанавливать программно.
- Research Scout #4: только существующий сохранённый отчёт; HOLD/MANUAL_REVIEW и исправления статей не являются подтверждением эффективности.
- PWA: manifest.webmanifest, sw.js, PNG 192/512, maskable, Apple Touch Icon, offline.html. Никогда не помещать защищённые API или OAuth cookies в офлайн-кэш.
- Cloudflare Full (strict): успешный публичный HTTPS НЕ доказывает режим. Подтверждение правил возможно только через авторизованную конфигурацию Cloudflare.

## Безопасная read-only проверка

    readlink -f /opt/hermes-control-center/current
    cat /var/lib/hermes-main-deploy/last-success.sha
    systemctl is-active hermes-control-center.service hermes-control-center-snapshot.timer hermes-codex-usage.timer hermes-h01-ops-agent.timer
    curl -fsS http://127.0.0.1:9133/healthz
    curl -I https://hermes.mikemoore.top/
    curl -I https://brain.mikemoore.top/

Изменения оформляются в PR с Python/Node/Chromium Playwright тестами и проверкой CI, затем применяются ограниченным exact-SHA CD с rollback. Не менять production вручную ради UI-тестирования. Авторизацию владельца уже приняли; не требовать повторного логина без изменения OAuth.

## Исторический протокол (16.10.2026 и ранее, НЕ текущий runbook)

Сохранённые ниже сведения о Basic Auth, Cloudflare 1034, прежнем отключённом GitHub OAuth и временном NO-GO относятся к прошлым релизам. Не использовать их как инструкции по эксплуатации актуального production.

---

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


## Verified release update - 2026-10-16

The previous `tls internal` staging description above is superseded by this release update:

- Owner supplied a Cloudflare Origin CA certificate matching the existing VPS-generated CSR and private key. The certificate is valid until 2041-10-12, has the exact SAN `hermes.mikemoore.top`, and is now live in Caddy for the Hermes-only origin site.
- Caddy configuration validation and reload passed. The live origin presents the installed Origin CA certificate, with matching SHA-256 fingerprint. Service status and the local-only backend remain healthy.
- Cloudflare DNS and origin port routing now work: public HTTPS returns 401 for unauthenticated requests, not the previous Cloudflare 1034. The public TLS handshake passed. Existing Second Brain continues returning HTTP 303.
- Final gates remain: verify authenticated 200 via the public URL after certificate activation; confirm a Cloudflare hostname-specific Configuration Rule enforces SSL `Full (strict)` for Hermes, or an equivalent verified zone-wide setting. An HTTP 401 by itself cannot establish the Cloudflare SSL mode.
- Until both final gates are verified, retain Issue #163 as open. Do not activate the resident agent (#33 still NO-GO).


## Approved React/Vite release - 2026-10-16

**Delivery: PASS for visual-only read-only UI. GitHub OAuth remains NOT ENABLED.**

- Owner-approved design: **C+B Atlas structure/navigation, C+A sans-serif typography** (including branded login preview). Competing C+A console toggle removed.
- Source: [merged PR #200](https://github.com/MikeMoore1337/hermes/pull/200), merge commit `1f516566f8fb9c66ade391c863dbee373fabfc44`, verified PR HEAD `0bf0453674f66f755ce171262d5421322f1ff254`. UI [CI #38929284336](https://github.com/MikeMoore1337/hermes/actions/runs/38929284336), baseline [CI #38929284303](https://github.com/MikeMoore1337/hermes/actions/runs/38929284303) both success. Local verification: Node 3/3, Python HTTP 13/13, Chromium 7/7, no production npm audit findings.
- Build: React/Vite **compiled on Windows before delivery**, only 7 static/backend files deployed via a fixed-path allowlisted ZIP. No Node or build tooling installed on VPS. Historical snapshots/research/alert data and service definitions not replaced.
- SHA-256 of transferred ZIP: `bf6bb096e58f5d6b7a3b6eb7a75b5b8b29945e1cc18df47f0873190a16f306e4`. ZIP checked against exact seven-file allowlist, symlink and path traversal rejected, each file hashed in `deploy-receipt.json`. Release directory: `/opt/hermes-control-center/releases/h15-ui-1f516566`; symlink `/opt/hermes-control-center/current` switched atomically.
- Previous release kept as `/opt/hermes-control-center/releases/20261016T090626Z`; no Caddy config change, no SSL certificate or Basic Auth credential change, no changes to Second Brain or other Hermes timers.
- Staged preview tested as `hermes-control` on loopback port 9134: HTML, CSS/JS, brand WebP, both PNG icons, read-only JSON, invalid Host, unknown routes, HEAD and unsupported POST. **Note:** the Python stdlib default unsupported POST returns HTTP 501 (not a write capability); this exceptional stdlib-generated response lacks the custom CSP header, unlike supported routes. Consider hardening it separately if warranted.
- Production smoke after atomic switch: unauthenticated `GET /` and `GET /api/overview` over public HTTPS returned 401; Basic-Auth authenticated `GET /` and `GET /api/overview` returned 200; JSON mode `read_only`, seven systemd entries, resident Agent `blocked`. `127.0.0.1:9133` loopback-only. `caddy`, `hermes-control-center.service`, snapshot and Ops/QA/Research/News timers active; `brain.mikemoore.top` HTTP 303 with TLS verify 0. No service journal errors observed in first postdeploy checks.
- Design test evidence committed in `docs/ux/evidence/h15-react-vite/`. Screenshots are **fixture-based**, not actual production telemetry. Current login remains hidden behind Basic Auth and `/?preview=login` is visual preview **with disabled OAuth button**. GitHub OAuth task [#180](https://github.com/MikeMoore1337/hermes/issues/180) requires a separate OAuth App, owner-only identity verification, tests and independent security acceptance before Caddy authentication change.
- Runtime P0 [#33](https://github.com/MikeMoore1337/hermes/issues/33) remains NO-GO, and public SSL Full (strict) rule confirmation remains a separate gate; TLS 0 and 200 alone do not prove its Cloudflare configuration.

### Targeted rollback to previous visual-only release

On the authorized VPS, after confirming the former release exists, run:

```sh
test -d /opt/hermes-control-center/releases/20261016T090626Z
ln -s /opt/hermes-control-center/releases/20261016T090626Z /opt/hermes-control-center/current.rollback
mv -Tf /opt/hermes-control-center/current.rollback /opt/hermes-control-center/current
systemctl restart hermes-control-center.service
curl -fsS -H 'Host: hermes.mikemoore.top' http://127.0.0.1:9133/healthz
```

These steps affect only the read-only web service. Do not change Caddy or disable Ops Watch, Research, QA, news, incident delivery or the network guard for a UI rollback.


## Approved UI rollout: 2026-10-16 (supersedes earlier staging notes)

**OWNER ACCEPTANCE:** All composition, navigation, colors and layout from **C+B (Operations Atlas)**, with **C+A sans-serif typography** for headings, metrics, navigation and branded login. No competing mode selector. Approved winged-H raster branding and self-hosted favicon included.

- [PR #200](https://github.com/MikeMoore1337/hermes/pull/200) merged as `1f516566f8fb9c66ade391c863dbee373fabfc44`. Final [UI CI #38929284336](https://github.com/MikeMoore1337/hermes/actions/runs/38929284336) and [repo CI #38929284303](https://github.com/MikeMoore1337/hermes/actions/runs/38929284303) passed.
- On VPS, immutable-ish release directory `/opt/hermes-control-center/releases/h15-ui-1f516566` is selected by `/opt/hermes-control-center/current`; previous known-good release `/opt/hermes-control-center/releases/20261016T090626Z` retained for rollback. Bundle archive SHA-256: `bf6bb096e58f5d6b7a3b6eb7a75b5b8b29945e1cc18df47f0873190a16f306e4`; on-server `deploy-receipt.json` records seven file hashes.
- Operator service and snapshot timer remain active, as does Caddy. HTTPS public smoke check **401 without Basic Auth**, **200 with authorized Basic Auth** for both HTML and `GET /api/overview`; Second Brain still returns HTTPS **303**. Loopback app remains bound to `127.0.0.1:9133`. All seven allowed components visible; resident agent state remains `blocked`.
- Staged isolated read-only release on alternate local port passed exact asset allowlist, CSP, Host, stale API, unknown-path, HEAD/POST and no-write checks before switching; post-deploy E2E and rollback gates passed.
- Runtime serves static built React 19/Vite 7 assets; **Node.js and npm are not installed or executed as web server on VPS**.
- `/?preview=login` is a **visual-only** login preview under existing Basic Auth: its GitHub login control is deliberately disabled. GitHub OAuth is **not active**; separate security issue [#180](https://github.com/MikeMoore1337/hermes/issues/180) remains open. Do not remove Basic Auth until owner-only OAuth succeeds with a separate OAuth app and denial/rollback tests.
- AI resident runtime security gate [#33](https://github.com/MikeMoore1337/hermes/issues/33) remains **NO-GO**. Neither approval of the design nor deployment of the static UI authorizes privileged agent start.

### Rollback: UI release only

If the new UI or its local API regresses, restore the previous release symlink atomically, restart **only** `hermes-control-center.service`, then check localhost API, public authentication, and `brain.mikemoore.top`. Never restart the autonomous Agent, alter :443/xray, modify Cloudflare rules or remove snapshot timer during an ordinary UI rollback. See `deploy/install-control-center.sh` for sandboxing assumptions. Keep the bundled receipt for audit.

### External security confirmation

Cloudflare Origin CA certificate was installed successfully and the public TLS handshake verifies at the Cloudflare edge. **HTTP 401 alone does not prove Cloudflare's configured SSL mode**: explicit verification of a hostname-specific `Full (strict)` rule or equivalent zone-level mode remains a separate owner-facing security gate if not previously verified.
