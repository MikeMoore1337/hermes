# Codex Usage Monitor - Hermes Issue #255

The module adds a read-only Codex quota collector, an authenticated GET
/api/providers/codex and a responsive widget in the existing Atlas Control Center.
It does not authorize a VPS ChatGPT account, install the collector or activate an AI agent.
All screenshots use synthetic quota data until a verified live connection is enabled.

## Source and boundaries

The collector starts official Codex CLI app-server over local JSONL stdio and calls only
initialize, initialized, account/rateLimits/read. No inference, account rotation or
reset-credit consumption is part of this module.
ChatGPT account login is required; an OpenAI API key does not represent subscription quotas.
Codex subscription quota differs from Cloudflare Workers Free and paid API billing.

An atomic sanitized snapshot contains only window duration, remaining/used percentages,
reset timestamps and status. No emails, account identifiers, raw response bodies or tokens.
The GET endpoint uses the existing Control Center authentication and has no write operation.
It returns not_configured when there is no source; stale after more than 10 minutes.

## VPS activation - not performed

The deploy/hermes-codex-usage.service and .timer are source-controlled templates only.
Installing Codex CLI, opening new outbound traffic and authorizing ChatGPT on VPS require
a separate explicit owner approval.

1. Pin an official Codex CLI release; verify actual app-server support on the VPS.
2. Create a hermes-codex system user with primary group hermes-control.
3. Provision /var/lib/hermes-codex-usage (owner hermes-codex, group hermes-control,
   mode 0750). Create auth/ under it with owner hermes-codex and mode 0700.
   The Control Center web service must not be able to read the auth directory.
4. Using exactly that OS identity and CODEX_HOME=/var/lib/hermes-codex-usage/auth,
   complete the official codex login --device-auth owner flow.
5. Test the actual subscription quota, re-authorization, 401/429/network failures
   and expiry. Keep original raw tokens off the web, logs, GitHub, YFC and Second Brain.
6. After approval, install the two new units and enable the timer. It runs a short
   one-shot probe roughly every five minutes and writes usage.json mode 0640.
7. Roll back with systemctl disable --now hermes-codex-usage.timer; do not change
   the existing restricted network rules of hermes-control-center.service.

When monitoring fails, no prior quota is interpreted as usable. Do not infer that
quota has been restored merely because the reset clock time passed.

## Tests and review

Run python3 -m unittest tests.test_codex_usage tests.test_control_center -v.
In control_center/frontend run npm ci --ignore-scripts, npm test, npm run build,
and npm run test:e2e. Screenshot evidence in docs/ux/evidence/h15-codex-usage
is fixture-based and awaits review before production UI changes.

Future Hermes scheduler integration is a separate phase. No autonomous queues,
provider switching, payments or reset-credit consumption are activated here.
