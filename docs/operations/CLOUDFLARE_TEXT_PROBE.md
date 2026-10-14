# Cloudflare one-shot real inference probe

This script is intentionally NOT the autonomous Hermes Agent: it sends exactly
one minimal request directly from the approved Hermes VPS to the fixed
api.cloudflare.com host, without provider fallbacks, retries or model tools.

It reads two vars from root-provisioned /var/lib/hermes-agent/.env without
using the shell, requires mode 0600, and validates a fixed account-scoped URL.
It never outputs account ID, token, response text or raw error body.
Expected output: result, HTTP status, model ID, and numerical token usage only.

Command (after PR/CI and reviewed deployment, with isolated SSH access):

    python3 /opt/hermes-agent-owner/scripts/cloudflare_text_probe.py

The request is NOT an E2E security test of the container's egress policy.
A successful direct host request does NOT authorize permanent agent egress,
systemd enable, real tool execution, Telegram notifications or paid plans.
Cloudflare Workers Free has 10,000 Neurons per day and a free-plan hard stop;
the owner must verify their account remains on Workers Free.

Do not run repeatedly if it fails; inspect the sanitized category and
resolve that cause, without pasting credentials to issues or chat.
