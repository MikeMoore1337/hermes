# H-01 #33 - limited resident Ops AI acceptance (2026-10-17)

## Scope, proof and decisions

The owner explicitly authorized completing #33, including temporary extra
*installation* load, provided operating thresholds are restored. The existing
H-01 host was observed to have 3.9 GiB RAM, 2 GiB swap and approximately
11 GiB disk free before staging.

The official, immutable v0.22.2 AMD64 image
`sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`
was **actually downloaded** on the current VPS. A maintenance-only process
monitor allowed peak load1 up to 4.50 while retaining memory, swap, disk
and Control Center/news guard checks. The pull exited 0 after ~156s.
No persistent host resource thresholds were changed.

A patched derivative was actually built **on the same VPS** from the checked
pinned source and native-tool patch; `git apply --check` and application
succeeded. Exact Docker ID:
`sha256:1ae52b578f5944510beabfa71aaf1d469f24ad69258a38840cce02d57e89ea79`.
This is a local derivative, not an upstream signed image.

On the VPS the real original-versus-patched offline native dispatch inspector
returned `PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS` with 1) original gap
reproduced, 2) checked denied paths blocked and 3) synthetic allowed paths
working. The command exits 2 intentionally as it refuses to authorize
unrestricted resident tools. It tests synthetic calls, not live MCP/network
permission proof.

A real **v0.22.2 Hermes CLI** text response was then obtained from
Cloudflare Workers AI with the existing approved Free provider
`@cf/openai/gpt-oss-20b`: one `chat` turn, `-t bot_room` (no native
tools), max 1 turn, bounded 195s, nonroot Docker, no capabilities,
read-only root FS, internal bridge and allowlisted CONNECT proxy.
Observed: exit 0, response `OK`, duration 140.97s, no 400/401/403/429,
Control Center and Ops Watch timer still active, load1=1.03 after.
Account Free tier is owner-confirmed by ADR-0002, but provider-side
**cost = NOT_MEASURED**, and the response does not prove every future
request will succeed.

The smoke temporarily started the pre-existing dedicated proxy; a
concurrent exact-SHA CD for PR #263 intentionally failed because its older
deployment script required the proxy to be inactive. The proxy was
stopped, the failed deployment job rerun, and the second attempt
completed successfully at SHA `380e2130b97cf8509c5dd6cd3dd1764f9a241af9`.
No new Hermes daemon was started during that smoke.

## Narrow autonomous mode

The resident service in this change deliberately does **not** run the
unrestricted upstream gateway. Instead systemd runs a bounded **one-shot
incident analyst** every approximately 30 minutes:

1. Read the existing Ops Watch SQLite state *read only* through the
   canonical `read_events` adapter. Most events are handled by rules alone
   and generate **no model calls**.
2. For a validated `ADVISOR_CANDIDATE`, enforce current normal
   `load1 <= 1.30`, RAM, swap, disk, news-idle, guard and proxy checks.
3. Reserve a call **before** Docker execution in an atomic, persistent
   state file. Maximum **1 model call per UTC day**, no automatic retry on
   an error, timeout, restart or HTTP 429; handled event IDs cannot replay.
4. Run the exact local patched image in the separate nonroot Docker
   process with explicit empty `bot_room` native toolset, no MCP,
   browser, shell, host DB, vault, SSH, GitHub or Telegram credentials;
   the only host credential injected is the existing Cloudflare Workers
   AI Free token. The tool only returns a proposed textual analysis.
5. Accept only a valid strictly allowlisted JSON report with evidence
   from the source event; no auto-remediation or publication. All output
   is sanitized before logging.

A new local image identity file `/etc/hermes-agent/h01-image.env`
contains only its full immutable Docker ID (not a secret).
`/var/lib/hermes-h01/state.json` and `run.lock` enforce durability
and deduplication. The systemd timer is persistent-false to avoid
catch-up floods after downtime. Proxy listens only on the restricted
internal bridge; the general Hermes gateway remains disabled.

The manual installer `deploy/install-h01-ops-agent.sh` is
owner-gated and checks exact source SHA, image/patch labels, network
guard, CPU/RAM admission, credentials mode and unit conflicts. It
must not be run as part of GitHub CI/CD; the production source
release is immutable and must be deployed first.

### Verification labels

- Image pull, patch build, synthetic tool checker, Workers Free
  text-only Hermes turn: **VPS VERIFIED**.
- Full real Ops event model analysis: **NOT RUN** unless a genuine
  eligible incident is observed; no incident should be invented to
  trigger a live production model call.
- Service/timer: **NOT ACTIVE** until manual install + current resource
  admission checks.
- Long-horizon simultaneous peak-load burn-in and provider billing:
  **NOT MEASURED** at initial activation. Do not call that passed
  based on unit tests or one turn.

Rollback: `systemctl disable --now hermes-h01-ops-agent.timer`;
stop the bounded service if active; disable/stop the dedicated
proxy if no other authorized consumer needs it. Do not remove news
workers or delete persistent call reservations to reset a quota.
