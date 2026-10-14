# H-01 Agent startup diagnostic - Issue #24

The original invocation used chat -q with --oneshot -Q, which obscured
startup. This candidate uses the upstream explicit top-level one-shot command:
hermes -z PROMPT --provider workers-ai -m @cf/openai/gpt-oss-20b -t todo
--reasoning low.

Upstream -z bypasses interactive tool approvals. This test is restricted to
the todo-only toolset, a separate non-root private state, an internal Docker
bridge, a Cloudflare-only proxy, immutable image and strict CPU/RAM/pid limits.
NEVER reuse the flags on an agent with shell or external write permissions.

The new one-shot runner:
- runs only with explicit --execute, no automatic schedule;
- skips if news/ops-watch timers or resource guard unhealthy, load1 > 1.10,
  private creds/firewall/bridge absent, proxy unexpectedly running/enabled;
- starts the non-persistent Cloudflare proxy for this one test only;
- terminates and removes the container if load1 > 1.30 or 130s elapse;
- captures raw stdout/stderr only in unlinked root-only /run temporary file;
- logs only fixed error codes and counters, and always stops the proxy;
- runs one bounded Workers Free model invocation, no paid fallbacks.

Operator (approved VPS only, after green CI and verified source transfer):
python3 /opt/hermes-agent-owner/scripts/agent_turn_probe.py --execute

This smoke does not enable a daemon, Telegram publishing or other tools.
A successful response alone is not authorization to enable 24/7 gateway.

## Confirming real tool use (separate, bounded operation)

After a successful text-only call, one more explicit run can use --execute
--tool-test. The model is instructed to call ONLY the in-memory todo_list
tool with synthetic content, then print TOOL_OK. The runner verifies that the
agent-owned SQLite state.db has a new active todo tool call/result row;
a merely claimed TOOL_OK without an actual persisted call is NOT a pass.
This test allows at most 205 seconds to accommodate two model round trips.
There is no vault, repository or news access, and no external write tool.
No background task or periodic monitoring is enabled.

## Mutual exclusion (race guard for VPS use)

The executable now takes a root-owned, mode-0600 nonblocking flock on
`/run/hermes-agent-test.lock` **before** the capacity checks and keeps it
until the Cloudflare proxy has been stopped and the agent container has been
removed. A competing invocation immediately fails with `agent_already_running`.
A symlink, unexpected owner, non-regular or overly permissive lock is refused.
Never delete the lock file during operation: keeping the inode prevents lock
replacement races. Partial systemd proxy startup failures also trigger proxy
stop in the finally block. This is an agent-only lock; it does not modify
YFC discovery or Ops Watch scheduling.

## Cloudflare Workers Free failure policy (14 Oct 2026)

The free-only provider classifies **every** provider failure as `retryable=false`
and `should_fallback=false`, including 401, 402, 403, 408, 429, 5xx,
and network/unknown errors. Provider-supplied error text is never returned.
Official Cloudflare docs distinguish 429/3036 (daily 10,000 Neurons spent)
from 429/3040 (out of capacity), and 403/5035 (model needs Paid plan).
The provider does not inspect response bodies or silently purchase credits;
both causes therefore fail closed under a fixed diagnostic category.

Sources: https://developers.cloudflare.com/workers-ai/platform/pricing/
and https://developers.cloudflare.com/workers-ai/platform/errors/

**Billing boundary:** a pinned free-eligible model and non-retryable policy are
NOT sufficient to enforce a zero-dollar limit if the owner's Cloudflare
account were later upgraded to Workers Paid or AI Gateway prepaid billing.
Before a scheduled service, verify the account is on Workers Free and no
unified/prepaid billing applies; introduce a separately verified daily hard
budget and quota observation. No automatic gateway/agent run is allowed yet.
