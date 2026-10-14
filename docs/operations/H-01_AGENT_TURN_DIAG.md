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
