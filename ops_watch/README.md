# Ops Watch: offline core (H-02)

Status: deterministic evaluation and local CLI only. NOT a deployed monitor. No polling sources, scheduled tasks, state persistence, messages, model calls or runtime operations.

The component accepts a bounded normalized JSON snapshot:
- schema = hermes-ops-snapshot-v1
- observed_at = timezone-aware ISO timestamp (not older than 15 minutes)
- news = timer_enabled, timer_active, last_successful_discovery_at, consecutive_discovery_failures, consecutive_drain_failures, pending_jobs, oldest_pending_age_seconds, recent_provider_rate_limits
- optional yfc = backend, worker, bot_polling (healthy, unhealthy, unknown)
- optional actions = ci, deploy (success, failure, running, unknown)

Use a confirmed Telegram polling heartbeat, not merely a running container, before emitting bot_polling=unhealthy. If that signal is unavailable, report unknown. The recent_provider_rate_limits field must be measured in a known bounded recent window or last drain phase, NOT the historical cumulative provider_rate_limit_count.

No news articles with a healthy discovery timer is not a failure. An old snapshot results only in snapshot_stale. Missing optional sources are unknown, not proof of health.

Offline testing:
    python3 -m unittest discover -s tests -v

Offline evaluation (with a locally prepared, trusted normalized file):
    python3 -m ops_watch.cli --snapshot /path/to/snapshot.json

Changes between findings can be computed using ops_watch.changes or CLI --previous. There is no persistent deduplication or notification transport. Unexpected human-authored fields are never copied into findings; do not submit personal data or secrets in input.

Before production:
1. Finish H-01 with OS-level isolation and measured resource budget.
2. Add independently reviewed read-only collectors for YFC and GitHub, with authentication and exact minimal privileges.
3. End-to-end test missing signals, drift, restart/recovery, rate limits, dedup, resource ceilings and negative permissions.
4. Obtain explicit approval for any actual alert destination. No restart, merge, deploy, news publication or vault access.
