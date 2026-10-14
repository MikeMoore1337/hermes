# Ops Watch: offline core (H-02)

Status: deterministic offline core plus optional local-only on-VPS news health collector and a separately reviewed 10-minute timer. No outbound notifications, third-party APIs, model calls, SSH probes, GitHub access or service modification.

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


## Local collector (approved Hermes host only)

The collector reads **only the health subsection** of the existing YFC-owned `/var/lib/hermes/state.json` (the full file is private and never logged). It reads only the state of `hermes-discovery.timer`; writes a sanitized list of incident codes in root-owned `/var/lib/hermes-agent/ops-watch/findings.json` and logs added/resolved fingerprints to the local system journal. The systemd timer may be enabled independently of a model provider, without affecting YFC's news processing.

Install **only after tested PR/CI** and confirm no pre-existing system monitor: `bash deploy/install-ops-watch.sh` on approved server with matching source. Check via `systemctl list-timers hermes-ops-watch.timer`, `journalctl -u hermes-ops-watch.service`. The service is sandboxed, network-less, has no write access to YFC state, and is not an alternative publication path. A user-facing Telegram channel is a later separate task with new credentials/approval.

Failure of reading health **fails closed**: no old success is claimed, and the systemd unit reports an error. Rate-limit anomaly is intentionally disabled until a source reports a real recent interval, not a cumulative counter. Optional remote connectors remain unknown until genuinely implemented.

### Least-privilege note (2026-10-14)

The original unit with no Linux capabilities cannot traverse the existing news service's 0700 private state directory (owned by another UID). The new unit needs exactly `CAP_DAC_READ_SEARCH` **for reading**, not `CAP_DAC_OVERRIDE` for writing, and keeps `ProtectSystem=strict`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, and a single `ReadWritePaths` output directory. This capability permits reading other filesystem paths if the process were compromised; its security boundary is the audited, tiny, read-only Python collector, no network, non-secret logging and systemd sandbox. Future migration to a dedicated scoped health API should eliminate the privileged filesystem read.


## Control of Hermes Agent network safety

The local 10-minute Ops Watch also reads **systemd metadata only** for `hermes-cloudflare-network-guard.service`. It reports stable, allowlisted incident codes when the guard is missing, disabled, or inactive, and preserves existing incident deduplication/recovery. It never reads AI credentials, model output or raw nft rules. A malformed systemd response is **UNKNOWN / collection failure**, never reported as a healthy guard. No automatic repairs or Telegram notifications are implied. This is an additional operational signal, not a proof that exact firewall rules stayed unchanged after the last startup check.

## Локальный предварительный текст инцидента (без отправки)

Каждый запуск сборщика формирует **фиксированные, проверенные** описания только
для новых и закрытых инцидентов и сохраняет их в локальном
`/var/lib/hermes-agent/ops-watch/incident-preview.json`. Текст никогда не
интерполирует сведения из новостей, ошибки модели, журналов CI, приватных
сервисов или URL. После прохода без изменений файл становится пустым массивом.
Это **снимок последнего прохода**, а не надёжная очередь доставки: внешнего
Telegram/почтового сообщения и подтверждения получения пока нет.
Разрешение и новый отдельный канал оповещений остаются обязательными.
