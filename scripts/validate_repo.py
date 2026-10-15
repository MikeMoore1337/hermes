"""Проверка исходной структуры Hermes без сети, секретов и внешних пакетов."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    "README.md",
    "AGENTS.md",
    "policies/INDEX.md",
    "scripts/check_policy_index.py",
    "tests/test_policy_index.py",
    "docs/audits/H-08-methodology-matrix-2026-10-14.md",
    "docs/templates/PROJECT_WORKFLOW_SNIPPET.md",
    "docs/architecture/OVERVIEW.md",
    "docs/architecture/OWNERSHIP.md",
    "docs/architecture/MIGRATION.md",
    "docs/architecture/H-01-runtime-plan.md",
    "docs/roadmap/ROADMAP.md",
    "docs/status/HERMES-CURRENT-2026-10-14.md",
    "docs/status/HERMES-CURRENT-2026-10-15.md",
    "docs/audits/H-02-vps-monitor-2026-10-14.md",
    "docs/audits/H-02-autosender-vps-2026-10-14.md",
    "docs/architecture/GROQ_FREE_BLOCKER.md",
    "docs/security/THREAT_MODEL.md",
    "docs/operations/DEPLOYMENT.md",
    "docs/decisions/ADR-0001-separate-repository.md",
    ".github/workflows/quality.yml",
    "agents/README.md",
    "integrations/README.md",
    "integrations/REGISTRY.md",
    "integrations/candidates.json",
    "integrations/registry.py",
    "agent_budget/__init__.py",
    "agent_budget/policy.py",
    "agent_budget/policy.json",
    "tests/test_agent_budget_policy.py",
    "docs/operations/H-10-AGENT-ROLES-BUDGETS.md",
    "docs/operations/H-10-CLOUDFLARE-FREE-VERIFICATION.md",
    "tests/test_integration_registry.py",
    "skills/README.md",
    "deploy/README.md",
    "deploy/smoke.sh",
    "deploy/run-agent-sandbox.sh",
    "deploy/prepare-agent-home.sh",
    "deploy/H-01-LOCAL-SANDBOX.md",
    "deploy/hermes-agent-sandbox.service.example",
    "tests/test_agent_sandbox_contract.py",
    "scripts/host_capacity.py",
    "tests/test_host_capacity.py",
    "tests/test_smoke_contract.py",
    "plugins/cloudflare-workers-ai-free/__init__.py",
    "plugins/cloudflare-workers-ai-free/plugin.yaml",
    "plugins/cloudflare-workers-ai-free/LICENSE",
    "deploy/install-cloudflare-free.sh",
    "deploy/set-cloudflare-free-credentials.sh",
    "tests/test_cloudflare_credentials_script.py",
    "docs/audits/H-01-cloudflare-free-preflight-2026-10-14.md",
    "scripts/cloudflare_text_probe.py",
    "scripts/agent_turn_probe.py",
    "tests/test_agent_turn_probe.py",
    "docs/operations/H-01_AGENT_TURN_DIAG.md",
    "scripts/cloudflare_connect_proxy.py",
    "deploy/setup-cloudflare-egress.sh",
    "scripts/ensure_cloudflare_egress.py",
    "deploy/hermes-cloudflare-network-guard.service",
    "tests/test_cloudflare_egress_guard.py",
    "docs/operations/H-01-NETWORK-BOOT.md",
    "deploy/hermes-cloudflare-proxy.service",
    "deploy/smoke-cloudflare-agent.sh",
    "tests/test_cloudflare_proxy_isolation.py",
    "docs/architecture/CLOUDFLARE_EGRESS.md",
    "docs/audits/H-01-cloudflare-live-2026-10-14.md",
    "docs/audits/H-01-full-agent-tool-turn-2026-10-14.md",
    "docs/audits/H-01-image-provenance-2026-10-14.md",
    "deploy/hermes-image-provenance.json",
    "deploy/hermes-upstream-security-diff.json",
    "docs/audits/H-01-upstream-security-diff-2026-10-14.md",
    "docs/audits/H-01-image-sbom-source-load-2026-10-15.md",
    "docs/audits/H-04-private-ci-watch-vps-2026-10-15.md",
    "docs/audits/H-03-research-digest-vps-2026-10-15.md",
    "docs/audits/H-03-first-science-candidates-2026-10-15.md",
    "tests/test_h01_upstream_security_diff.py",
    "tests/test_hermes_image_provenance.py",
    "scripts/image_local_inventory.py",
    "scripts/verify_v0221_local_image.py",
    "tests/test_v0221_local_image.py",
    "docs/operations/H-01-V0221-OFFLINE-IMAGE.md",
    "scripts/verify_upstream_release_receipt.py",
    "scripts/verify_upstream_release_ci.py",
    "scripts/verify_upstream_source_ci.py",
    "tests/test_upstream_source_ci.py",
    "docs/audits/H-01-upstream-source-ci-2026-10-15.md",
    "tests/test_upstream_release_ci.py",
    "docs/audits/H-01-upstream-release-ci-2026-10-15.md",
    "tests/test_upstream_release_receipt.py",
    "docs/audits/H-01-upstream-docker-receipt-drift-2026-10-15.md",
    "docs/audits/H-01-new-release-v0221-candidate-2026-10-15.md",
    "tests/test_image_local_inventory.py",
    "docs/operations/H-01-LOCAL-IMAGE-INVENTORY.md",
    "docs/audits/H-01-network-guard-vps-2026-10-14.md",
    "tests/test_cloudflare_text_probe.py",
    "docs/operations/CLOUDFLARE_TEXT_PROBE.md",
    "tests/test_cloudflare_free_provider.py",
    "qa_advisor/__init__.py",
    "qa_advisor/core.py",
    "qa_advisor/github_public.py",
    "qa_advisor/evidence.py",
    "tests/test_qa_h04_evidence.py",
    "qa_advisor/ci_snapshot.py",
    "qa_advisor/signal_store.py",
    "qa_advisor/watch_once.py",
    "tests/test_qa_ci_signal_store.py",
    "tests/test_qa_ci_watch.py",
    "deploy/hermes-qa-watch.service",
    "deploy/hermes-qa-watch.timer",
    "deploy/install-qa-watch.sh",
    "docs/operations/H-04-READONLY-WATCH.md",
    "tests/test_qa_ci_snapshot.py",
    "tests/test_qa_github_public.py",
    "qa_advisor/github_public.py",
    "tests/test_qa_github_public.py",
    "qa_advisor/README.md",
    "tests/test_qa_advisor.py",
    "research_scout/__init__.py",
    "research_scout/core.py",
    "research_scout/pubmed_fetch.py",
    "research_scout/ncbi_esummary.py",
    "research_scout/ncbi_rate_limit.py",
    "tests/test_research_ncbi_rate_limit.py",
    "research_scout/ncbi_esearch.py",
    "research_scout/ncbi_end_to_end.py",
    "research_scout/REVIEW_RUN.md",
    "tests/test_research_ncbi_end_to_end.py",
    "research_scout/NCBI_ESEARCH.md",
    "tests/test_research_ncbi_esearch.py",
    "research_scout/citation_review.py",
    "research_scout/review_cli.py",
    "research_scout/REVIEW_CLI.md",
    "tests/test_research_review_cli.py",
    "research_scout/CITATION_REVIEW.md",
    "tests/test_research_citation_review.py",
    "tests/test_research_ncbi_esummary.py",
    "tests/test_research_pubmed_fetch.py",
    "research_scout/PUBMED.md",
    "research_scout/README.md",
    "research_scout/europe_pmc.py",
    "research_scout/crossref.py",
    "research_scout/article_integrity.py",
    "tests/test_article_integrity.py",
    "docs/operations/H-03-ARTICLE-INTEGRITY.md",
    "research_scout/daily_digest.py",
    "tests/test_research_daily_digest.py",
    "tests/test_research_daily_integrity.py",
    "tests/test_research_daily_systemd.py",
    "deploy/hermes-research-scout.service",
    "deploy/hermes-research-scout.timer",
    "deploy/install-research-scout.sh",
    "docs/operations/H-03-DAILY-RESEARCH.md",
    "tests/test_research_crossref.py",
    "research_scout/EUROPE_PMC.md",
    "tests/test_research_europe_pmc.py",
    "tests/test_research_scout.py",
    "tests/test_research_safety_matrix.py",
    "ops_watch/incident_preview.py",
    "ops_watch/state_store.py",
    "ops_watch/delivery_contract.py",
    "ops_watch/telegram_sender.py",
    "ops_watch/telegram_e2e.py",
    "ops_watch/telegram_dispatch.py",
    "deploy/hermes-ops-alerts.service",
    "deploy/hermes-ops-alerts.timer",
    "deploy/install-ops-alerts.sh",
    "tests/test_ops_watch_telegram_dispatch.py",
    "tests/test_ops_watch_telegram_e2e.py",
    "tests/test_ops_watch_telegram_sender.py",
    "tests/test_ops_watch_delivery_contract.py",
    "tests/test_ops_watch_state_store.py",
    "tests/test_ops_watch_incident_preview.py",
    "ops_watch/core.py",
    "ops_watch/collector.py",
    "deploy/hermes-ops-watch.service",
    "deploy/hermes-ops-watch.timer",
    "deploy/install-ops-watch.sh",
    "tests/test_ops_watch_collector.py",
    "tests/test_ops_watch_recovery_transitions.py",
    "tests/test_ops_watch_atomic_projection.py",
    "tests/test_ops_alert_sender_self_monitor.py",
    "tests/test_ops_alert_sender_service_monitor.py",
    "docs/operations/H-02-SAFE-INCIDENT-TEST.md",
    "ops_watch/cli.py",
    "ops_watch/README.md",
    "tests/test_ops_watch.py",
    "docs/audits/H-01-on-host-smoke-2026-10-11.md",
)

FORBIDDEN_TRACKED_FILENAMES = frozenset({".env", "id_rsa", "id_ed25519", "credentials.json"})


def validate(root: Path = ROOT) -> list[str]:
    """Вернуть конкретные ошибки структуры и минимальных ограничений CI."""
    errors: list[str] = []
    for relative in REQUIRED_PATHS:
        candidate = root / relative
        if not candidate.is_file():
            errors.append(f"Нет обязательного файла: {relative}")
        elif candidate.is_symlink():
            errors.append(f"Неожиданная символьная ссылка: {relative}")

    workflow = root / ".github/workflows/quality.yml"
    if workflow.is_file():
        content = workflow.read_text(encoding="utf-8")
        if "contents: read" not in content:
            errors.append("CI не фиксирует contents: read")
        if "pull_request_target" in content:
            errors.append("Запрещён pull_request_target")
        if "deploy" in content.lower() or "secrets." in content.lower():
            errors.append("CI bootstrap не должен содержать deploy/secrets")

    for path in root.rglob("*"):
        if ".git" in path.parts or path.is_dir():
            continue
        if path.name in FORBIDDEN_TRACKED_FILENAMES:
            errors.append(f"Секретный файл не должен находиться в дереве: {path.relative_to(root)}")
    return errors


def main() -> int:
    """Напечатать диагностику и вернуть код завершения."""
    errors = validate()
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"PASS: Hermes bootstrap structure ({len(REQUIRED_PATHS)} required files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
