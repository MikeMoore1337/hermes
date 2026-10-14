"""Проверка исходной структуры Hermes без сети, секретов и внешних пакетов."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    "README.md",
    "AGENTS.md",
    "policies/INDEX.md",
    "docs/architecture/OVERVIEW.md",
    "docs/architecture/OWNERSHIP.md",
    "docs/architecture/MIGRATION.md",
    "docs/architecture/H-01-runtime-plan.md",
    "docs/roadmap/ROADMAP.md",
    "docs/audits/H-02-vps-monitor-2026-10-14.md",
    "docs/architecture/GROQ_FREE_BLOCKER.md",
    "docs/security/THREAT_MODEL.md",
    "docs/operations/DEPLOYMENT.md",
    "docs/decisions/ADR-0001-separate-repository.md",
    ".github/workflows/quality.yml",
    "agents/README.md",
    "integrations/README.md",
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
    "docs/audits/H-01-network-guard-vps-2026-10-14.md",
    "tests/test_cloudflare_text_probe.py",
    "docs/operations/CLOUDFLARE_TEXT_PROBE.md",
    "tests/test_cloudflare_free_provider.py",
    "research_scout/__init__.py",
    "research_scout/core.py",
    "research_scout/README.md",
    "tests/test_research_scout.py",
    "ops_watch/core.py",
    "ops_watch/collector.py",
    "deploy/hermes-ops-watch.service",
    "deploy/hermes-ops-watch.timer",
    "deploy/install-ops-watch.sh",
    "tests/test_ops_watch_collector.py",
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
