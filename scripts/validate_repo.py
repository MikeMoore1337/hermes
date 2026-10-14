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
    "docs/security/THREAT_MODEL.md",
    "docs/operations/DEPLOYMENT.md",
    "docs/decisions/ADR-0001-separate-repository.md",
    ".github/workflows/quality.yml",
    "agents/README.md",
    "integrations/README.md",
    "skills/README.md",
    "deploy/README.md",
    "deploy/smoke.sh",
    "scripts/host_capacity.py",
    "tests/test_host_capacity.py",
    "tests/test_smoke_contract.py",
    "ops_watch/core.py",
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
