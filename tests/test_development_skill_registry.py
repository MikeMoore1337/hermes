"""Ensure the development-only Toolkit skill set remains separately owned."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "agent-framework-fit",
    "external-skill-review",
    "security-boundaries",
    "provider-reality-check",
    "research-verification",
    "contract-testing",
    "change-impact-analysis",
    "browser-workflow-evidence",
    "release-safety",
}


def test_development_skills_have_valid_names_and_pinned_provenance() -> None:
    root = ROOT / ".agents" / "skills"
    found = {p.name for p in root.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}
    assert found == EXPECTED
    for name in EXPECTED:
        content = (root / name / "SKILL.md").read_text(encoding="utf-8")
        assert content.splitlines()[0] == "---"
        assert re.search(r"^name:\s*" + re.escape(name) + r"$", content, re.MULTILINE)
        assert "Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259" in content
        assert not (ROOT / "skills" / name / "SKILL.md").exists()


def test_runtime_skill_catalog_remains_development_separated() -> None:
    source = (ROOT / "skills" / "README.md").read_text(encoding="utf-8")
    assert "не содержит устанавливаемых навыков" in source
    assert (ROOT / ".agents" / "README.md").is_file()
