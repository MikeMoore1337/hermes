"""Offline validation of the canonical Hermes policy link router; never execute rules."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTER = "policies/INDEX.md"
SAFE_MD = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.md\Z")
LINK = re.compile(r"\[[^\]\n]+\]\(([^)\n]+)\)")
EXPECTED_ROUTES = frozenset({
    "Любая разработка",
    "Runtime / новая служба",
    "Миграция новостей",
    "YFC интеграция",
    "Second Brain интеграция",
    "Работа с внешним источником",
    "H-03 исследование",
    "H-09 новая интеграция",
    "H-02 уведомления",
})


def check_text(root: Path, content: str) -> list[str]:
    """Verify only local, existing Markdown links; return bounded category codes."""
    problems = []
    if len(content) > 12000 or any(ord(c) < 32 and c not in "\n" for c in content):
        return ["policy_index_unsafe_content"]
    routes: set[str] = set()
    for line in content.splitlines():
        if not line.startswith("|"):
            continue
        parts = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(parts) != 2 or parts[0] in ("Работа", "---", ":---"):
            continue
        route, links = parts
        if not route or route in routes:
            problems.append("duplicate_or_invalid_policy_route")
        routes.add(route)
        parsed = LINK.findall(links)
        if not parsed or ("../AGENTS.md" not in parsed):
            problems.append("missing_agents_in_policy_route")
        # Parent traversal is allowed only when the final real path stays in
        # the same repo; this permits policies/INDEX -> ../AGENTS.md.
        for link in parsed:
            candidate = root / "policies" / link
            cleaned = link.removeprefix("../")
            components = link.split("/")
            allowed_parent = 1 if link.startswith("../") else 0
            if (not SAFE_MD.fullmatch(cleaned) or link.startswith("/")
                    or "://" in link or components.count("..") != allowed_parent):
                problems.append("unsafe_policy_link")
                continue
            try:
                resolved = candidate.resolve(strict=False)
                if not resolved.is_relative_to(root.resolve()):
                    problems.append("policy_link_outside_repository")
                    continue
                node = candidate
                symlinked = False
                while node.is_relative_to(root):
                    if node.is_symlink():
                        symlinked = True
                        break
                    if node == root:
                        break
                    node = node.parent
                if symlinked:
                    problems.append("symlinked_policy_link")
                    continue
                if not candidate.is_file():
                    problems.append("missing_policy_target")
            except OSError:
                problems.append("policy_file_unavailable")
        # Reject invisible/hostile Markdown nonlinks which could be mistaken
        # for mandatory instructions without stable provenance.
        if "http://" in links or "https://" in links or "<script" in links.lower():
            problems.append("external_policy_instruction_denied")
    if routes != EXPECTED_ROUTES:
        problems.append("incomplete_or_unexpected_policy_routes")
    return sorted(set(problems))


def validate(root: Path = ROOT) -> list[str]:
    file = root / ROUTER
    if file.is_symlink() or not file.is_file():
        return ["policy_index_missing_or_symlinked"]
    try:
        return check_text(root, file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return ["policy_index_unavailable"]


def main() -> int:
    findings = validate()
    for finding in findings:
        print("FAIL:", finding)
    if findings:
        return 1
    print("PASS: local task routing, canonical rules and no external instructions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
