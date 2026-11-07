# OpenSource Radar v1 - offline source adoption review (#775)

This is a **read-only candidate precheck** in the existing Hermes QA Advisor package. It evaluates an **operator-supplied, constrained snapshot**, not GitHub directly. It cannot establish that a repository is trustworthy, that a license grants a particular use right, or that a component is safe to execute.

## What is checked

- GitHub-style repository slug \`owner/repo\` with bounded characters; only configured Hermes, Toolkit or YFC targets.
- Supplied 40-character immutable source commit SHA, default branch, archive/fork flags, latest push and release timestamps, bounded observation age.
- Supplied SPDX license identifier limited to a small known set, with permissive/unknown/copyleft review distinctions. AGPL integration into YFC is **HOLD**, not automatically approved.
- Provided security advisory signal \`REPORTED / NONE_OBSERVED / UNKNOWN\`, plus independently unverified target compatibility claim.
- Explicit statuses \`PILOT_REVIEW / NEEDS_REVIEW / HOLD_FOR_REVIEW / REJECT_RECOMMENDED\`, and immutable-commit GitHub URLs constructed from validated slug and SHA only.

## Synthetic input

\`\`\`json
{
  "schema": "hermes-ossradar-evidence-v1",
  "source_repo": "example-org/oss-lib",
  "target_repo": "MikeMoore1337/hermes",
  "observed_at": "2026-11-05T08:55:00Z",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "default_branch": "main",
  "is_archived": false,
  "is_fork": false,
  "pushed_at": "2026-11-04T12:00:00Z",
  "last_release_at": "2026-10-20T12:00:00Z",
  "license_spdx": "MIT",
  "advisory_signal": "NONE_OBSERVED",
  "compatibility_signal": "COMPATIBLE"
}
\`\`\`

These are invented **test-only** values, not a real repository report.

## Commands

\`\`\`bash
python3 -m unittest tests.test_opensource_radar -v
python3 -m qa_advisor.opensource_radar
python3 -m qa_advisor.opensource_radar --input /path/to/sanitized-candidate.json
\`\`\`

The default CLI mode is inert and emits \`NOT_EXECUTED\`. A supplied file must be non-symlink, regular, and at most 16 KiB. Invalid/unknown types and injected fields are rejected with fixed error codes. No HTTP, shell, clone, install, write, or model call takes place.

## Status meaning and safety invariants

- \`REJECT_RECOMMENDED\` indicates a supplied incompatible target. This is **only a recommendation**.
- \`HOLD_FOR_REVIEW\` signals license uncertainty/copyleft obligations, an archived repository or a reported security advisory.
- \`NEEDS_REVIEW\` signals missing pinned SHA, stale/incomplete maintenance or compatibility data, fork provenance, or other uncertainty.
- \`PILOT_REVIEW\` indicates no additional reported blocker **in the supplied facts**, but it is **not** an adoption approval or proof of security. Even here, \`security_not_verified\` remains visible because \`NONE_OBSERVED\` is not evidence of no CVEs.

All results set \`source_verified=false\`, \`license_verified=false\`, \`compatibility_verified=false\`, \`security_scan=NOT_RUN\`, \`source_executed=false\`, \`install_authorized=false\`, \`owner_approval=NOT_GRANTED\`. Never ingest README/Issue instructions as commands.

## Still required to finish Issue #775

- Read-only live GitHub source adapter which verifies canonical repository identity, immutable commit, source origin, tag/release provenance, public LICENSE/NOTICE and relevant dependencies, not merely a GitHub API license label.
- A scoped security advisory source and a verified compatibility protocol, without paid APIs. Preserve UNKNOWN when evidence is absent.
- Review source/license/NOTICE and exact SHA **before** installing external scripts/packages. No automatic \`curl | sh\` or third-party code execution.
- Optional gated handoff to DepPilot, maintaining independently verified source evidence. UI changes require owner-approved design process.
- Exact-head CI/review; separately authorized deployment and runtime evidence.

This module is not a duplicate of existing research/OSS catalog workflows (#61/#464). Its initial output is intentionally small and evidence-oriented, without creating another scheduler or database.


## Exact-commit LICENSE / NOTICE content integrity (GitHub public adapter)

The opt-in public reader now resolves an immutable source commit SHA, then obtains
the standard GitHub license resource **at that exact ref**. It decodes a bounded
base64 file (max 128 KiB), verifies the returned Git blob SHA-1 from actual
bytes, and emits only a SHA-256 digest. Missing file or an invalid hash never
proves license suitability.

Likewise it checks only three **standard root** filenames \`NOTICE\`,
\`NOTICE.txt\` and \`NOTICE.md\`, pinned to the same source commit. It records
\`FOUND_STANDARD_ROOT_FILE\` with digest or
\`NOT_FOUND_STANDARD_ROOT_PATHS\`. The latter does **not** prove the project
has no NOTICE elsewhere or that redistributing it has no obligations.

The reported SPDX identifier is still GitHub/source metadata;
\`license_verified=false\`, \`compatibility_verified=false\`,
\`security_scan=NOT_RUN\`, \`install_authorized=false\` and
\`owner_approval=NOT_GRANTED\` remain unchanged. No file contents are returned,
copied into Hermes, executed or exposed in the Command Center.

## Пилотный план и инвентаризация корня на закреплённом SHA

Публичный read-only адаптер дополнительно читает **только метаданные**
корневого каталога по точному commit SHA и передаёт распознанные имена
конфигурационных файлов (`pyproject.toml`, `package.json`, `uv.lock`,
`Cargo.toml`, `go.mod` и файлы LICENSE/NOTICE из закрытого перечня).
Пользовательские имена и содержимое файлов не копируются в отчёт.

Поле `root_metadata.coverage` различает `OBSERVED_PINNED_ROOT`,
`PARTIAL` и `NOT_AVAILABLE`; основной язык выводится лишь из
ограниченного списка известных языков GitHub, иначе `UNKNOWN`.
Повторное чтение SHA исходной ветки выявляет изменение источника во
время получения метаданных и прерывает проверку. `pilot_steps` - пять
фиксированных шагов для **человеческой приёмки**, не выполняемые команды.
`release_tag_verified=false`, `license_verified=false` и
`compatibility_verified=false` сохраняются: метаданные корня и дата
последнего релиза сами по себе этого не подтверждают.
