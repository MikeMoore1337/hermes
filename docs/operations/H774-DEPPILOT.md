# DepPilot v1 - offline dependency candidate planning (#774)

DepPilot is a **read-only** companion for Hermes QA Advisor. It reads **only** an explicitly supplied \`uv.lock\` or npm \`package-lock.json\` and a separate small candidate-metadata JSON file. This is *not* a package resolver, source/registry fetcher, security scanner, auto-upgrader or PR creator.

Existing OSV/SBOM/CVE audits (#185/#199 and H-22) remain separate. DepPilot does not claim to replace their security findings.

## Capabilities

- Parses pinned Python package records from \`uv.lock\` using stdlib \`tomllib\`; parses npm \`package-lock.json\` lockfileVersion 2 or 3, including scoped and nested \`node_modules\` entries.
- Requires the supplied candidate document to match the **SHA-256 of the actual lockfile bytes**, avoiding accidental analysis against another lock version.
- Compares installed and proposed **simple numeric** versions. \`MAJOR/MINOR/PATCH\` are positions in version components, **not** proof of semantic-version guarantees, PEP 440 compatibility, or lack of breaking changes. Complex/pre-release versions are \`UNORDERED\`.
- Compares a supplied runtime version (e.g. Python 3.14.x or Node.js 22.x) against supplied numeric \`min_runtime\`/\`max_runtime_exclusive\`, returning \`SUPPORTED_BY_SUPPLIED_RANGE\`, \`UNSUPPORTED\` or \`UNKNOWN\`. These are **not verified package metadata**, and one stated bound cannot prove complete compatibility.
- \`MULTIPLE_INSTALLED\`, \`MISSING\`, \`UNORDERED\`, missing runtime constraints, stale metadata, source mismatch and unrecognized packages never become silent green status.
- A candidate update includes a fixed regression checklist; the checker itself never runs dependency tests, downloads packages, writes a lockfile or opens a PR.

## Candidate file

\`\`\`json
{
  "schema": "hermes-deppilot-candidates-v1",
  "repo": "MikeMoore1337/hermes",
  "lock_sha256": "<sha256 of uv.lock bytes>",
  "observed_at": "2026-11-05T08:55:00Z",
  "runtime_version": "3.14.0",
  "candidates": [
    {
      "ecosystem": "pypi",
      "name": "pytest",
      "candidate_version": "8.4.2",
      "min_runtime": "3.11.0",
      "max_runtime_exclusive": "3.15.0"
    }
  ]
}
\`\`\`

This is **an illustrative template**, not a statement that any named version is the latest, compatible, installable, maintained or actually published. The provided version and compatibility data must be independently verified against official registry/release metadata before use.

## Commands

\`\`\`bash
python3 -m unittest tests.test_deppilot -v
python3 -m qa_advisor.deppilot
python3 -m qa_advisor.deppilot --lockfile ./uv.lock --candidates ./candidates.json
\`\`\`

By default the command is inert: \`NOT_EXECUTED\`. The CLI refuses a symlink, unreadable/invalid file, overlarge lockfile (8 MiB) or candidate JSON (64 KiB), or missing paired input. No network or write effects.

## Result and risk gates

- \`REVIEW_REQUIRED\`: proposed version differences in internally consistent evidence, with required tests.
- \`INCONCLUSIVE\`: stale, mismatched, incomplete or unknown installed/candidate/runtime evidence; this never authorizes an update.
- \`NO_CHANGES_IN_SUPPLIED_CANDIDATES\`: no differences in the small operator-supplied candidate set, **not** proof all dependencies are current.

Always \`candidate_source_verified=false\`, \`latest_versions_verified=false\`, \`dependency_constraints_verified=false\`, \`tests_executed=false\`, \`changes_written=false\`, \`pull_requests_created=false\`, \`vulnerability_scan=NOT_RUN\`, and \`production_authorized=false\`.

## Still required to finish Issue #774

- Verify actual source manifest constraints, current registry versions, transitive compatibility and official Python/Node compatibility **without paid APIs**, within an authorized sandbox and project scope.
- Compare project lockfile/toolchain against latest *compatible* candidates; perform real lock regeneration plus focused dependency/unit/browser regressions in a new authorized target-project branch.
- Reuse existing Github/QA Advisor evidence paths; do not touch the owner's original Windows projects, YFC \`master\`, or production services.
- Collect exact-head CI/review/source provenance, and obtain separate owner authorization for any real deployment.

No new scheduler, tokens, provider billing, automatic installation or upgrade.
