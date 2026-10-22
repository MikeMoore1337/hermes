# H-27 #464 - reviewed extensions without a second plugin framework

**Decision: REUSE EXISTING + minimal offline verification (no runtime adapter).**
This is an ADR-style implementation note scoped to Issue #464. The feature
exists as deterministic fixtures/tests inside the already shipped
`hermes_toolperf/` evaluation package. No plugin manager, loader, installer,
auto-update loop, worker, new API endpoint, or Hermes BRC privilege is added.

## Existing component inventory

| Component | Existing source | Review decision |
| --- | --- | --- |
| Research Scout | `research_scout/core.py`: explicit source host allowlist, bounded metadata normalization, provenance review | **Reuse existing**: no generic source plugin needed |
| QA Advisor | `qa_advisor/core.py`: fixed repository, run and job schema; deterministic read-only triage | **Reuse existing**: no third-party QA hook needed |
| Control Center | `control_center/server.py` and existing owner authentication; frontend/UI gates unchanged | **Reuse existing**: not another plugin dashboard |
| Cloudflare Workers Free example | `plugins/cloudflare-workers-ai-free/plugin.yaml`, native Hermes profile and credential preconditions | **Do not activate** or assume approval based on manifest |
| Hermes dashboard plugin | `plugins/hermes-control-center/dashboard/plugin_api.py`, gated dashboard snapshot | **Do not install** pending resident runtime approval |
| Hermes BRC / MCP | Other H-15 and #350 workstreams | **Out of scope**; no trust from MCP `readOnlyHint` |

There is no proven case for generic runtime plugin installation in these
components. The actual gap is **documentation and regression coverage** of
reviewed source identity, capability/scope drift and denial before future
third-party integrations are considered.

## External references and source rights

- Method/reference only: `NousResearch/hermes-example-plugins`
  `main@fb6726740efccccd56ddb117c25f1d1f3d4edd65`, GitHub repository
  license metadata MIT (verified at time of audit).
- Method/reference only: `NousResearch/hermes-official-plugins`
  `main@55c1b45893116eaa09256d3d8731a3184bc12c4d`, repository license
  metadata MIT; individual plugins can have their own licenses, so each
  concrete candidate needs separate review.
- **No external source code, manifest, license file, model or data was copied**
  or executed. Neither MIT metadata nor a repository URL is implicit permission
  to install third-party code on Hermes.

## Strict offline manifest and review record

`hermes_toolperf/plugin_review.py` models exactly one synthetic data source.
The complete required manifest is:

`id`, `api_version`, `capabilities`, `data_scope`, `side_effects`,
`owner_policy`, `source_repo`, `source_commit`, `license`,
`optional_dependencies`.

Manifest input is JSON, not a replacement for Hermes native YAML/plugin
formats. It requires the known API v1, exact source pin, reviewed license,
single synthetic `research.read` capability, no side effects, no optional
dependencies and a fixed synthetic scope. Unknown fields, aliases and unknown
permissions fail closed. A separate fixed review record has exact
`source_commit`, `license`, `capabilities`, `data_scope`,
`owner_policy`, `reviewed`, `enabled`; `False`, revoked or mismatching
review denies the operation. No automatic `pip/npm` installation occurs.

The manifest's `source_repo=synthetic/hermes-fixture` and
`source_commit=0123456789abcdef0123456789abcdef01234567` are **deliberately
synthetic values**: they are not an actual repository, verified Git object,
owner approval or runtime credential. The comparator only proves that its
**two offline artifacts match**, not that a supply-chain review occurred.
Actual SHA authenticity must be proven against a separately approved source
before a future installation. There is no source checkout, path import or
network access in this test lane.

The one reader returns a fixed in-memory record with
`source_kind=synthetic`. It can only accept `research-record-v1`, detects
duplicate call IDs, and has no writes/network/process effects.

## Evidence and negative scenarios

- `hermes_toolperf/fixtures/plugin-review-v1.json`: 16 versioned negative
  manifests with fixed IDs and expected reason codes.
- `hermes_toolperf/plugin_cases.py`: deterministic replay with canonical
  SHA-256 for dataset and each negative case. The independent oracle requires
  the correct denial **and** empty call/effect ledgers for denied input.
- `tests/test_plugin_review_contract.py`: positive fixture, duplicate call,
  disabled/unreviewed policy, mismatched SHA/license/scope, untrusted
  `readOnlyHint`, unknown dependencies, unexpected fixture, corrupt JSON,
  output tampering and no network/subprocess execution.
- Run `python3 -m hermes_toolperf.plugin_cases` and
  `python3 -m unittest tests.test_plugin_review_contract -v`.
  Both use Python standard library only and are included in exact-SHA CI.

## Production and approval boundaries

- `SOURCE_DELIVERED` only means the Python test files reached the normal
  Hermes source release; it does not mean the runtime plugin was installed.
- `PLUGINS_ENABLED=false`, `RUNTIME_ADAPTER=NOT_IMPLEMENTED`,
  `REAL_UPSTREAM_SHA_AUTHENTICATION=NOT_RUN`, and
  `THIRD_PARTY_EFFECTS=NOT_RUN` remain accurate.
- Before any future external plugin or MCP-enabled resident agent:
  authenticate the real upstream commit/content, verify per-file license,
  dependencies and rollback, inspect actual OS/network ACL, enforce deny
  in the installed runtime and obtain separate owner approval under #350.
  Never rely on the manifest's claimed read-only status.
- Control Center visual changes would require a separate design approval;
  there are **no UI changes** here.

**Conclusion:** `IMPLEMENT_MINIMAL_FIX` for the independently identified
offline-review gap; `NO_GO` for a second universal plugin framework and
automatic plugin activation without a proven consumer.
