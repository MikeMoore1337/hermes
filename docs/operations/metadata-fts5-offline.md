# H-30 / #467: SQLite FTS5, synthetic metadata only

**Verdict: `GO_OFFLINE_PROTOTYPE / DEFER_LIVE_INGEST`.** FTS5 is a
stdlib-backed low-footprint approach for bounded searchable task metadata.
No actual owner-approved producer or real search consumer exists yet.
Do **not** activate in resident Hermes, expose an HTTP endpoint,
read production SQLite/Second Brain or install a new memory service.

## Source inventory and owner/data-scope contract

The inventory below describes existing **owners**, not permission to copy.

| Existing component | Data and owner | Decision for H-30 |
| --- | --- | --- |
| `ops_watch/state_store.py`, `incidents.sqlite3` | Ops Watch's transactional state/outbox, operational events and persistence | **DENY ingest**: runtime incident data; independent production ACL and provenance gate |
| `qa_advisor/signal_store.py` | Root-owned strict latest CI observation under /var/lib/hermes-qa-watch | **DENY ingest**: real CI data; keep existing isolated semantics |
| `research_scout/` | Scientific source metadata and content provenance under Research Scout | **DENY ingest**: separate licensing and user-review scope |
| `second_brain_readonly/offline_adapter.py` | Mock-only scoped status; real Second Brain #6/#63 authorizations not granted | **DENY** Second Brain vault and status transport, even read-only |
| `control_center/` | Owner-only dashboard and Codex/project-specific snapshots | **DENY** HTTP index endpoint or another data-export channel |
| Existing `hermes_benchmark`, `hermes_toolperf` and `hermes_context_eval` | Fixed synthetic offline harness, no runtime task history | **ALLOW TEST FIXTURES ONLY**; no production source binding |
| **New** `hermes_metadata_fts/` | Synthetic fixtures `H-demo-####` with source URIs that LOOK like GitHub | In-memory ephemeral, strictly `project_id=hermes`, `scope=synthetic:hermes`, `no_source_authentication` |

Data allowed for **synthetic test records only**:
`schema_version=1`, `task_id` (fictional), `project_id`,
`kind` (issue/pr/ci/deploy), `title` (short synthetic label),
`timestamp` (Unix UTC seconds), `source_uri` (synthetic illustrative
GitHub path or absent), `revision`, `scope`, `status`
(`verified/stale/unknown`), `revoked` (must be false at admission).
No raw prompts, messages, credentials, user names, full body, arbitrary paths
or arbitrary project/scope fields may enter the schema.

**Caveat:** Here `verified` means the **synthetic fixture** has the
expected local metadata/URI form. It does NOT authenticate a real GitHub
receipt; each search result explicitly reports
`source_authenticated: false`. A genuine integration must separately
prove resource provenance, authorization, retention and revoke semantics.

Owner boundary: **NO_GO** on ingesting any real data until separate
owner-reviewed producer authentication, per-project ACL and lifecycle
review. Caller-chosen `project_id` is not a production identity or
authorization token; FTS prototype instances are hard-scoped to one
non-real project. The actual Second Brain gates remain #6/#63.

## FTS5 contract and lifecycle

- Python 3 stdlib `sqlite3` with SQLite FTS5 enabled, `unicode61` tokenizer;
  supports Russian/English case-insensitive token matching.
- `sqlite3.connect(":memory:")`, `temp_store=MEMORY`, no on-disk index,
  no timers/network/processes, no real SQL access from callers.
- Static bounded exact schema and allowlists; title <=120 chars /
  <=240 UTF-8 bytes, internal record count **256**, search results **20**,
  1–6 query tokens, search phrase <=80 chars, 30-day retention, up to 256
  tombstones for explicit deletion or expiration.
- Reject token-like secrets, absolute private paths, vault mentions and
  dangerous structured fields. This is **defense in depth**, not a general
  PII detector; real user content must never be admitted via these checks.
- Search: `query` → safely quoted unicode words → parameterized FTS5
  `MATCH`; exact project/scope enforced. Optional kind, UTC range,
  explicitly requested status. Defaults to `verified`; stale/unknown
  are **never silently promoted**. Missing source is only valid when not
  `verified`, returned as `None`.
- Upsert deduplicates exact `task_id + revision`; same revision with a
  different payload rejects `REVISION_CONFLICT`; older revision rejects
  `STALE_REVISION`. A higher revision replaces old FTS content and
  status atomically. `remove` deletes both metadata and index row,
  creates a local tombstone, denies resurrection within the
  **lifetime of this ephemeral instance**.
- Closing this object discards the index. Expired tombstones are not durable,
  so no cross-process revoke guarantee is claimed.

## Fixed CI benchmark and evidence limits

Run from repository root, no packages/API/models:

```bash
python3 -m unittest tests.test_hermes_metadata_fts -v
python3 -m hermes_metadata_fts.benchmark --format json
python3 -m hermes_metadata_fts.benchmark
```

The benchmark indexes **160 synthetic rows** and makes **64 bounded
queries**, outputs real wall-clock p50/p95 of the local runner,
Python-only allocation peak, approximate `PRAGMA page_count * page_size`
of SQLite in-memory pages and `persistent_disk_bytes=0`.
CPU%, total process RSS, actual deployed VPS load, user relevance,
production disk and real provenance remain **NOT_MEASURED**. Do not
conflate Python `tracemalloc` with full native SQLite allocator/RSS.

The existing GitHub CI runs benchmark after all unit tests, without
a new required workflow and without triggering any model. Optional OS
memory/resource caps for a real worker are **NOT_IMPLEMENTED**; the
strict small row/tombstone/query caps are prototype safety bounds only.

## FTS5 versus external memory options

| Option | Value | Decision |
| --- | --- | --- |
| SQLite FTS5 | In-process, already available in stdlib Python SQLite build, structured provenance fields, lexical RU/EN search | **GO_OFFLINE**, evaluate real utility only after authorized producer |
| Mem0 | Additional persistence/provider orchestration and embeddings often require model API | DEFER / no usage case justifying cost |
| OpenViking | Extra storage/indexing components and integration | DEFER |
| Honcho | Personalization/service boundary and external dependencies | DEFER |
| Supermemory | External/cloud components and separate credential/data export | NO_GO until explicit privacy/consent decision |
| Vector DB / SaaS | New ops and model cost, unproven benefit for metadata | NO_GO |

Upstream method only: `NousResearch/hermes-agent` (MIT repository
metadata, checked 22.10.2026). No code/data copied. Comparison is an
architecture decision, not a security or cost certification for upstream
services.

**Release boundary:** source-only quality CI and source deploy deliver
this inert test harness; they do **not** install a persistent index or
approve historical/user session ingestion. If a real producer becomes
necessary, open a separate issue with owner approval, actual source
contract, security checks, measured VPS budget and guaranteed deletion.
