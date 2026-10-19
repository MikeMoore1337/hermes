# H-11 #63: Offline knowledge-quality contract, stage 1

## Scope

This is a **synthetic-only**, memoryless quality classifier. It is not a
Second Brain integration. It never reads or writes the private vault, does not
call an API or model, and does not implement a second search/index service.
Stage 2 remains BLOCKED by Second Brain #386, Hermes #6 and #33.

Second Brain v4 documentation:
[README](https://github.com/MikeMoore1337/second-brain/blob/main/README.md)
describes canonical Markdown/YAML metadata, Obsidian wikilinks, vault validate,
Search/Retrieval as read-only projections, and separately owner-approved
Safe Write. It does **not** establish that the synthetic H-11 contracts here
are already enforced on actual v4 live retrievals. No private vault was read.

## Gap matrix

| Check | Documented Second Brain v4 | Synthetic H-11 behaviour | Decision |
|---|---|---|---|
| Metadata, source provenance | Vault metadata and validation documented | Source references checked; missing source => HOLD; no provenance => UNKNOWN | Actual integration NOT VERIFIED |
| Freshness | No real stale guarantee established by this assessment | Checked date and source update older than 30 days => HOLD | Need separately specified API semantics |
| Revoked permissions | Safe Write/retrieval capabilities have separate boundaries | Source access=revoked => HOLD | API auth/revocation is owned by #6, NOT IMPLEMENTED |
| Contradictory facts | Cannot infer a semantic truth checker from v4 README | Synthetic YES/NO for same demo topic/predicate => HOLD on both | Does not provide semantic NLP checking |
| Orphaned/low-trust links | Obsidian wikilinks validation documented | Unknown fact links => HOLD; an existing linked HOLD/UNKNOWN fact also downgrades the referring fact transitively | Real vault link integrity and semantic dependency NOT VERIFIED |
| Inaccessible/expired API | Separate owner gate under #6 | No API or filesystem access implemented | BLOCKED |
| Unknown or missing scientific meaning | No self-generated facts allowed | UNKNOWN without provenance, never invent evidence | Offline check only |

The comparison deliberately differentiates **documented**, **tested in mock
data**, **not verified**, and **blocked**. It does not claim to identify
actual v4 implementation gaps without an owner-approved source audit.

## Synthetic-only input contract

`knowledge_quality.offline_audit.audit_fixture(data, as_of="2026-10-16")`
accepts a strict object with `schema=hermes-h11-synthetic-fixture-v1`,
`sources` and `facts`. Both sources and facts use synthetic identifiers.
Source origin must equal `synthetic_only`. Facts use demo-only topics and
predicates, `YES|NO|UNKNOWN` values, explicit dates and reference arrays.

Only summary statuses READY, UNKNOWN, HOLD and fixed reason codes are
returned; not original fact values. Date is injected by caller so offline
tests are deterministic. Bounds: 80 sources, 100 facts, max 8 references
per field and 16 KiB CLI input. Paths, URLs, personal text, arbitrary
metadata and unknown keys fail closed.

Offline CLI:

```bash
python3 -m knowledge_quality.offline_audit --as-of 2026-10-16 < synthetic-fixture.json
python3 -m unittest discover -s tests -p test_h11_offline_knowledge_quality.py -v
```

This is **not** a policy engine to be connected to the actual Second Brain
without approval. No network, new dependency, secret or model. The tests
include stale, revoked, contradictory, orphaned, insufficient provenance,
missing source, forged origin, private path and overflow conditions.
A linked synthetic fact is not automatically trusted just because its ID exists:
linked HOLD propagates HOLD; linked UNKNOWN yields UNKNOWN unless a stronger
HOLD condition is present. Propagation is bounded by the fixture's 100-fact
limit, including cycles. This is not a real-world dependency/causality proof.


## Evidence matrix: Second Brain v4 vs Hermes H-11 (2026-10-19)

Labels refer to the named capability, not the entire product.
**DOCUMENTED** = public contract; **IMPLEMENTED** = inspected public code;
**TESTED_OFFLINE** = synthetic evidence; **NOT_VERIFIED** = live behavior not tested;
**BLOCKED** = explicit owner/dependency gate; **MISSING** = future external contract unspecified.

| Check | Second Brain v4 public evidence | Hermes stage 1 | Missing contract | Verdict |
|---|---|---|---|---|
| Provenance | Optional research sources, source validation | Strict synthetic source IDs | Approved quality-status projection | DOCUMENTED, IMPLEMENTED, TESTED_OFFLINE; live NOT_VERIFIED |
| Freshness | Canonical dates and retrieved_at; no global fact TTL | 30-day synthetic checked_on and updated_on | Approved evidence validity policy | TESTED_OFFLINE; live NOT_VERIFIED |
| Revoked permissions | Separate Safe Write and read boundaries | Revoked source => HOLD | External revocation semantics (#6) | TESTED_OFFLINE; integration BLOCKED |
| Contradictions | No general semantic conflict checker established | Conflicting demo YES/NO => HOLD | Canonical conflict status | TESTED_OFFLINE; live NOT_VERIFIED |
| Orphan links | Wikilink target validation (not heading/block validation) | Missing synthetic ID => HOLD | Evidence dependency vs ordinary link distinction | IMPLEMENTED, TESTED_OFFLINE; mapping NOT_VERIFIED |
| Transitive dependencies | Specialized Stage 2/12/14 relations, not a generic trust graph | Bounded multi-hop HOLD/UNKNOWN | Approved graph semantics | TESTED_OFFLINE; live NOT_VERIFIED |
| Missing source | Optional source list for research-derived notes | Missing source ID => HOLD | Canonical source lookup status | TESTED_OFFLINE; live NOT_VERIFIED |
| Insufficient evidence | Marker-gated Personal Memory evidence metadata | Empty sources or UNKNOWN => UNKNOWN | Evidence quality threshold | TESTED_OFFLINE; live NOT_VERIFIED |
| Source expiry | Retrieved time does not establish expiry | Synthetic staleness only | Canonical source expires_at | Future external contract MISSING |
| Safe retrieval | Current UUID reread, index is never truth | No retrieval or network | Approved metadata-only reader (#6) | DOCUMENTED, IMPLEMENTED; external access BLOCKED |
| Trust propagation | No universal trust graph promise | HOLD > UNKNOWN > READY over required links | Link dependency authority | TESTED_OFFLINE; live NOT_VERIFIED |
| Access revocation | Vault belongs to Second Brain | Synthetic revoked => HOLD | Read credential/scope revocation (#6) | TESTED_OFFLINE; external enforcement BLOCKED |

Public evidence:
[Vault contract](https://github.com/MikeMoore1337/second-brain/blob/main/docs/architecture/vault-contract-v1.md),
[provenance tests](https://github.com/MikeMoore1337/second-brain/blob/main/tests/test_provenance.py),
[validation code](https://github.com/MikeMoore1337/second-brain/blob/main/src/second_brain/application/validation.py),
[self-retrieval contract](https://github.com/MikeMoore1337/second-brain/blob/main/docs/cognitive-twin/self-retrieval-v1-contract.md).
These public guarantees and synthetic tests do not measure the quality of actual notes.

### Strict input decoding

All JSON object keys must be unique at every nesting level. Plain JSON decoding
silently accepts shadowed keys, such as an initial private-vault origin followed
by synthetic_only, or a private raw value followed by YES. The CLI now rejects
these before synthetic schema validation, using the existing generic REJECTED /
invalid_fixture response and exit 2. It never exports the shadowed value.
The same input produces the same statuses regardless of fact ordering.
HOLD overrides UNKNOWN on multiple required links; READY only means the
synthetic rules found no blocking condition, not factual truth.

## Proposed read-only Stage 2 metadata contract (NOT approved)

This is a requirements draft for Second Brain and Hermes #6, not a deployed
API, new endpoint, transport, service account or permission to access data.
Permissible *candidate fields* are: schema_version, opaque fact_id,
source_status, provenance_status, freshness_status, permission_status,
checked_at, expires_at, quality_status and bounded reason_codes.
Second Brain must define their exact closed enum values, authority, scopes,
bounded size, version compatibility and temporal semantics.

Reject unknown schema versions, duplicate keys, missing fields, unexpected
statuses, conflicting status combinations, expired responses, malformed dates
and incomplete provenance. Permission revoked, 401/403, unavailable API,
untrusted response origin, unknown evidence or expired data must never be
silently promoted to READY. No guessed values, broad credential retry or
cached-as-truth fallback. Concrete HOLD/UNKNOWN/denial mapping must be approved
and tested under #6 first. No raw notes, fact content, local paths,
attachments, personal data, secrets, access tokens or model memory.
Hermes must have no write scopes, SQL, filesystem or vault Git access.

### Stage 2 gates - not satisfied by synthetic CI

| Requirement | Owner | Current evidence | Status |
|---|---|---|---|
| Real burn-in and owner-reviewed report | [Second Brain #386](https://github.com/MikeMoore1337/second-brain/issues/386) | OPEN; elapsed 14 days alone insufficient | BLOCKED |
| Approved external read-only API and privacy schema | Second Brain / [Hermes #6](https://github.com/MikeMoore1337/hermes/issues/6) | No approved external status projection verified | BLOCKED |
| Minimum scopes, expiry, rate limits and revocation | Hermes #6 | No real connector tested | BLOCKED |
| H-01 stability and acceptance | [Hermes #33](https://github.com/MikeMoore1337/hermes/issues/33) / [#2](https://github.com/MikeMoore1337/hermes/issues/2) | Separate operational acceptance pending | BLOCKED |
| Explicit approval for actual personal-data flow | Owner | Not recorded | BLOCKED |
| Read-only OS/API enforcement and privacy guarantees | Hermes #6 | No authorized external consumer | BLOCKED |
| Real integration and denial tests | Hermes #6 / #63 | Not allowed before gates | BLOCKED |

After exact-SHA tests, offline stage may be marked STAGE_1_DONE; Stage 2
remains STAGE_2_BLOCKED. Do not close Issue #63, enable runtime, read private
second-brain-vault, activate a connector, or modify Second Brain production.

## Follow-up / owner gate

Only after real v4 burn-in and an explicit owner-approved read-only API
contract should #6 define scopes, response expiry, revocation and redaction.
Then #63 may assess **approved, sanitized statuses**, never direct vault
files, Git, SQL, private note content or automatic exports to a public LLM.

Status: `STAGE_1_SYNTHETIC_ONLY`. `STAGE_2_BLOCKED`. No production GO.
