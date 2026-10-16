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

## Follow-up / owner gate

Only after real v4 burn-in and an explicit owner-approved read-only API
contract should #6 define scopes, response expiry, revocation and redaction.
Then #63 may assess **approved, sanitized statuses**, never direct vault
files, Git, SQL, private note content or automatic exports to a public LLM.

Status: `STAGE_1_SYNTHETIC_ONLY`. `STAGE_2_BLOCKED`. No production GO.
