# I4 #599 — first source dossier for YFC lifting-load educational draft

**Status:** `NEEDS_SOURCE_SNAPSHOTS_AND_HUMAN_REVIEW` (26 October 2026).  
**Policy:** `AUTO_DRAFT_ONLY`; `hmac_submission_allowed=false`; `auto_publish=false`.  
**Publication:** Root owner action only, after full article and evidence review in Hermes Control Center.

This is an **operator reading checklist**, not a scientific attestation, machine-approved claim packet, licence clearance or production article. No privileged host files, model calls, HMAC secrets, production requests or private source snapshots were accessed or created for this dossier. It is intentionally excluded from automated input discovery.

## Candidate educational topic

**Working RU title:** «Лёгкие и тяжёлые рабочие веса: как читать исследования о гипертрофии и силе».

This comparison requires careful differentiation of **load intensity**, **total volume**, **training to failure**, **strength-test specificity** and **populations**. The two studies below are not identical interventions and should not be aggregated into a new numerical effect estimate.

## Two original research articles

| Source ID for private staging | Identifier | Method/result reported by publisher | Source rights/status |
|---|---|---|---|
| `fink2016` | Fink J et al., *SpringerPlus* 2016, DOI `10.1186/s40064-016-2333-z`, PMCID `PMC4899398` | Randomized three-group study, 21 young male participants (7 per group), 8 weeks of unilateral preacher curls to failure: 80% 1RM, 30% 1RM, or alternation every 2 weeks. MRI elbow-flexor CSA increased **within** groups by 9.1%, 9.4% and 8.8% respectively; no statistically significant between-group difference in CSA change was detected. Isometric MVC increased significantly **within** the 80% group only. | Publisher article says **CC BY 4.0**. [Crossmark](https://crossmark.crossref.org/dialog/?doi=10.1186%2Fs40064-016-2333-z) reported **Document is current** at web-check time; this does not supersede a separate complete notice/retraction review. |
| `vann2022` | Vann CG et al., *Frontiers in Physiology* 2022, DOI `10.3389/fphys.2022.857555`, PMCID `PMC8962955` | Six-week study in previously resistance-trained men comparing **higher-load** with **higher-volume/lower-load** training. The authors report VL growth in the higher-volume condition and stronger leg-extensor strength response in the higher-load condition, with interpretation bounded by population, time and measurements. | Article indicates **CC BY**. Exact licence version, amendments, notices and retractions **NOT VERIFIED** in this dossier. |

Original full-text locations:

- Fink et al.: https://pmc.ncbi.nlm.nih.gov/articles/PMC4899398/ ; DOI https://doi.org/10.1186/s40064-016-2333-z
- Vann et al.: https://pmc.ncbi.nlm.nih.gov/articles/PMC8962955/ ; DOI https://doi.org/10.3389/fphys.2022.857555

**Do not assert:** (i) statistical non-significance proves two load regimes equivalent; (ii) differences in within-group p-values establish statistically significant between-group differences; (iii) studies on one muscle/short periods generalize to all exercises or people; (iv) the above licence page checks are a final redistribution clearance; or (v) verified outcomes for a specific YFC user.

## Prospective claim-to-source candidates — all PENDING

| Candidate | Provisional framing requiring full-text methods/result read | Verification blockers |
|---|---|---|
| `load_hypertrophy` | In the studied interventions, both lighter and heavier loads can coincide with local muscle-growth measures; general superiority/equivalence must not be inferred. | Compare population, load, failure criteria, muscle, volume and confidence intervals across both papers; direct original table/figure inspection |
| `strength_specificity` | Strength outcomes should be interpreted relative to exercise intensity and test type; do not conflate maximum dynamic strength with elbow-flexor isometric MVC or leg-extensor tests. | Distinguish between-group comparisons, test modality and uncertainty |
| `evidence_limitations` | Short experiments and small samples limit transfer to long-term programming, older adults or women. | Verify exact sample attrition, inclusion criteria, adverse events, corrections and external validity |

**Do not mark these `verified`.** Existing `research_scout.yfc_article_composer` deliberately writes `review_status: pending` and `support_level: unclear`. No source claims may be inferred from bibliographic metadata alone.

## Reproducible operator-only private snapshot procedure

After separately approving source rights/notice checks and preparing a directory owned by the current execution identity with mode `0700`, stage each unique `source_id` using the existing fail-closed one-shot tool. This is *documentation of a potential operator step*, **not** evidence the commands ran.

```sh
python3 -B -m research_scout.yfc_primary_snapshot \
  --fetch-and-stage --pmcid PMC4899398 --source-id fink2016 \
  --expected-doi 10.1186/s40064-016-2333-z
python3 -B -m research_scout.yfc_primary_snapshot \
  --fetch-and-stage --pmcid PMC8962955 --source-id vann2022 \
  --expected-doi 10.3389/fphys.2022.857555
```

Each private immutable `0600` text snapshot and returned `full_text_sha256` must be checked against the actual retained file and exact official URL before populating `source_receipts`; this document deliberately contains **no invented hashes**. Never run against public CI test fixtures as if they were real primary sources. If source fetch is unavailable, already staged, notices are unclear, publisher rights cannot be established or scientific interpretation is unresolved, remain in `HOLD`.

After operator-curated RU prose, exact source/notice review and `licence_reviews`, the no-network composer can prepare a **pending** `HermesWebArticleProposal`. The HMAC-only YFC intake must be invoked only through the existing explicitly approved runtime, with its preconfigured secret not exposed to logs or comments. First acceptance requires a genuine `accepted / draft` receipt from YFC production, persisted article ID/version/hash displayed in Hermes and confirmation that the public page is not accessible. Owner publication is a **separate later click**.

**Still absent:** protected original-text SHA receipts, final rights/notice reports for both studies, full-text claim interpretation, operator-reviewed RU packet, HMAC production acknowledgement, actual Hermes inbox row, production E2E. Keep Hermes #599 and YFC #1226 open.

References: [Hermes #599](https://github.com/MikeMoore1337/hermes/issues/599), [snapshot operator guide](./I4-OA-SOURCE-SNAPSHOT.md).
