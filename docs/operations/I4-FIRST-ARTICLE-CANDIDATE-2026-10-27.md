# Hermes #599 — first RU article candidate: lifting loads

**Status:** `FULL_RU_CONTENT_PREPARED / PRIVATE_SOURCE_RECEIPTS_MISSING / NOT_SUBMITTED`.
**Owner gate:** draft-only HMAC intake MAY be considered only after independent source/rights review, trusted-host staging, exact receipts and final scientific checks. **No automatic publication; no Root identity in Research Scout.**

## Concrete deliverable

The complete six-section, fifteen-paragraph Russian article, five source-bound claims and all evidence matrix entries are maintained in the adjacent machine-readable file:

[`research_scout/reviews/i4-lifting-load-candidate-2026-10-27.json`](../../research_scout/reviews/i4-lifting-load-candidate-2026-10-27.json).

The article is human-readable by inspection of `article.title`, `article.lead` and `article.body_sections[]`. It is encoded as the pre-existing `hermes-i4-reviewed-content-v1` envelope and corresponds to YFC `HermesWebArticleProposal` schema; the envelope is **deliberately incomplete** because `source_receipts=[]`. The regular `yfc_draft_handoff.build_payload` **must reject** it with `PRIMARY_TEXT_RECEIPTS_MISSING` rather than infer primary evidence or access HMAC credentials. This candidate is **not** a YFC inbox record or fake production receipt.

### Source 1

- Julius Fink et al., *Impact of high versus low fixed loads and non-linear training loads on muscle hypertrophy, strength and force development*, SpringerPlus (20 May 2016).
- DOI: `10.1186/s40064-016-2333-z`. PMCID: `PMC4899398`.
- Full primary publisher text: https://link.springer.com/article/10.1186/s40064-016-2333-z
- Official private-snapshot locator: https://pmc.ncbi.nlm.nih.gov/articles/PMC4899398/
- Methods/results checked against publisher page on 27 October 2026: 21 participants, three groups of 7, unilateral preacher curls to failure, 80% vs 30% 1RM vs alternating, eight weeks. MRI CSA: +9.1%, +9.4%, +8.8% respectively; no significant difference between groups. The significant within-group MVC change at 80% **does not by itself establish** a statistically significant between-group advantage.
- Publisher explicitly lists Creative Commons Attribution 4.0 International. This is a **publisher-page observation**, not final rights/notice approval. Official licence: https://creativecommons.org/licenses/by/4.0/

### Source 2

- Christopher G. Vann et al., *Effects of High-Volume Versus High-Load Resistance Training on Skeletal Muscle Growth and Molecular Adaptations*, Frontiers in Physiology (11 March 2022).
- DOI: `10.3389/fphys.2022.857555`. PMCID: `PMC8962955`.
- Full primary publisher text: https://www.frontiersin.org/journals/physiology/articles/10.3389/fphys.2022.857555/full
- Official private-snapshot locator: https://pmc.ncbi.nlm.nih.gov/articles/PMC8962955/
- Methods/results checked against publisher page on 27 October 2026: 15 resistance-trained men, randomized leg-side conditions, six weeks; higher volume/lower load versus lower volume/higher load. At immediate POST, MRI vastus lateralis CSA +3.2% (HV) versus −0.1% (HL); between-condition change difference was present at POST but **not** at POSTPR, ten days later. Unilateral leg extension strength showed a condition-specific HL benefit. This is not evidence that every other muscle or strength test follows the same pattern.
- Publisher identifies **CC BY**, but exact version and complete notice status have not been independently established. Do **not** forge a `CC-BY-4.0` receipt on that basis alone.

### Current evidence and integrity boundaries

1. These are two original intervention studies, not two independent systematic reviews. Their different populations, muscles, outcomes, volume and follow-up prevent a general equivalence claim.
2. Publisher full text was examined for reported methods, measurements and outcomes. **No trusted Hermes-host full-text JATS extraction and immutable local SHA-256 receipts have been obtained in this workflow.**
3. **Publisher correction / Crossref reverse updates / retraction checks are not fully cleared for either source.** The absence of a notice in a page or generic search is not proof of absence. Leave rights and integrity in **HOLD** until explicit checks.
4. All five claim-source matrix rows are `review_status=pending, support_level=unclear`. No independent peer review, human science approval or licence attestation is claimed.
5. This repo file may be shipped as a **candidate only**. Its presence on the resident Hermes filesystem does not itself enqueue a draft or permit a source verification flag.

## Trusted-host completion procedure (NO unapproved writes)

Use the existing [bounded source snapshot operator tool](I4-OA-SOURCE-SNAPSHOT.md) only in the **already approved Hermes research execution identity**; **do not substitute a BRC sandbox, synthetic fixture or GitHub CI** for the real host. Before one-shot network access, verify owner of `/var/lib/hermes-research-scout/i4-primary-texts` and `0700` mode without outputting any secret.

Run at most one official JATS fetch per approved source ID, with explicit opt-in and expected DOI:

```sh
python3 -B -m research_scout.yfc_primary_snapshot \
  --fetch-and-stage --pmcid PMC4899398 --source-id fink2016 \
  --expected-doi 10.1186/s40064-016-2333-z

python3 -B -m research_scout.yfc_primary_snapshot \
  --fetch-and-stage --pmcid PMC8962955 --source-id vann2022 \
  --expected-doi 10.3389/fphys.2022.857555
```

If the tool reports `SOURCE_ALREADY_STAGED`, inspect the existing protected file and its SHA before deciding; **never overwrite, retry blindly or invent an expected hash**. The output contains `full_text_sha256` for the exact locally extracted text and separate `raw_xml_sha256`. Only after exact file readback, rights/notice checks and operator scientific review should the two `{source_id, url, full_text_sha256}` receipts be inserted into a **private** copy of the candidate envelope at `/var/lib/hermes-research-scout/i4-reviewed-content.json` (mode `0600` and owned by research execution identity, parent `0700`). Do not replace a pre-existing reviewed document without an explicit safe change plan.

Then use the existing fail-closed entry point. The first invocation is local-only and never publishes:

```sh
python3 -B -m research_scout.yfc_draft_handoff
```

It must report `READY_NOT_SUBMITTED`. If source rights, notice, SHA, model schema, article text or paper methods are unresolved, **stop there**. Separately approved, already configured host secrets `HERMES_I4_HMAC_SECRET` and `HERMES_I4_HMAC_KEY_ID` are required for any actual HMAC **draft-only** request; do not echo, reenter into a chat, commit, log or pass them through CI. The existing one-shot `--submit` option requires explicit `HERMES_I4_DRAFT_SUBMIT_APPROVED=YES` and accepts only genuine YFC `accepted/duplicate + draft` receipts. This is **not permission** for a hidden background submit, and never publishes.

Complete #599 only after production `accepted / draft` response is recorded, article ID/version and exact text are visible through the now owner-tested Hermes Root browser bridge, negative public visibility is checked, and the user confirms the displayed article. Publishing later remains a **distinct, explicit YFC Root click**.

## Test contract

`python3 -m unittest tests.test_i4_first_article_candidate -v` ensures exact expected source identifiers, bounded full article, claims and matrix, no verified labels/credentials or synthetic hashes, valid intake article constraints, and **fail-closed** behaviour until real source receipts exist.

No paid API calls, Codex CLI, Claude CLI, live HMAC requests or background model invocations were made in preparing this candidate.
