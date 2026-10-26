# I4 #599 - reviewed-claim packet composer

The existing Research Scout daily metadata digest cannot independently produce a
medically accurate article. The offline yfc_article_composer module provides a
deterministic, zero-cost next step after obtaining human-authored findings,
limitations, two or more source references per claim and SHA-256 protected
primary-text snapshots.

Input is a strict hermes-i4-claim-packets-v1 envelope with metadata, sources,
source_receipts, licence_reviews and claims. It returns the same
hermes-i4-reviewed-content-v1 document used by the pre-existing draft handoff.
Draft sections contain ONLY operator-provided interpretations and caveats, not
claims invented by the model or inferred from article titles. Scientific claim
matrix rows are always pending/unclear.

Important: licence and publisher notice fields are operator declarations.
SPDX/Creative Commons values or a JATS licence marker alone DO NOT establish
rights. Hash identity alone does not verify the source's science. Scientific
expert review remains independent; this module never attests it.

The composer does not persist or print source material, fetch any URL, read
credentials or transmit a draft. No cron/systemd activation, paid API, LLM,
Root session or publication route is involved. All transmission remains under
the separate explicit opt-in of yfc_draft_handoff. The generated article stays
READY_NOT_SUBMITTED; the owner later decides whether to publish in Hermes
Control Center using independent YFC Root authorization.

Offline tests: python3 -m unittest tests.test_i4_yfc_article_composer -v

This release does not supply any real publisher-cleared research files or a
production signed intake receipt. Synthetic test fixture rights are NOT real.
Until genuine evidence and source-rights review exist, #599 stays OPEN.
