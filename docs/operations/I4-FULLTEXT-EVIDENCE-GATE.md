# I4 / Hermes #599 — Full-text evidence availability gate

Source: official Europe PMC REST `GET /{PMCID}/fullTextXML`, for its
Open Access subset only. This route is a *source preflight*, **not** an
article writer, a scientific reviewer, a license clearance or a publisher.

## Source and identity policy

`research_scout.yfc_fulltext_gate.fetch("PMC…")` accepts a strict numeric
PMCID prefixed with `PMC`. It uses the existing Europe PMC DNS and pinned
TLS transport. Exactly one bounded HTTPS GET is permitted; redirects,
compression, unexpected Content-Type, non-200, excessive bytes and arbitrary
URLs are refused. It needs no credential, subscription, paid AI or Codex CLI.

`inspect(pmcid, raw, expected_doi=…)` works offline with already retrieved
JATS XML. Entity/DOCTYPE processing is prohibited. It checks exact PMCID,
optional expected DOI, article/body structure, maximum 512 KiB and 15,000
nodes. `sha256` proves identity of the inspected input bytes, not scientific
validity; a JATS license marker does not prove republication rights.

**Only safe metadata leaves this module:** source identity and digest,
full-text presence, license marker presence, fixed review flags/status.
Paragraphs, figures, effects, user data, XML content and publication text are
**not returned or stored**. The caller must not log or retain raw XML by
default. There is no timer, file writes, HMAC request, API key or model turn.

Even positive result is `NEEDS_CONTENT`, with:
`license_reuse_verified=false`, `primary_claims_verified=false`,
`claim_source_matrix=[]`, `reviewer_attestation=null`,
`yfc_intake_payload=null`, `hmac_submission_allowed=false`,
`automatic_publication=false`.

The next editorial gate must independently establish original full text,
license conditions, correction/retraction notices, per-claim quotations and
supporting source matrix, contradictions, qualified human review status
(`pending` unless genuinely approved). **Never** construct a complete
YFC article merely from a Crossref/Europe PMC bibliography card.

Companion YFC #1226 / PR #1241 implements deterministic HMAC candidate
provisioning, but its intake must still receive a separately valid,
fully structured article; these metadata receipts cannot be transmitted.
YFC/Hermes owner-only UI #601 and the existing Root publication action
remain separate from this research work. Automatic publication is forbidden.

Offline tests:
`python3 -m unittest tests.test_i4_yfc_fulltext_gate -v`.
Production download/extraction is **not** enabled or scheduled by delivery of
this source. A future real scheduled use of new network traffic needs a
separate bounded resource/operations gate.
