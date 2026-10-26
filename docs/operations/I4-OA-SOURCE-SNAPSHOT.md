# I4 #599 - official OA private source snapshots

The operator-only command:

    python3 -B -m research_scout.yfc_primary_snapshot --fetch-and-stage --pmcid PMC12345678 --source-id sourceone --expected-doi 10.1234/example

uses the existing bounded pinned-TLS Europe PMC client, validates JATS
PMCID and optional DOI, extracts body paragraphs without HTML and writes
one immutable sourceone.txt into the protected
/var/lib/hermes-research-scout/i4-primary-texts directory.

Pre-create that directory under the execution identity with mode 0700.
New files use 0600. The operation rejects a duplicate, symlink,
wrong process owner or mode, invalid identity, excess size or XML.
No overwrite is permitted, including on retry after uncertain writes.
Do not add a timer or root-owned credential to this command.

The output SHA-256 covers the exact extracted .txt; a separate hash
covers raw JATS XML. The plaintext is retained only in the protected
directory and is never printed by this tool. A source snapshot is
NEEDS_EDITORIAL_REVIEW, NOT approved evidence; retractions and publisher
corrections are not automatically cleared, even when licence metadata
exists. This is not a licence reuse clearance or scientific review.

Use the source_id, exact official PMC URL and full_text_sha256 as private
source_receipts in a separately operator-reviewed packet before invoking
the no-network claim-packet composer and handoff. No automatic model calls,
HMAC submission, YFC Root session, or public article publication happen here.

Unit tests: python3 -m unittest tests.test_i4_yfc_primary_snapshot -v
The tests use synthetic XML, not real copyrighted articles. Production
use requires independent checks of source licence, rights and scientific
claims. No new external polling loop or recurring fetch is activated.
