"""H-03 offline expert handoff: unresolved *scientific* review gates.

A source having a DOI, a Crossref metadata hit, public HTML, or a reviewer
checklist never establishes methodological validity. This file provides an
immutable, source-bound checklist, NOT a way to approve studies.
No I/O except optional JSON written to stdout, no network/models/publication.
"""
from __future__ import annotations

from datetime import UTC, datetime
import argparse
import json
from typing import Any

from .report_view import curated_reports

SCHEMA = "hermes-science-expert-handoff-v1"

# Claims below are limited to observed official public HTML/abstract and
# an explicitly *unverified* secondary registry mirror. Each task is a
# question for a future independent reviewer, not a conclusion.
# Structure: (gate_id, requested_review, source_url, source_depth)
REVIEW_GATES = {
    "42840492": (
        ("W1", "Check whether any direct combined whey+RT randomized trial measured validated human cognitive and microbiome endpoints in the same participants.",
         "https://www.frontiersin.org/journals/cellular-and-infection-microbiology/articles/10.3389/fcimb.2026.1918695/full",
         "PUBLISHER_SECTIONS_2_AND_10_OBSERVED"),
        ("W2", "Independently retrieve the pivotal primary trials; audit indirectness, selection of cited evidence, bias and population heterogeneity.",
         "https://pubmed.ncbi.nlm.nih.gov/42840492/", "ABSTRACT_AND_BIBLIOGRAPHY_ONLY"),
        ("W3", "Audit claim-specific effects and 95% confidence intervals for cognition; if never measured directly, report NOT_APPLICABLE, not zero effect.",
         "https://www.frontiersin.org/journals/cellular-and-infection-microbiology/articles/10.3389/fcimb.2026.1918695/full",
         "NARRATIVE_REVIEW_NO_POOLED_COGNITIVE_EFFECT"),
        ("W4", "Independently check publisher notices and licensing before any public downstream excerpt.",
         "https://www.frontiersin.org/journals/cellular-and-infection-microbiology/articles/10.3389/fcimb.2026.1918695/full",
         "PUBLISHER_NOTICE_CLEARANCE_NOT_VERIFIED"),
    ),
    "42771055": (
        ("I1", "Independently assess selection and nonresponse bias: 2485 questionnaire responders out of 4538 registry participants; examine loss to follow-up.",
         "https://link.springer.com/article/10.1007/s00520-026-11251-3",
         "PUBLISHER_RESULTS_SECTION_OBSERVED"),
        ("I2", "Validate resistance session frequency proxy (15 minutes per session), sensitivity, and original questionnaire against supplement.",
         "https://link.springer.com/article/10.1007/s00520-026-11251-3",
         "PUBLISHER_METHODS_SECTION_OBSERVED"),
        ("I3", "Check models, confounding, missingness, reported odds ratios and 95% confidence intervals; do not equate guideline adherence with cancer treatment efficacy.",
         "https://link.springer.com/article/10.1007/s00520-026-11251-3",
         "PUBLISHER_SELECTED_RESULTS_OBSERVED"),
        ("I4", "Independently verify corrected results against source: Springer correction changed median moderate activity 50 to 150 minutes per week.",
         "https://link.springer.com/article/10.1007/s00520-026-11294-6",
         "PUBLISHER_CORRECTION_CONFIRMED"),
        ("I5", "Independent full-text, appendix and statistical audit, including impact of the corrected descriptive value; publisher assertion alone is not an independent recalculation.",
         "https://link.springer.com/article/10.1007/s00520-026-11251-3",
         "REQUIRES_UNREVIEWED_SUPPLEMENT_AND_DATA"),
    ),
    "42797032": (
        ("P1", "Retrieve original 36 intervention trials; verify de-duplication, sample sizes, comparator and missing outcome data.",
         "https://pubmed.ncbi.nlm.nih.gov/42797032/", "ABSTRACT_AND_SELECTED_METHODS_ONLY"),
        ("P2", "Independently apply appropriate systematic-review quality criteria (e.g. AMSTAR 2); author-reported 11 low RoB2, 24 some concerns, 1 serious ROBINS-I is not an independent rating.",
         "https://pubmed.ncbi.nlm.nih.gov/42797032/", "AUTHOR_ROB_SUMMARY_ONLY"),
        ("P3", "Audit the primary muscle-function endpoints, trial-level effect sizes, 95% CIs, clinical importance, heterogeneity and whether quantitative pooling is warranted.",
         "https://www.mdpi.com/2072-6643/18/18/3049", "PUBLISHER_FULL_TABLES_NOT_INDEPENDENTLY_VERIFIED"),
        ("P4", "Review the full publisher version and supplementary history, not only the Crossref updates filter; source notes show initial 18 September 2026 uploads, not notice clearance.",
         "https://www.mdpi.com/2072-6643/18/18/3049/notes", "PUBLISHER_VERSION_NOTES_INDEXED_NOT_FULL_CLEARANCE"),
        ("P5", "Confirm distribution license for any quote, table or supplement reused by a downstream project.",
         "https://www.mdpi.com/2072-6643/18/18/3049", "LICENSE_REUSE_NOT_INDEPENDENTLY_AUDITED"),
    ),
    "42733310": (
        ("C1", "Obtain official ClinicalTrials.gov NCT06906146 history and match sample size / amendments against 25 athletes reported in the article. Secondary mirrors mention planned enrollment 50, not independently authoritative.",
         "https://clinicaltrials.gov/study/NCT06906146", "OFFICIAL_REGISTRY_FULL_RECORD_NOT_OBSERVED"),
        ("C2", "Independently check crossover sequence allocation, washout, possible carryover, masking and missing visits using the primary article and protocol.",
         "https://pubmed.ncbi.nlm.nih.gov/42733310/", "ABSTRACT_ONLY_PROTOCOL_NOT_REVIEWED"),
        ("C3", "Retrieve lactate, ultrasound and functional performance tables; verify effect sizes, 95% CIs, correction for multiple timepoints/tests and clinical relevance.",
         "https://pubmed.ncbi.nlm.nih.gov/42733310/", "ABSTRACT_P_VALUES_ONLY"),
        ("C4", "Separate metabolic surrogate effects at 60 minutes (lactate p=0.029) from Wingate, knee extension force and other functional outcomes; non-significance does not prove equivalence.",
         "https://pubmed.ncbi.nlm.nih.gov/42733310/", "ABSTRACT_FUNCTIONAL_RESULTS_ONLY"),
        ("C5", "Check manufacturer/device involvement, source license, protocol deviations, and publisher correction/retraction notices.",
         "https://onlinelibrary.wiley.com/doi/10.1002/ejsc.70246",
         "PUBLISHER_FULL_TEXT_AND_NOTICES_NOT_VERIFIED"),
    ),
}

FIXED_PMIDS = frozenset(REVIEW_GATES)
EXPECTED_DOIS = {
    "42840492": "10.3389/fcimb.2026.1918695",
    "42771055": "10.1007/s00520-026-11251-3",
    "42797032": "10.3390/nu18183049",
    "42733310": "10.1002/ejsc.70246",
}


def packet(*, now: datetime) -> dict[str, Any]:
    """Build fail-closed handoff; it cannot collect or accept approvals."""
    if (type(now) is not datetime or now.tzinfo is None
            or now.utcoffset().total_seconds() != 0):
        raise ValueError("handoff_requires_utc")
    records = curated_reports()
    if (len(records) != 4 or len({r["pmid"] for r in records}) != 4
            or {r["pmid"] for r in records} != FIXED_PMIDS):
        raise ValueError("handoff_curated_sources_changed")
    reviews: list[dict[str, Any]] = []
    for report in records:
        pmid, doi = report["pmid"], report["doi"]
        if (type(doi) is not str
                or doi.casefold() != EXPECTED_DOIS[pmid]
                or report["scientific_claims_verified"] is not False
                or report["full_text_reviewed"] is not False
                or report["expert_review"] != "NOT_RUN"
                or report["review_status"] != "NEEDS_EXPERT_REVIEW"
                or report["status"] not in ("HOLD", "MANUAL_REVIEW")):
            raise ValueError("handoff_curated_science_promoted")
        if pmid == "42771055" and (
                report["status"] != "HOLD"
                or report.get("correction_url") !=
                "https://link.springer.com/article/10.1007/s00520-026-11294-6"):
            raise ValueError("handoff_correction_must_hold")

        tasks = []
        seen: set[str] = set()
        for gate_id, question, reference, evidence_limit in REVIEW_GATES[pmid]:
            if gate_id in seen or not reference.startswith("https://"):
                raise ValueError("handoff_gate_invalid")
            seen.add(gate_id)
            tasks.append({
                "id": gate_id,
                "question": question,
                "reference_url": reference,
                "source_coverage": evidence_limit,
                "review_state": "NOT_INDEPENDENTLY_REVIEWED",
                "effect_size": "NOT_INDEPENDENTLY_VERIFIED",
                "confidence_interval": "NOT_INDEPENDENTLY_VERIFIED",
                "reviewer": None,
                "review_signature": None,
                "editorial_approval": False,
            })
        reviews.append({
            "pmid": pmid,
            "doi": doi,
            "source_title": report["title"],
            "original_candidate_status": report["status"],
            "scientific_review_status": "NEEDS_EXPERT_REVIEW",
            "scientific_claims_verified": False,
            "reviewer_approval": False,
            "publisher_clearance_verified": False,
            "publication_allowed": False,
            "gates": tasks,
            "gates_incomplete": len(tasks),
        })
    return {
        "schema": SCHEMA,
        "generated_at": now.isoformat(),
        "source_scope": "FOUR_FIXED_OWNER_CURATED_REPORTS_AND_PUBLIC_SOURCE_POINTERS",
        "studies": reviews,
        "study_count": 4,
        "incomplete_gate_count": sum(x["gates_incomplete"] for x in reviews),
        "conclusion": "HOLD_FOR_INDEPENDENT_SCIENTIFIC_REVIEW",
        "scientific_claims_verified": False,
        "full_text_independently_reviewed": False,
        "external_publication_allowed": False,
        "reviewer_signoff_supported_by_this_tool": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline H-03 expert review handoff")
    parser.parse_args(argv)
    print(json.dumps(packet(now=datetime.now(UTC)),
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
