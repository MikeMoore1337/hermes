"""Research Scout: distinguish metadata-only inference from curated abstract evidence."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from agent_budget.pilot import (
    PilotError, _prepared_case, _research_quality,
    validate_research_result, run_pilot,
)

class ResearchAbstractPilotTests(unittest.TestCase):
    def test_public_abstract_is_paraphrased_and_not_full_text(self) -> None:
        task, case_id, provenance, draft, prompt, mock = _prepared_case(
            "research:plant_recovery_public_abstract"
        )
        self.assertEqual(task, "research")
        self.assertEqual(case_id, "plant_recovery_public_abstract")
        self.assertEqual(provenance, "curated_public_abstract_paraphrases")
        self.assertFalse(draft["abstract_source_provenance"]["full_text_reviewed"])
        self.assertIn("expected_sample_size", prompt)
        self.assertIn("field_evidence", prompt)
        self.assertEqual(len(draft["public_abstract_facts"]), 8)
        self.assertNotIn("manual_reference", prompt)
        result = validate_research_result(mock(), draft)
        self.assertEqual(result["sample_size"], "UNKNOWN")
        self.assertEqual(result["correction_status"], "UNKNOWN")
        self.assertEqual(result["evidence_basis"],
                         "curated_public_abstract_facts_not_full_text")
        quality = _research_quality(result, draft)
        self.assertEqual(quality["semantic_accuracy"], "NEEDS_EXPERT_REVIEW")
        self.assertEqual(quality["hallucination_count"], "NOT_RELIABLY_COUNTED")

    def test_metadata_only_cannot_invent_study_findings(self) -> None:
        for case in (
            "plant_recovery", "whey_gut_brain",
            "ironman_correction", "massage_cret",
        ):
            with self.subTest(case=case):
                _, _, _, draft, _, mock = _prepared_case("research:"+case)
                result = json.loads(mock())
                result["study_type"] = "Систематический обзор"
                with self.assertRaisesRegex(PilotError, "metadata_only_scientific_claims_denied"):
                    validate_research_result(result, draft)

    def test_abstract_cannot_misread_study_count_as_participants(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:plant_recovery_public_abstract")
        result = json.loads(mock())
        result["sample_size"] = "36 участников"
        result["field_evidence"]["sample_size"] = ["F1"]
        with self.assertRaisesRegex(PilotError, "abstract_sample_size_or_correction_unverified"):
            validate_research_result(result, draft)

    def test_abstract_cannot_claim_correction_absent(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:plant_recovery_public_abstract")
        result = json.loads(mock())
        result["correction_status"] = "Исправления отсутствуют"
        result["field_evidence"]["correction_status"] = ["F1"]
        with self.assertRaisesRegex(PilotError, "abstract_sample_size_or_correction_unverified"):
            validate_research_result(result, draft)

    def test_abstract_requires_exact_fact_ids_for_every_known_field(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:plant_recovery_public_abstract")
        value = json.loads(mock())
        value["field_evidence"]["main_results"] = ["UNKNOWN_FACT"]
        with self.assertRaisesRegex(PilotError, "abstract_ungrounded_fact_id"):
            validate_research_result(value, draft)
        value = json.loads(mock())
        del value["field_evidence"]["main_results"]
        with self.assertRaisesRegex(PilotError, "abstract_field_evidence_invalid"):
            validate_research_result(value, draft)
        value = json.loads(mock())
        value["field_evidence"]["control"] = ["F1"]
        with self.assertRaisesRegex(PilotError, "abstract_field_evidence_invalid"):
            validate_research_result(value, draft)

    def test_other_three_public_abstracts_and_ids_are_grounded(self) -> None:
        cases = {
            "whey_gut_brain_public_abstract": ("UNKNOWN", "UNKNOWN", "42840492"),
            "ironman_correction_public_abstract": (
                "2485", "CORRECTION_REPORTED_50_TO_150_MIN_PER_WEEK", "42771055"
            ),
            "massage_cret_public_abstract": ("25", "UNKNOWN", "42733310"),
        }
        for name, (sample, correction, pmid) in cases.items():
            with self.subTest(name=name):
                _, _, provenance, draft, prompt, mock = _prepared_case("research:"+name)
                self.assertEqual(provenance, "curated_public_abstract_paraphrases")
                self.assertEqual(draft["identifiers"]["pmid"], pmid)
                self.assertEqual(draft["abstract_source_provenance"]["expected_sample_size"], sample)
                self.assertEqual(draft["abstract_source_provenance"]["expected_correction_status"], correction)
                self.assertIn("field_evidence", prompt)
                result = validate_research_result(mock(), draft)
                self.assertEqual(result["sample_size"], sample)
                self.assertEqual(result["correction_status"], correction)
                self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
                self.assertEqual(_research_quality(result, draft)["expert_review"], "NOT_RUN")

    def test_ironman_correction_and_observational_study_must_not_be_rewritten(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:ironman_correction_public_abstract")
        output = json.loads(mock())
        output["correction_status"] = "UNKNOWN"
        del output["field_evidence"]["correction_status"]
        with self.assertRaisesRegex(PilotError, "abstract_sample_size_or_correction_unverified"):
            validate_research_result(output, draft)
        output = json.loads(mock())
        output["sample_size"] = "36"
        with self.assertRaisesRegex(PilotError, "abstract_sample_size_or_correction_unverified"):
            validate_research_result(output, draft)

    def test_known_fact_cannot_cite_unrelated_research_field(self) -> None:
        for case, field, bad_id in (
            ("plant_recovery_public_abstract", "objective_outcomes", "F4"),
            ("whey_gut_brain_public_abstract", "main_results", "F1"),
            ("ironman_correction_public_abstract", "main_results", "F2"),
            ("massage_cret_public_abstract", "objective_outcomes", "F4"),
        ):
            with self.subTest(case=case, field=field):
                _, _, _, draft, _, mock = _prepared_case("research:" + case)
                value = json.loads(mock())
                value["field_evidence"][field] = [bad_id]
                with self.assertRaisesRegex(PilotError, "abstract_fact_field_mismatch"):
                    validate_research_result(value, draft)

    def test_scientific_output_cannot_cite_empty_unsupported_field(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:whey_gut_brain_public_abstract")
        value = json.loads(mock())
        value["objective_outcomes"] = "Доказано улучшение памяти."
        value["field_evidence"]["objective_outcomes"] = ["F3"]
        with self.assertRaisesRegex(PilotError, "abstract_fact_field_mismatch"):
            validate_research_result(value, draft)

    def test_ironman_correction_references_actual_erratum(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:ironman_correction_public_abstract")
        provenance = draft["abstract_source_provenance"]
        self.assertIn("10.1007/s00520-026-11294-6", provenance["correction_url"])
        result = json.loads(mock())
        result["field_evidence"]["correction_status"] = ["F6"]
        with self.assertRaisesRegex(PilotError, "abstract_required_source_citation_missing"):
            validate_research_result(result, draft)
        result = json.loads(mock())
        result["field_evidence"]["sample_size"] = ["F3"]
        with self.assertRaisesRegex(PilotError, "abstract_fact_field_mismatch"):
            validate_research_result(result, draft)

    def test_massage_biomarker_cannot_be_substituted_for_functional_gain(self) -> None:
        _, _, _, draft, _, mock = _prepared_case("research:massage_cret_public_abstract")
        result = validate_research_result(mock(), draft)
        self.assertIn("Нет значимых различий", result["objective_outcomes"])
        self.assertEqual(result["sample_size"], "25")
        self.assertNotEqual(result["correction_status"], "NO_CORRECTIONS")
        # Syntactic references are not semantic proof.
        self.assertEqual(_research_quality(result, draft)["semantic_accuracy"],
                         "NEEDS_EXPERT_REVIEW")

    def test_local_mock_run_never_proves_real_llm_quality(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = run_pilot(engine="mock", cases=["research:plant_recovery_public_abstract"],
                                output=Path(directory) / "results.json")
        self.assertEqual(len(records), 1)
        item = records[0]
        self.assertEqual(item["status"], "PASS")
        self.assertEqual(item["model_execution"], "MOCK_ONLY")
        self.assertEqual(item["quality"]["expert_review"], "NOT_RUN")
        self.assertEqual(item["quality"]["semantic_accuracy"], "NEEDS_EXPERT_REVIEW")


if __name__ == "__main__":
    unittest.main()
