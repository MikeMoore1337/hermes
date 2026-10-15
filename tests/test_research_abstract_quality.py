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
        self.assertIn("sample_size=UNKNOWN", prompt)
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
        _, _, _, draft, _, mock = _prepared_case("research:plant_recovery")
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
