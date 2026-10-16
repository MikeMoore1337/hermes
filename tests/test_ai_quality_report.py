"""Evidence rollup must never certify mock model quality or USD=0."""
import json
import subprocess
import sys
import unittest

from agent_budget.pilot import RESULT_SCHEMA
from agent_budget.quality_report import QualityReportError, summarize

def record(name="ops:provider_http_429",mode="MOCK_ONLY",status="PASS",cost=None):
    return {
        "schema": RESULT_SCHEMA, "case": name, "task": name.split(":",1)[0],
        "model_execution": mode,"status":status,
        "model_calls": 0 if mode == "NOT_RUN" else 1,
        "metrics": {"provider_cost_usd":cost,"provider_neurons":None},
    }

class QualityRollupTests(unittest.TestCase):
    def test_mock_success_never_claims_model_quality_or_cost(self):
        rows=[record(),record("research:plant_recovery")]
        result=summarize(rows)
        self.assertEqual(result["mock_cases"],2)
        self.assertEqual(result["live_observed_cases"],0)
        self.assertEqual(result["reported_provider_cost_usd"],"NOT_RUN")
        self.assertEqual(result["provider_neurons"],"NOT_RUN")
        self.assertFalse(result["scientific_quality_verified"])
        self.assertFalse(result["billing_guaranteed_free"])
        self.assertEqual(result["llm_better_than_rules"],"NOT_PROVEN")

    def test_unknown_live_cost_blocks_financial_claim(self):
        rows=[record(mode="LIVE_OBSERVED_COST_NOT_VERIFIED",status="BLOCKED")]
        rows[0]["validation_status"]="PASS"
        result=summarize(rows)
        self.assertEqual(result["live_schema_accepted_cases"],1)
        self.assertEqual(result["reported_provider_cost_usd"],"NOT_VERIFIED")
        self.assertEqual(result["provider_neurons"],"NOT_VERIFIED")
        self.assertFalse(result["billing_guaranteed_free"])

    def test_reported_zero_cost_is_not_billing_guarantee(self):
        rows=[record(mode="LIVE_OBSERVED",cost=0.0)]
        result=summarize(rows)
        self.assertEqual(result["reported_provider_cost_usd"],"0.0")
        self.assertFalse(result["billing_guaranteed_free"])
        self.assertFalse(result["scientific_quality_verified"])

    def test_mixed_live_and_mock_not_merged(self):
        rows=[record(),record("research:plant_recovery",mode="LIVE_OBSERVED",cost=None)]
        result=summarize(rows)
        self.assertEqual(result["mock_cases"],1)
        self.assertEqual(result["live_observed_cases"],1)
        self.assertEqual(result["reported_provider_cost_usd"],"NOT_VERIFIED")

    def test_duplicates_and_forged_result_rejected(self):
        with self.assertRaises(QualityReportError):
            summarize([record(),record()])
        bad=record();bad["model_calls"]=99
        with self.assertRaises(QualityReportError):
            summarize([bad])
        bad=record();bad["model_execution"]="MAGIC_SUCCESS"
        with self.assertRaises(QualityReportError):
            summarize([bad])
        with self.assertRaises(QualityReportError):
            summarize([])

    def test_cli_is_offline_and_bounded(self):
        args=[sys.executable,"-m","scripts.hermes_ai_quality_report","--stdin"]
        response=subprocess.run(
            args,input=json.dumps([record()]).encode("utf-8"),capture_output=True,check=False
        )
        self.assertEqual(response.returncode,0,response.stderr)
        self.assertEqual(json.loads(response.stdout)["mock_cases"],1)
        for bad in (b"not-json",b" " * 262145):
            response=subprocess.run(args,input=bad,capture_output=True,check=False)
            self.assertEqual(response.returncode,2)
            self.assertEqual(json.loads(response.stdout)["status"],"REJECTED")

if __name__=="__main__":
    unittest.main()
