"""Rules-vs-Advisor comparison never claims live LLM value."""
from __future__ import annotations

import unittest

from ops_watch.advisor_comparison import compare_result, compare_scenarios
from ops_watch.incident_advisor import SCENARIOS, mock_result, prepare_context


class AdvisorComparisonTests(unittest.TestCase):
    def test_not_run_is_explicit(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        result = compare_result(context)
        self.assertEqual(result["ai"]["execution"], "NOT_RUN")
        self.assertEqual(result["difference"], "NOT_RUN")
        self.assertEqual(result["worth_using_ai"], "NOT_RUN")
        self.assertEqual(result["rules"]["root_cause"], "NOT_ESTABLISHED_BY_RULES")

    def test_mock_is_not_live_advantage(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        result = compare_result(
            context, advisor_result=mock_result(context), execution="MOCK_ONLY"
        )
        self.assertEqual(result["ai"]["execution"], "MOCK_ONLY")
        self.assertEqual(result["worth_using_ai"], "NOT_PROVEN")
        self.assertTrue(result["difference"]["status_match"])

    def test_same_bounded_cases_are_compared(self) -> None:
        rows = compare_scenarios()
        self.assertEqual(len(rows), 12)
        self.assertEqual({row["ai"]["execution"] for row in rows}, {"NOT_RUN"})
        self.assertTrue(all(row["input_provenance"] == "synthetic" for row in rows))


if __name__ == "__main__":
    unittest.main()
