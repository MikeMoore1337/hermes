"""Exact pinned YFC 241A historical SEO evidence is usable offline."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

from marketing.seo_research import SeoResearchDenied, build_packet
from marketing.yfc_wordstat_import import SOURCE_BLOB_SHA1, import_yfc_wordstat
from tests.test_marketing_seo_research import input_packet

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "yfc_241a_semantic_core_20260916.csv"


class YfcWordstatImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_bytes()

    def load(self, query: str, as_of: str = "2026-10-19"):
        return import_yfc_wordstat(self.source, selected_query=query, as_of=as_of)

    def test_pinned_csv_kbju_is_single_yandex_source(self):
        result = self.load("калькулятор кбжу")
        self.assertEqual(result["source_git_blob_sha1"], SOURCE_BLOB_SHA1)
        self.assertEqual(result["source_quality"], "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED")
        self.assertEqual(len(result["observations"]), 2)
        self.assertEqual(
            [(o["wordstat_operator"], o["search_volume"]) for o in result["observations"]],
            [("broad", 16127), ("quoted_fixed_word_count", 4763)],
        )
        self.assertEqual({o["source"] for o in result["observations"]}, {"yandex_wordstat"})
        self.assertEqual({o["wordstat_region"] for o in result["observations"]}, {"Russia"})
        self.assertFalse(result["publication_allowed"])
        self.assertFalse(result["yfc_write_allowed"])
        self.assertFalse(result["paid_api_used"])

    def test_historical_1rm_program_diary_technique(self):
        for query, broad, quoted in (
            ("калькулятор 1пм", 363, 261),
            ("жим лежа техника", 2943, 528),
            ("дневник тренировок", 3038, 456),
            ("программа тренировок 3 раза в неделю", 1351, 32),
        ):
            with self.subTest(query=query):
                records = self.load(query)["observations"]
                self.assertEqual([r["search_volume"] for r in records], [broad, quoted])

    def test_no_export_remains_no_data(self):
        self.assertEqual(self.load("приложение для фитнес-тренера")["observations"], [])
        self.assertEqual(self.load("рассчитать рабочий вес")["observations"], [])
        recs = self.load("full body 3 раза в неделю")["observations"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["wordstat_operator"], "broad")
        self.assertEqual(recs[0]["search_volume"], 20)

    def test_owner_data_into_h12_market_brief_with_no_fake_science(self):
        data = input_packet()
        data["theme"] = "market_research"
        data["research_item"] = None
        data["selected_query"] = "калькулятор кбжу"
        data["site_gap"]["clusters"][0]["cluster"] = "калькулятор кбжу"
        data["site_gap"]["clusters"][0]["phrases"] = ["калькулятор кбжу"]
        data["observations"] = self.load("калькулятор кбжу")["observations"]
        packet = build_packet(data)
        self.assertEqual(packet["status"], "READY_FOR_REVIEW")
        self.assertEqual(packet["evidence_kind"], "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED")
        self.assertEqual(len(packet["observations"]), 2)
        self.assertIsNone(packet["research_brief"])
        self.assertFalse(packet["publication_allowed"])
        self.assertIn("quoted_fixed_word_count", packet["markdown"])
        self.assertIn("NOT_PROVIDED", packet["markdown"])
        self.assertFalse(packet["search_metrics_combined"])
        data["site_gap"]["clusters"][0]["covered_by"] = "https://example.org/nutrition"
        self.assertEqual(build_packet(data)["status"], "HOLD")

    def test_stale_historical_owner_evidence_not_fresh(self):
        rec = self.load("калькулятор кбжу", as_of="2027-01-15")
        data = input_packet()
        data.update(theme="market_research", research_item=None,
                    selected_query="калькулятор кбжу", as_of="2027-01-15")
        data["site_gap"]["clusters"][0]["cluster"] = "калькулятор кбжу"
        data["site_gap"]["clusters"][0]["phrases"] = ["калькулятор кбжу"]
        data["observations"] = rec["observations"]
        packet = build_packet(data)
        self.assertEqual(packet["status"], "NO_DATA")
        self.assertTrue(all(item["stale"] for item in packet["observations"]))

    def test_reject_tampered_owner_data_and_invalid_context(self):
        with self.assertRaisesRegex(SeoResearchDenied, "wordstat_source_snapshot_mismatch"):
            import_yfc_wordstat(self.source.replace(b"16127", b"99999", 1),
                                selected_query="калькулятор кбжу", as_of="2026-10-19")
        with self.assertRaisesRegex(SeoResearchDenied, "wordstat_as_of_invalid"):
            self.load("калькулятор кбжу", as_of="2026-01-01")
        with self.assertRaisesRegex(SeoResearchDenied, "wordstat_query_invalid"):
            self.load("<script>")

    def test_cli_output_and_rejection_are_deterministic(self):
        cmd = [sys.executable, "-m", "scripts.hermes_import_yfc_wordstat",
               "--query", "калькулятор кбжу", "--as-of", "2026-10-19"]
        success = subprocess.run(cmd, input=self.source, capture_output=True, timeout=15)
        self.assertEqual(success.returncode, 0, success.stderr)
        obj = json.loads(success.stdout)
        self.assertEqual(len(obj["observations"]), 2)
        self.assertEqual(obj["schema"], "hermes-h12-yfc-wordstat-import-v1")
        for inp in (b"", b"not-csv", self.source + b"attacker"):
            failed = subprocess.run(cmd, input=inp, capture_output=True, timeout=15)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(json.loads(failed.stdout)["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
