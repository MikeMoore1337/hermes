"""H-03 one extra official article lookup per daily run; no false clean status."""
from __future__ import annotations

import io
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from research_scout.daily_digest import DigestError, prepare, save, TOPIC_IDS, main
from research_scout.article_integrity import ArticleIntegrityError

NOW = datetime(2026, 10, 15, 5, tzinfo=UTC)
PMID = "42771055"
DOI = "10.1007/s00520-026-11251-3"

def article(*, status="HOLD", notice_state="REVIEW_REQUIRED",
            codes=None, doi=DOI, source="MED", identifier=PMID):
    return {
        "status":status,"notice_state":notice_state,
        "notice_codes": codes if codes is not None else ["CORRECTION_NOTICE"],
        "doi":doi,"article_source":source,"article_identifier":identifier,
        "scientific_claims_verified":False,"automatic_publication":False,
    }

def finder(topic, *, now):
    if topic != TOPIC_IDS[0]:
        return {"status":"NO_DATA","topic":topic,"candidates":[]}
    return {"status":"MANUAL_REVIEW","topic":topic,"candidates":[{
        "source":"EUROPE_PMC", "id":PMID, "doi":DOI,
        "source_url":"https://europepmc.org/article/MED/"+PMID,
        "first_publication_date":"2026-10-01",
        "status":"MANUAL_REVIEW", "reason":"metadata_only",
        "scientific_claims_verified":False, "title":"Real science candidate",
    }]}

def crossref(_):
    return {"status":"MANUAL_REVIEW","doi":DOI}

class DailyIntegrityGateTests(unittest.TestCase):
    def test_actual_correction_is_hold_with_five_calls_and_no_publication(self):
        call=Mock(return_value=article())
        result=prepare(now=NOW,searcher=finder,doi_verifier=crossref,
                       integrity_verifier=call)
        call.assert_called_once_with("MED",PMID)
        self.assertEqual(result["requests_attempted"],5)
        self.assertEqual(result["status"],"HOLD")
        self.assertEqual(result["items"][0]["article_notice_codes"],["CORRECTION_NOTICE"])
        self.assertEqual(result["items"][0]["article_notice_state"],"REVIEW_REQUIRED")
        self.assertEqual(result["items"][0]["reason"],"integrity_hold")
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["automatic_publication"])
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            save(result,Path(directory))
            import json
            persisted=json.loads((Path(directory)/"latest-citations.json").read_bytes())
            self.assertEqual(persisted["items"][0]["reason"],"integrity_hold")

    def test_missing_article_metadata_fails_closed_without_publication(self):
        for verifier in (
            Mock(side_effect=ArticleIntegrityError("article_http_unavailable")),
            Mock(return_value=article(source="PMC")),
            Mock(return_value=article(identifier="42771056")),
            Mock(return_value=article(status="MANUAL_REVIEW",
                                     notice_state="NOT_REPORTED_IN_THIS_METADATA",
                                     codes=[],doi="10.9999/different")),
            Mock(return_value=None),
        ):
            with self.subTest(case=str(verifier.side_effect or verifier.return_value)[:30]):
                report=prepare(now=NOW,searcher=finder,doi_verifier=crossref,
                               integrity_verifier=verifier)
                self.assertEqual(report["status"],"HOLD")
                self.assertEqual(report["requests_attempted"],5)
                row=report["items"][0]
                self.assertEqual(row["status"],"HOLD")
                self.assertIn(row["reason"],("integrity_hold","integrity_unknown"))
                self.assertFalse(report["automatic_publication"])

    def test_unavailable_network_marks_explicit_error_and_not_fake_notice_clearance(self):
        outcome=prepare(now=NOW,searcher=finder,doi_verifier=crossref,
                        integrity_verifier=Mock(side_effect=ArticleIntegrityError("article_http_unavailable")))
        self.assertEqual(outcome["items"][0]["article_notice_state"],"UNAVAILABLE")
        self.assertEqual(outcome["errors"],
                         [{"topic":"article-integrity","reason":"integrity_unavailable"}])

    def test_no_doi_means_zero_integrity_and_crossref_requests(self):
        def no_doi(topic,*,now):
            r=finder(topic,now=now)
            if r["candidates"]:
                r["candidates"][0]["doi"]=None
            return r
        one,two=Mock(),Mock()
        report=prepare(now=NOW,searcher=no_doi,doi_verifier=one,integrity_verifier=two)
        one.assert_not_called()
        two.assert_not_called()
        self.assertEqual(report["requests_attempted"],3)
        self.assertEqual(report["items"][0]["article_notice_state"],"NOT_CHECKED")

    def test_metadata_without_notice_is_not_verified_clearance(self):
        def verifier(source,identifier):
            return article(status="MANUAL_REVIEW",
                notice_state="NOT_REPORTED_IN_THIS_METADATA",codes=[])
        report=prepare(now=NOW,searcher=finder,doi_verifier=crossref,
                       integrity_verifier=verifier)
        self.assertEqual(report["status"],"MANUAL_REVIEW")
        self.assertEqual(report["items"][0]["article_notice_state"],
                         "NOT_REPORTED_IN_THIS_METADATA")
        self.assertFalse(report["scientific_claims_verified"])

    def test_only_one_candidate_has_an_integrity_lookup(self):
        calls=[]
        def many(topic,*,now):
            d=finder(topic,now=now)
            if d["candidates"]:
                second={**d["candidates"][0],
                        "id":"42771056",
                        "source_url":"https://europepmc.org/article/MED/42771056",
                        "doi":"10.1234/other"}
                d["candidates"].append(second)
            return d
        result=prepare(now=NOW,searcher=many,doi_verifier=crossref,
                      integrity_verifier=lambda src,ident:(calls.append((src,ident)),article())[1])
        self.assertEqual(calls,[("MED",PMID)])
        self.assertEqual(result["requests_attempted"],5)
        self.assertEqual(result["items"][1]["article_notice_state"],"NOT_CHECKED")

    def test_persisted_report_cannot_launder_uncleared_notice(self):
        report=prepare(now=NOW,searcher=finder,doi_verifier=crossref,
                       integrity_verifier=lambda *_:article())
        report["items"][0]["status"]="MANUAL_REVIEW"
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);path.chmod(0o700)
            with self.assertRaisesRegex(DigestError,"report_article_not_on_hold"):
                save(report,path)

    def test_invalid_doi_is_refused_before_crossref_or_article_requests(self):
        def poisoned(topic, *, now):
            result=finder(topic, now=now)
            if result["candidates"]:
                result["candidates"][0]["doi"]="file:///etc/shadow"
            return result
        cross=Mock()
        article_check=Mock()
        report=prepare(now=NOW,searcher=poisoned,doi_verifier=cross,
                       integrity_verifier=article_check)
        cross.assert_not_called()
        article_check.assert_not_called()
        self.assertEqual(report["status"],"HOLD")
        self.assertEqual(report["errors"][0]["reason"],"source_unknown")
        self.assertEqual(report["requests_attempted"],3)

    def test_any_corrected_article_holds_whole_packet_even_with_healthy_neighbors(self):
        def mixed(topic, *, now):
            r=finder(topic, now=now)
            if topic == TOPIC_IDS[1]:
                r={"topic":topic,"status":"MANUAL_REVIEW","candidates":[{
                    "source":"EUROPE_PMC","id":"42733310",
                    "source_url":"https://europepmc.org/article/MED/42733310",
                    "doi":"10.1002/ejsc.70246","first_publication_date":"2026-10-01",
                    "title":"Second study unaffected", "status":"MANUAL_REVIEW",
                    "reason":"metadata_only","scientific_claims_verified":False,
                }]}
            return r
        r=prepare(now=NOW,searcher=mixed,doi_verifier=crossref,
                  integrity_verifier=lambda *_:article())
        self.assertEqual(r["status"],"HOLD")
        self.assertEqual(r["errors"],[])
        self.assertEqual(r["items"][0]["reason"],"integrity_hold")
        self.assertEqual(r["items"][1]["status"],"MANUAL_REVIEW")
        self.assertEqual(r["items"][1]["article_notice_state"],"NOT_CHECKED")

    def test_pmc_without_doi_is_hold_not_a_reviewable_citation(self):
        def pmc(topic, *, now):
            r=finder(topic, now=now)
            if r["candidates"]:
                r["candidates"][0]["id"]="PMC13639859"
                r["candidates"][0]["source_url"]="https://europepmc.org/articles/PMC13639859"
                r["candidates"][0]["doi"]=None
            return r
        lookup,integrity=Mock(),Mock()
        r=prepare(now=NOW,searcher=pmc,doi_verifier=lookup,
                  integrity_verifier=integrity)
        self.assertEqual(r["status"],"HOLD")
        self.assertEqual(r["items"][0]["reason"],"doi_missing")
        self.assertEqual(r["items"][0]["article_notice_state"],"NOT_CHECKED")
        lookup.assert_not_called()
        integrity.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);path.chmod(0o700)
            save(r,path)

    def test_existing_callers_remain_offline_without_integrity_opt_in(self):
        network=Mock()
        report=prepare(now=NOW,searcher=finder,doi_verifier=crossref)
        network.assert_not_called()
        self.assertEqual(report["requests_attempted"],4)
        self.assertEqual(report["items"][0]["article_notice_state"],"NOT_CHECKED")

    def test_production_entrypoint_explicitly_passes_single_integrity_verifier(self):
        with patch("research_scout.daily_digest.prepare") as prepare_call:
            with patch("research_scout.daily_digest.save"):
                prepare_call.return_value={
                    "status":"MANUAL_REVIEW","items":[],"errors":[],
                    "requests_attempted":3,
                }
                with patch("sys.stdout",new_callable=io.StringIO):
                    self.assertEqual(main(["--execute"]),0)
        self.assertEqual(prepare_call.call_count,1)
        self.assertEqual(prepare_call.call_args.kwargs["integrity_verifier"].__name__,
                         "inspect")


if __name__=="__main__":
    unittest.main()
