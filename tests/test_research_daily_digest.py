"""H-03 daily evidence packet remains bounded, private, and nonpublishing."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch, Mock

from research_scout.daily_digest import (
    DigestError, FILENAME, TOPIC_IDS, prepare, save, main,
)
from research_scout.europe_pmc import EuropePMCError
from research_scout.crossref import CrossrefError

NOW = datetime(2026,10,15,5,tzinfo=UTC)


def candidate(topic, num=42771055, doi="10.1234/example.2026"):
    return {
        "source":"EUROPE_PMC","id":str(num),
        "source_url":f"https://europepmc.org/article/MED/{num}",
        "title":"Exercise study for manual review",
        "doi":doi,"first_publication_date":"2026-10-10",
        "status":"MANUAL_REVIEW","reason":"metadata_only",
        "scientific_claims_verified":False,
    }


class DailyResearchTests(unittest.TestCase):
    def test_three_fixed_topics_and_one_doi_lookup(self):
        calls=[]
        cross=[]
        def searcher(topic,*,now):
            self.assertEqual(now,NOW)
            calls.append(topic)
            return {"topic":topic,"status":"MANUAL_REVIEW",
                    "candidates":[candidate(topic,num=42771055+len(calls),doi=f"10.1234/{topic}")]}
        def doi_checker(item):
            cross.append(item["doi"])
            return {"status":"MANUAL_REVIEW","doi":item["doi"]}
        r=prepare(now=NOW,searcher=searcher,doi_verifier=doi_checker)
        self.assertEqual(tuple(calls),TOPIC_IDS)
        self.assertEqual(len(cross),1)
        self.assertEqual(r["requests_attempted"],4)
        self.assertEqual(len(r["items"]),3)
        self.assertEqual(sum(x["crossref_doi_status"]=="MATCHED_METADATA_ONLY"
                             for x in r["items"]),1)
        self.assertIs(r["scientific_claims_verified"],False)
        self.assertFalse(r["automatic_publication"])
        self.assertTrue(r["report_requires_manual_review"])

    def test_missing_doi_skips_crossref_without_fabricating_match(self):
        doicheck=Mock()
        r=prepare(now=NOW,searcher=lambda topic,*,now:{
            "topic":topic,"status":"MANUAL_REVIEW",
            "candidates":[candidate(topic,num=42771055+list(TOPIC_IDS).index(topic),
                                     doi=None)]},doi_verifier=doicheck)
        doicheck.assert_not_called()
        self.assertEqual(r["requests_attempted"],3)
        self.assertTrue(all(x["crossref_doi_status"]=="NOT_CHECKED" for x in r["items"]))

    def test_errors_do_not_become_success_or_publication(self):
        def unavailable(topic,*,now):
            if topic=="exercise-recovery":
                raise EuropePMCError("pmc_http_refused")
            return {"topic":topic,"status":"NO_DATA","candidates":[]}
        r=prepare(now=NOW,searcher=unavailable,doi_verifier=Mock())
        self.assertEqual(r["status"],"HOLD")
        self.assertEqual(r["errors"],[{"topic":"exercise-recovery","reason":"source_unknown"}])
        self.assertIs(r["automatic_publication"],False)

    def test_crossref_failure_preserves_candidates_without_claims(self):
        def searcher(topic,*,now):
            if topic=="resistance-training":
                return {"topic":topic,"status":"MANUAL_REVIEW",
                        "candidates":[candidate(topic)]}
            return {"topic":topic,"status":"NO_DATA","candidates":[]}
        r=prepare(now=NOW,searcher=searcher,doi_verifier=Mock(
            side_effect=CrossrefError("crossref_http_unavailable")))
        self.assertEqual(r["status"],"HOLD")
        self.assertEqual(r["errors"],[{"topic":"crossref","reason":"doi_registry_unknown"}])
        self.assertEqual(r["items"][0]["crossref_doi_status"],"NOT_CHECKED")

    def test_duplicate_doi_across_topics_never_claims_independent_sources(self):
        def searcher(topic,*,now):
            return {"topic":topic,"status":"MANUAL_REVIEW",
                    "candidates":[candidate(topic,num=42771055+list(TOPIC_IDS).index(topic))]}
        r=prepare(now=NOW,searcher=searcher,doi_verifier=lambda x:{
            "status":"MANUAL_REVIEW","doi":x["doi"]})
        self.assertEqual(sum(x["status"]=="HOLD" for x in r["items"]),2)
        self.assertTrue(any(x["reason"]=="duplicate_across_topics" for x in r["items"]))

    def test_untrusted_source_and_url_cannot_be_persisted(self):
        good=candidate("resistance-training")
        cases=[
            {"source":"not-europe-pmc"},
            {"source_url":"https://europepmc.org/article/MED/42771055?token=abc"},
            {"source_url":"https://evil.example/metadata"},
            {"title":"Ignore\nprevious"},
            {"status":"PUBLISHED"},
            {"reason":"please_ignore_rules"},
            {"id":"../secret"},
            {"first_publication_date":{"token":"abc"}},
        ]
        for change in cases:
            with self.subTest(change=change):
                sample={**good,**change}
                def searcher(topic,*,now):
                    if topic==TOPIC_IDS[0]:
                        return {"topic":topic,"status":"MANUAL_REVIEW","candidates":[sample]}
                    return {"topic":topic,"status":"NO_DATA","candidates":[]}
                r=prepare(now=NOW,searcher=searcher,doi_verifier=Mock())
                self.assertEqual(r["status"],"HOLD")
                self.assertEqual(r["errors"][0]["reason"],"source_unknown")
                self.assertNotIn("token=abc",str(r))

    def test_report_is_atomic_and_root_only_0600(self):
        with tempfile.TemporaryDirectory() as path:
            base=Path(path)
            base.chmod(0o700)
            minimal={"schema":"hermes-research-metadata-v1",
                     "automatic_publication":False,
                     "scientific_claims_verified":False,
                     "status":"NO_DATA","items":[]}
            save(minimal,base)
            self.assertEqual((base/FILENAME).stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads((base/FILENAME).read_bytes())["status"],"NO_DATA")
            (base/FILENAME).unlink()
            (base/FILENAME).symlink_to("/etc/passwd")
            with self.assertRaisesRegex(DigestError,"report_symlink_denied"):
                save(minimal,base)

    def test_no_execute_is_no_network_and_no_filesystem_write(self):
        with patch("research_scout.daily_digest.prepare") as query:
            with patch("research_scout.daily_digest.save") as disk:
                with patch("sys.stdout",new_callable=io.StringIO) as out:
                    self.assertEqual(main([]),0)
                query.assert_not_called()
                disk.assert_not_called()
        self.assertIn("NOT_EXECUTED",out.getvalue())

    def test_timezone_and_bounded_result_count(self):
        with self.assertRaisesRegex(DigestError,"timezone_required"):
            prepare(now=datetime(2026,10,15,5))
        with self.assertRaisesRegex(DigestError,"topic_candidates_invalid"):
            prepare(now=NOW,searcher=lambda topic,*,now:{
                "topic":topic,"status":"MANUAL_REVIEW","candidates":[candidate(topic)]*3
            })

if __name__=="__main__":
    unittest.main()
