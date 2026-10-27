"""Article integrity is a mandatory HOLD on correction/withdrawal, not science proof."""
from __future__ import annotations

import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

from research_scout import article_integrity as article

PMID="42771055"
PMCID="PMC13639859"
DOI="10.1007/s00520-026-11251-3"


def packet(*, source="MED", identifier=PMID, pmid=PMID, pmcid="PMC13597563",
           doi=DOI, notices=None):
    result={"source":source,"id":identifier,"pmid":pmid,"pmcid":pmcid,
            "doi":doi,"title":"UNTRUSTED title containing SECRET"} 
    if notices is not None:
        result["commentCorrectionList"]={"commentCorrection":notices}
    return json.dumps({"version":"6.9","hitCount":1,"result":result}).encode()


def notice(kind="Erratum in"):
    return {"id":"42825937","orderIn":1,
            "reference":"PRIVATE_UNTRUSTED_REFERENCE",
            "source":"MED","type":kind}


class ArticleIntegrityTests(unittest.TestCase):
    def test_actual_official_correction_is_hold_no_private_metadata(self):
        result=article.inspect("MED",PMID,
            transport=lambda *args:packet(notices=[notice()]))
        self.assertEqual(result["status"],"HOLD")
        self.assertEqual(result["notice_codes"],["CORRECTION_NOTICE"])
        self.assertEqual(result["doi"],DOI)
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["automatic_publication"])
        self.assertFalse(result["authoritative_notice_clearance"])
        self.assertNotIn("PRIVATE_UNTRUSTED_REFERENCE",str(result))
        self.assertNotIn("UNTRUSTED title",str(result))

    def test_retraction_concern_and_unknown_notice_never_permit_review_without_hold(self):
        for kind, expected in (
            ("Retraction in","RETRACTION_OR_WITHDRAWAL_NOTICE"),
            ("Retraction of","RETRACTION_OR_WITHDRAWAL_NOTICE"),
            ("Expression of concern in","EXPRESSION_OF_CONCERN"),
            ("New notice added by upstream","OTHER_OR_UNKNOWN_NOTICE"),
        ):
            with self.subTest(kind=kind):
                result=article.parse(packet(notices=[notice(kind)]),
                                     source="MED",identifier=PMID)
                self.assertEqual(result["status"],"HOLD")
                self.assertIn(expected,result["notice_codes"])

    def test_absence_of_notices_does_not_assert_no_erratum(self):
        r=article.parse(packet(),source="MED",identifier=PMID)
        self.assertEqual(r["status"],"MANUAL_REVIEW")
        self.assertEqual(r["notice_state"],article.ABSENT)
        self.assertFalse(r["authoritative_notice_clearance"])

    def test_explicit_null_notice_container_cannot_promote_to_manual_review(self):
        document = json.loads(packet())
        document["result"]["commentCorrectionList"] = None
        with self.assertRaisesRegex(
            article.ArticleIntegrityError, "article_notice_schema_invalid"
        ):
            article.parse(json.dumps(document).encode(), source="MED", identifier=PMID)
        # Missing key is allowed as incomplete metadata, never notice clearance.
        missing = article.parse(packet(), source="MED", identifier=PMID)
        self.assertEqual(missing["notice_state"], article.ABSENT)
        self.assertFalse(missing["authoritative_notice_clearance"])

    def test_missing_pmc_doi_is_hold_even_if_record_exists(self):
        r=article.parse(packet(source="PMC",identifier=PMCID,pmid=None,
                               pmcid=PMCID,doi=None),
                        source="PMC",identifier=PMCID)
        self.assertEqual(r["status"],"HOLD")
        self.assertEqual(r["doi_state"],"MISSING_IN_THIS_METADATA")
        self.assertIsNone(r["pmid"])
        self.assertIsNone(r["doi"])

    def test_pmc_lookup_canonical_med_pmid_alias_keeps_pmcid_binding(self):
        # An official PMC lookup may use a MED/PMID record as its
        # canonical citation identity. Both identifiers must agree.
        raw = packet(source="MED", identifier=PMID, pmid=PMID,
                     pmcid=PMCID, doi=DOI)
        result = article.parse(raw, source="PMC", identifier=PMCID)
        self.assertEqual(result["article_source"], "PMC")
        self.assertEqual(result["article_identifier"], PMCID)
        self.assertEqual(result["pmcid"], PMCID)
        self.assertEqual(result["pmid"], PMID)
        self.assertEqual(result["status"], "MANUAL_REVIEW")
        self.assertFalse(result["authoritative_notice_clearance"])
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["automatic_publication"])

        with_notice = packet(source="MED", identifier=PMID, pmid=PMID,
                             pmcid=PMCID, notices=[notice("Retraction in")])
        rejected = article.parse(with_notice, source="PMC", identifier=PMCID)
        self.assertEqual(rejected["status"], "HOLD")
        self.assertEqual(rejected["notice_codes"],
                         ["RETRACTION_OR_WITHDRAWAL_NOTICE"])

    def test_pmc_canonical_alias_cannot_mask_mismatch_or_spoofed_record(self):
        invalid = (
            (packet(source="MED", identifier=PMID, pmid=PMID, pmcid="PMC99999"),
             "article_pmcid_mismatch"),
            (packet(source="MED", identifier="99999999", pmid=PMID, pmcid=PMCID),
             "article_identity_mismatch"),
            (packet(source="MED", identifier=PMID, pmid=None, pmcid=PMCID),
             "article_identity_mismatch"),
            (packet(source="MED", identifier="notnumeric", pmid="notnumeric", pmcid=PMCID),
             "article_related_pmid_invalid"),
            (packet(source="PPR", identifier=PMID, pmid=PMID, pmcid=PMCID),
             "article_identity_mismatch"),
            (packet(source="PMC", identifier=PMID, pmid=PMID, pmcid=PMCID),
             "article_identity_mismatch"),
            (packet(source="PMC", identifier=PMCID, pmid=PMID, pmcid="PMC99999"),
             "article_pmcid_mismatch"),
        )
        for raw, expected in invalid:
            with self.subTest(expected=expected, raw=raw[:60]):
                with self.assertRaisesRegex(article.ArticleIntegrityError, expected):
                    article.parse(raw, source="PMC", identifier=PMCID)

    def test_identity_mismatch_or_bad_pmid_fails_closed(self):
        for data, src, ident, error in (
            (packet(identifier="42771056"),"MED",PMID,"article_identity_mismatch"),
            (packet(pmid="42771056"),"MED",PMID,"article_pmid_mismatch"),
            (packet(pmcid="not-an-id"),"MED",PMID,"article_related_pmcid_invalid"),
            (packet(doi="file:///etc/passwd"),"MED",PMID,"article_doi_invalid"),
            (packet(source="PMC",identifier=PMCID,pmid=None,pmcid="PMC99999"),
             "PMC",PMCID,"article_pmcid_mismatch"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(article.ArticleIntegrityError,error):
                    article.parse(data,source=src,identifier=ident)

    def test_reject_untrusted_identifiers_before_network(self):
        call=Mock()
        for src,identifier in (
            ("MED","../../etc/passwd"),("MED","PMC13639859"),
            ("PMC",PMID),("PMC","https://internal/secret"),
            ("WEB",PMID),("MED",True),("MED","0"),("MED","42771055?format=xml"),
        ):
            with self.subTest(src=src,identifier=str(identifier)):
                with self.assertRaisesRegex(article.ArticleIntegrityError,
                                             "article_identifier_not_allowlisted"):
                    article.inspect(src,identifier,transport=call)
        call.assert_not_called()

    def test_json_poison_and_bad_status_are_rejected(self):
        bad=[
            (b'{"hitCount":1,"hitCount":1}',"article_duplicate_json_key"),
            (b'{"hitCount":0,"result":{}}',"article_schema_invalid"),
            (b'{"hitCount":true,"result":{}}',"article_schema_invalid"),
            (b'{"hitCount":1,"result":[]}',"article_schema_invalid"),
            (packet(notices=[{"type":None}]),"article_notice_type_invalid"),
            (packet(notices=[notice()]*13),"article_notice_list_invalid"),
            (packet(notices=["x"]),"article_notice_item_invalid"),
            (b'not json',"article_json_invalid"),
            (b'x'*48001,"article_response_invalid"),
        ]
        for value,reason in bad:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(article.ArticleIntegrityError,reason):
                    article.parse(value,source="MED",identifier=PMID)

    def test_exact_pinned_public_https_one_get_no_redirect(self):
        conn=Mock()
        response=Mock()
        response.status=200
        response.getheader.side_effect=lambda k, default="":(
            "application/json" if k=="Content-Type"
            else "identity" if k=="Content-Encoding"
            else "2048" if k=="Content-Length" else default
        )
        response.read.return_value=packet(notices=[notice()])
        conn.getresponse.return_value=response
        with patch.object(article,"resolve_public",return_value="1.1.1.1"):
            with patch.object(article,"PinnedHTTPS",return_value=conn):
                data=article.fetch("MED",PMID)
        self.assertEqual(data,packet(notices=[notice()]))
        self.assertEqual(conn.request.call_count,1)
        request=conn.request.call_args
        self.assertEqual(request.args[:2],("GET",
            "/europepmc/webservices/rest/article/MED/42771055?format=json&resultType=core"))
        self.assertEqual(request.kwargs["headers"]["Host"],"www.ebi.ac.uk")
        conn.close.assert_called_once()

    def test_http_404_or_302_does_not_follow_or_clear_notice(self):
        for status in (302,404,429,500):
            conn=Mock()
            res=Mock(status=status)
            conn.getresponse.return_value=res
            with patch.object(article,"resolve_public",return_value="1.1.1.1"):
                with patch.object(article,"PinnedHTTPS",return_value=conn):
                    with self.assertRaisesRegex(article.ArticleIntegrityError,
                                                 "article_http_unavailable"):
                        article.fetch("MED",PMID)
            self.assertEqual(conn.request.call_count,1)

    def test_cli_requires_execute_and_does_not_print_raw_article(self):
        with patch.object(article,"inspect") as call:
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(article.main(["--source","MED","--id",PMID]),0)
            call.assert_not_called()
        self.assertIn("NOT_EXECUTED",out.getvalue())
        with patch.object(article,"inspect",side_effect=article.ArticleIntegrityError(
                "article_http_unavailable")):
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(article.main(["--execute","--source","MED","--id",PMID]),2)
            self.assertNotIn("PRIVATE_UNTRUSTED_REFERENCE",out.getvalue())


if __name__ == "__main__":
    unittest.main()
