"""Offline test of Hermes Control Center YFC owner-only draft transport."""

from __future__ import annotations

import json
import unittest
from urllib.error import HTTPError

from control_center.yfc_editorial import (
    EditorialTransportError,
    YFC_ORIGIN,
    get_draft,
    list_drafts,
    publish_existing_draft,
)

ARTICLE_ID = "a" * 32
CONTENT_HASH = "f" * 64
TOKEN = "synthetic_test_only_root_bearer_token_1234567890"


class Reply:
    status = 200

    def __init__(self, data):
        self.data = json.dumps(data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, n):
        return self.data[:n]


class Transport:
    def __init__(self, reply, status=None):
        self.reply = reply
        self.status = status
        self.calls = []

    def open(self, req, timeout):
        self.calls.append((req, timeout))
        if self.status is not None:
            raise HTTPError(req.full_url, self.status, "FORBIDDEN", {}, None)
        return Reply(self.reply)


class YfcOwnerEditorialTests(unittest.TestCase):
    def test_list_is_root_only_read_and_strict_origin(self):
        response = [{
            "article_id": ARTICLE_ID,
            "article_status": "draft",
            "title": "Demo",
        }]
        fake = Transport(response)
        result = list_drafts(TOKEN, opener=fake)
        self.assertEqual(result, response)
        self.assertEqual(len(fake.calls), 1)
        req, timeout = fake.calls[0]
        self.assertEqual(req.get_method(), "GET")
        self.assertTrue(req.full_url.startswith(YFC_ORIGIN + "/api/v1/admin/articles/drafts?"))
        self.assertEqual(timeout, 15)
        self.assertEqual(req.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertNotIn(TOKEN, str(result))
        with self.assertRaisesRegex(EditorialTransportError, "yfc_root_token_required"):
            list_drafts("BAD\nHEADER", opener=fake)
        with self.assertRaisesRegex(EditorialTransportError, "yfc_limit_invalid"):
            list_drafts(TOKEN, limit=500, opener=fake)

    def test_get_draft_returns_source_matrix_with_no_false_signoff(self):
        fake = Transport({
            "article_id": ARTICLE_ID,
            "article_status": "draft",
            "content_hash": CONTENT_HASH,
            "content_version": 1,
            "sources": [{"source_id": "s_01", "url": "https://example.org"}],
            "claim_source_matrix": [{"claim_id": "c_01", "review_status": "pending"}],
            "review_blockers": ["claim_source_matrix_not_fully_verified"],
        })
        data = get_draft(TOKEN, ARTICLE_ID, opener=fake)
        self.assertEqual(data["claim_source_matrix"][0]["review_status"], "pending")
        self.assertEqual(fake.calls[0][0].get_method(), "GET")
        with self.assertRaisesRegex(EditorialTransportError, "yfc_article_id_invalid"):
            get_draft(TOKEN, "../../credentials", opener=fake)
        self.assertEqual(len(fake.calls), 1)

    def test_publication_rejected_without_explicit_owner_click(self):
        fake = Transport({})
        with self.assertRaisesRegex(EditorialTransportError, "owner_confirmation_required"):
            publish_existing_draft(
                TOKEN, article_id=ARTICLE_ID, content_hash=CONTENT_HASH,
                content_version=1, owner_confirmed=False, opener=fake,
            )
        self.assertEqual(fake.calls, [])

    def test_exact_owner_consent_posts_only_to_pinned_yfc_route(self):
        response = {
            "article_id": ARTICLE_ID,
            "article_status": "published",
            "content_version": 1,
            "canonical_url": "https://your-fitness-coach.ru/articles/demonstratsiya",
            "editorial_decision": "root_owner_publication",
            "scientific_verification": "not_attested",
        }
        fake = Transport(response)
        receipt = publish_existing_draft(
            TOKEN, article_id=ARTICLE_ID, content_hash=CONTENT_HASH,
            content_version=1, owner_confirmed=True, opener=fake,
        )
        self.assertEqual(receipt, response)
        self.assertNotIn(TOKEN, json.dumps(receipt))
        req, _ = fake.calls[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, YFC_ORIGIN + "/api/v1/admin/articles/drafts/publish")
        body = json.loads(req.data)
        self.assertEqual(body["article_id"], ARTICLE_ID)
        self.assertEqual(body["expected_content_hash"], CONTENT_HASH)
        self.assertTrue(body["confirm_exact_revision"])
        self.assertTrue(body["acknowledge_unverified_evidence"])
        self.assertNotIn(TOKEN, json.dumps(body))

    def test_stale_conflict_and_invalid_auth_are_sanitized(self):
        for status, expected in [
            (401, "yfc_root_auth_required"), (403, "yfc_root_auth_required"),
            (409, "yfc_article_revision_conflict"),
            (404, "yfc_article_not_publishable"),
        ]:
            with self.subTest(status=status):
                fake = Transport(None, status=status)
                with self.assertRaisesRegex(EditorialTransportError, expected) as cm:
                    publish_existing_draft(
                        TOKEN, article_id=ARTICLE_ID, content_hash=CONTENT_HASH,
                        content_version=1, owner_confirmed=True, opener=fake,
                    )
                self.assertNotIn(TOKEN, str(cm.exception))

    def test_bad_receipt_is_never_considered_published(self):
        fake = Transport({
            "article_id": ARTICLE_ID,
            "article_status": "draft",
            "content_version": 1,
            "canonical_url": "https://attacker.example/articles/foo",
            "editorial_decision": "root_owner_publication",
            "scientific_verification": "not_attested",
        })
        with self.assertRaisesRegex(EditorialTransportError, "yfc_publication_receipt_invalid"):
            publish_existing_draft(
                TOKEN, article_id=ARTICLE_ID, content_hash=CONTENT_HASH,
                content_version=1, owner_confirmed=True, opener=fake,
            )


if __name__ == "__main__":
    unittest.main()
