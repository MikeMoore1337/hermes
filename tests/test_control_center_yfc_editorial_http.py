"""Hermes I4: adversarial HTTP tests for two independent owner identities."""

from __future__ import annotations

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from control_center.auth import AuthConfig, ORIGIN
from control_center.server import make_handler
from control_center.yfc_editorial import EditorialTransportError

TOKEN = "synthetic_only_YFC_root_access_token_abcdef1234567890"
COOKIE = "hermes_cc_session=owner-session"
ARTICLE_ID = "a" * 32
CONTENT_HASH = "b" * 64


class OAuth:
    def authenticated(self, cookie):
        return cookie == "owner-session"


class EditorialHttpTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            auth_config=AuthConfig(mode="github"), oauth_service=OAuth()
        ))
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def req(self, action, data, *, cookie=COOKIE, origin=ORIGIN, intent="owner-interactive",
            host="hermes.mikemoore.top", method="POST", content_type="application/json",
            extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        payload = json.dumps(data).encode() if not isinstance(data, bytes) else data
        headers = {"Host": host, "Origin": origin, "Content-Type": content_type,
                   "X-Hermes-Editorial-Intent": intent}
        if cookie is not None:
            headers["Cookie"] = cookie
        headers.update(extra or {})
        conn.request(method, "/api/yfc/editorial/" + action, body=payload, headers=headers)
        response = conn.getresponse()
        output = (response.status, response.read())
        conn.close()
        return output

    def test_no_transport_before_both_owner_identity_checks(self):
        with patch("control_center.server.list_yfc_drafts") as downstream:
            self.assertEqual(self.req("list", {"root_token": TOKEN}, cookie=None)[0], 401)
            self.assertEqual(self.req("list", {"root_token": TOKEN}, cookie="bad=x")[0], 401)
            self.assertEqual(
                self.req("list", {"root_token": TOKEN}, origin="https://evil.example")[0], 403
            )
            self.assertEqual(self.req("list", {"root_token": TOKEN}, intent="")[0], 403)
            self.assertEqual(self.req("list", {"root_token": TOKEN},
                                      extra={"Sec-Fetch-Site": "cross-site"})[0], 403)
            self.assertEqual(self.req("list", {"root_token": TOKEN},
                                      host="evil.example")[0], 400)
            self.assertEqual(self.req("list", {"root_token": TOKEN},
                                      content_type="text/plain")[0], 415)
            downstream.assert_not_called()

    def test_read_passes_transient_token_without_echo(self):
        rows = [{"article_id": ARTICLE_ID, "title": "A", "content_hash": CONTENT_HASH,
                 "article_status": "draft", "content_version": 1}]
        with patch("control_center.server.list_yfc_drafts", return_value=rows) as downstream:
            status, raw = self.req("list", {"root_token": TOKEN, "limit": 25})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), rows)
        self.assertNotIn(TOKEN.encode(), raw)
        downstream.assert_called_once_with(TOKEN, limit=25, offset=0)

    def test_detail_requires_exact_id_and_has_no_public_get(self):
        body = {"root_token": TOKEN, "article_id": ARTICLE_ID}
        with patch("control_center.server.get_yfc_draft", return_value={
            "article_id": ARTICLE_ID, "title": "Demo", "lead": "Complete text"
        }) as downstream:
            status, raw = self.req("detail", body)
        self.assertEqual(status, 200)
        self.assertIn(b"Complete text", raw)
        downstream.assert_called_once_with(TOKEN, ARTICLE_ID)
        self.assertEqual(self.req("detail", body, method="GET")[0], 404)

    def test_invalid_body_never_calls_yfc_transport(self):
        with patch("control_center.server.publish_yfc_draft") as downstream:
            self.assertEqual(self.req("publish", b'{"root_token":"foo","root_token":"bar"}')[0], 400)
            self.assertEqual(self.req("publish", {"root_token": TOKEN, "article_id": ARTICLE_ID,
                "content_hash": CONTENT_HASH,"content_version":1,
                "owner_confirmed":True,"extra":"abc"})[0], 400)
            self.assertEqual(self.req("publish", b"{" + b"x" * 10000 + b"}")[0], 413)
            downstream.assert_not_called()

    def test_explicit_exact_revision_confirmation_is_single_publish(self):
        req = {"root_token": TOKEN, "article_id": ARTICLE_ID, "content_hash": CONTENT_HASH,
               "content_version": 1, "owner_confirmed": True}
        receipt = {"article_id": ARTICLE_ID, "content_version": 1,
                   "article_status": "published", "scientific_verification": "not_attested"}
        with patch("control_center.server.publish_yfc_draft", return_value=receipt) as call:
            status, raw = self.req("publish", req)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), receipt)
        self.assertNotIn(TOKEN.encode(), raw)
        call.assert_called_once_with(
            TOKEN, article_id=ARTICLE_ID, content_hash=CONTENT_HASH,
            content_version=1, owner_confirmed=True
        )
        self.assertEqual(self.req("publish", req, cookie=None)[0], 401)

    def test_downstream_fail_closed_and_sanitized(self):
        req = {"root_token": TOKEN,"article_id":ARTICLE_ID,
               "content_hash":CONTENT_HASH,"content_version":1,"owner_confirmed":True}
        for code, status in [
            ("yfc_root_auth_required",401),
            ("yfc_article_revision_conflict",409),
            ("owner_confirmation_required",422),
            ("yfc_request_unavailable",502),
        ]:
            with self.subTest(code=code):
                with patch("control_center.server.publish_yfc_draft",
                           side_effect=EditorialTransportError(code)):
                    result, raw = self.req("publish", req)
                self.assertEqual(result, status)
                self.assertNotIn(TOKEN.encode(), raw)
                self.assertEqual(json.loads(raw)["error"], code)

    def test_proxy_mode_cannot_read_or_publish_any_article(self):
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            auth_config=AuthConfig(mode="proxy")
        ))
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=3)
            conn.request("POST", "/api/yfc/editorial/publish",
                         body=b"{}", headers={"Host": "hermes.mikemoore.top",
                                              "Origin": ORIGIN})
            res = conn.getresponse()
            self.assertEqual(res.status, 403)
            conn.close()
        finally:
            proxy.shutdown();proxy.server_close();worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
