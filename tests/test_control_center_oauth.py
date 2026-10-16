"""Offline owner-only OAuth negative tests: no live GitHub or other network."""
from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from http.server import ThreadingHTTPServer

from control_center.auth import (
    AuthConfig, AuthError, GitHubProvider, OAuthService, ORIGIN,
    STATE_COOKIE, SESSION_COOKIE, MAX_PENDING, SESSION_TTL, STATE_TTL,
    parse_cookie,
)
from control_center.server import make_handler


class FakeProvider:
    def __init__(self, user_id=42142321):
        self.user_id = user_id
        self.calls = 0

    def identify(self, config, code, verifier):
        self.calls += 1
        assert len(verifier) >= 43
        return self.user_id


CONFIG = AuthConfig("github", ORIGIN, "Ov23abcdefghijk", "test-client-secret-long-enough",
                    42142321, b"test signing secret longer than 32 characters")


class ConfigurationTests(unittest.TestCase):
    def test_default_proxy_is_unchanged(self):
        self.assertEqual(AuthConfig.from_env({}).mode, "proxy")

    def test_github_fails_closed_without_all_secrets(self):
        for values in (
            {"HERMES_CC_AUTH_MODE": "github"},
            {"HERMES_CC_AUTH_MODE": "unknown"},
            {"HERMES_CC_AUTH_MODE": "github", "HERMES_CC_PUBLIC_ORIGIN": "http://hermes.mikemoore.top"},
        ):
            with self.subTest(values=values), self.assertRaises(AuthError):
                AuthConfig.from_env(values)

    def test_strict_owner_and_origin(self):
        values = {
            "HERMES_CC_AUTH_MODE": "github",
            "HERMES_CC_PUBLIC_ORIGIN": ORIGIN,
            "HERMES_CC_GITHUB_CLIENT_ID": "Ov23abcdefghijk",
            "HERMES_CC_ALLOWED_GITHUB_ID": "42142321",
            "HERMES_CC_SESSION_SECRET": "random-signature-secret-more-than-32-bytes",
        }
        self.assertEqual(AuthConfig.from_env(values).owner_id, 42142321)
        for key, bad in (
            ("HERMES_CC_ALLOWED_GITHUB_ID", "MikeMoore1337"),
            ("HERMES_CC_ALLOWED_GITHUB_ID", "0"),
            ("HERMES_CC_SESSION_SECRET", "weak"),
            ("HERMES_CC_PUBLIC_ORIGIN", "https://evil.invalid"),
            ("HERMES_CC_GITHUB_CLIENT_SECRET", "incorrectly-present-in-web-env"),
            ("HERMES_CC_OAUTH_BROKER_SOCKET", "/tmp/attacker.sock"),
        ):
            with self.subTest(key=key), self.assertRaises(AuthError):
                AuthConfig.from_env({**values, key: bad})


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.provider = FakeProvider()
        self.auth = OAuthService(CONFIG, provider=self.provider, clock=lambda: self.now[0])

    def login(self):
        url, state = self.auth.begin()
        self.assertEqual(urlsplit(url).netloc, "github.com")
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertNotIn("scope", query)
        self.assertEqual(query["redirect_uri"], [ORIGIN + "/auth/github/callback"])
        return self.auth.finish(code="code-token-12345", state=state, cookie_state=state)

    def test_session_signed_revoked_and_expires(self):
        cookie = self.login()
        self.assertTrue(self.auth.authenticated(cookie))
        self.assertFalse(self.auth.authenticated(cookie + "x"))
        self.assertFalse(self.auth.authenticated(cookie.replace(".", "..")))
        self.assertFalse(self.auth.authenticated(""))
        self.auth.revoke(cookie)
        self.assertFalse(self.auth.authenticated(cookie))
        second = self.login()
        self.now[0] += SESSION_TTL + 1
        self.assertFalse(self.auth.authenticated(second))

    def test_replay_and_cross_browser_state_are_rejected(self):
        _, state = self.auth.begin()
        with self.assertRaises(AuthError):
            self.auth.finish(code="code-token-12345", state=state, cookie_state="another-browser")
        cookie = self.auth.finish(code="code-token-12345", state=state, cookie_state=state)
        self.assertTrue(self.auth.authenticated(cookie))
        with self.assertRaises(AuthError):
            self.auth.finish(code="code-token-12345", state=state, cookie_state=state)

    def test_denied_id_cannot_get_session(self):
        self.provider.user_id = 123456789
        _, state = self.auth.begin()
        with self.assertRaises(AuthError):
            self.auth.finish(code="code-token-12345", state=state, cookie_state=state)
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(len(self.auth._sessions), 0)

    def test_expired_state_and_invalid_code(self):
        _, state = self.auth.begin()
        self.now[0] += STATE_TTL + 1
        with self.assertRaises(AuthError):
            self.auth.finish(code="code-token-12345", state=state, cookie_state=state)
        _, state = self.auth.begin()
        for invalid in ("", "not valid!", "a" * 513):
            with self.assertRaises(AuthError):
                self.auth.finish(code=invalid, state=state, cookie_state=state)

    def test_bounded_pending_state(self):
        for _ in range(MAX_PENDING):
            self.auth.begin()
        with self.assertRaises(AuthError):
            self.auth.begin()
        self.now[0] += STATE_TTL + 1
        self.auth.begin()

    def test_sensitive_cookie_duplicates_are_not_trusted(self):
        # A duplicated cookie must never elevate a session without a valid signed value.
        self.assertFalse(self.auth.authenticated(parse_cookie(
            "hermes_cc_session=attacker; hermes_cc_session=also-attacker", SESSION_COOKIE)))


class ProviderTests(unittest.TestCase):
    def test_github_code_exchange_uses_s256_verifier_and_minimal_scope(self):
        seen = []
        def fake_fetch(request):
            seen.append(request)
            if len(seen) == 1:
                self.assertEqual(request.full_url, "https://github.com/login/oauth/access_token")
                body = request.data.decode()
                self.assertIn("code_verifier=", body)
                self.assertIn("redirect_uri=https%3A%2F%2Fhermes.mikemoore.top", body)
                return {"access_token": "gho_fake_token_not_sent", "token_type": "bearer", "scope": ""}
            self.assertEqual(request.full_url, "https://api.github.com/user")
            self.assertTrue(request.get_header("Authorization").startswith("Bearer "))
            return {"id": CONFIG.owner_id}
        with patch("control_center.auth._fetch_json", side_effect=fake_fetch):
            self.assertEqual(GitHubProvider().identify(CONFIG, "code-token-12345", "v" * 50),
                             CONFIG.owner_id)
        self.assertEqual(len(seen), 2)

    def test_broad_scope_is_rejected_before_identity_lookup(self):
        with patch("control_center.auth._fetch_json",
                   return_value={"access_token": "gho_bad_scoped_token",
                                 "token_type": "bearer", "scope": "repo"}) as call:
            with self.assertRaises(AuthError):
                GitHubProvider().identify(CONFIG, "code-token-12345", "v" * 50)
        self.assertEqual(call.call_count, 1)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.snapshot = Path(self.temp.name) / "overview.json"
        from datetime import datetime, timezone
        self.snapshot.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "services": [{"id": "ops", "state": "active", "name": "Ops Watch",
                          "unit": "hermes-ops-watch.timer"}],
        }))
        self.provider = FakeProvider()
        self.oauth = OAuthService(CONFIG, provider=self.provider)
        handler = make_handler(self.snapshot, auth_config=CONFIG, oauth_service=self.oauth)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def req(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        base = {"Host": "hermes.mikemoore.top"}
        base.update(headers or {})
        conn.request(method, path, headers=base)
        response = conn.getresponse()
        result = response.status, response.getheaders(), response.read()
        conn.close()
        return result

    def test_api_auth_and_owner_signin_logout(self):
        st, h, body = self.req("GET", "/api/auth/session")
        self.assertEqual((st, json.loads(body)["authenticated"]), (200, False))
        self.assertEqual(self.req("GET", "/api/overview")[0], 401)
        self.assertEqual(self.req("GET", "/")[0], 200)
        st, h, _ = self.req("GET", "/auth/github/start")
        self.assertEqual(st, 303)
        headers = dict(h)
        self.assertIn("https://github.com/login/oauth/authorize?", headers["Location"])
        self.assertIn("HttpOnly; Secure; SameSite=Lax", headers["Set-Cookie"])
        state = parse_qs(urlsplit(headers["Location"]).query)["state"][0]
        st, h, _ = self.req("GET", "/auth/github/callback?code=code-token-12345&state=" + state,
                             {"Cookie": STATE_COOKIE + "=" + state})
        self.assertEqual(st, 303)
        cookies = [v for k,v in h if k.lower()=="set-cookie"]
        session_cookie = next(x for x in cookies if x.startswith(SESSION_COOKIE + "="))
        token = session_cookie.split(";", 1)[0]
        self.assertEqual(self.req("GET", "/api/overview", {"Cookie": token})[0], 200)
        self.assertTrue(json.loads(self.req("GET", "/api/auth/session",
                                           {"Cookie": token})[2])["authenticated"])
        self.assertEqual(self.req("POST", "/auth/logout",
                                  {"Origin": ORIGIN, "Cookie": token})[0], 204)
        self.assertEqual(self.req("GET", "/api/overview", {"Cookie": token})[0], 401)

    def test_fail_closed_routes(self):
        self.assertEqual(self.req("GET", "/api/overview?junk=1")[0], 404)
        self.assertEqual(self.req("GET", "/?next=https://evil.invalid")[0], 404)
        self.assertEqual(self.req("HEAD", "/auth/github/start")[0], 405)
        self.assertEqual(self.req("GET", "/auth/github/callback?code=test-only")[0], 403)
        self.assertEqual(self.req("POST", "/auth/logout", {"Origin": "https://evil.invalid"})[0],
                         403)
        self.assertEqual(self.req("GET", "/api/overview",
                                  {"Host": "evil.invalid"})[0], 400)

    def test_denied_user_and_wrong_state(self):
        st, h, _ = self.req("GET", "/auth/github/start")
        state = parse_qs(urlsplit(dict(h)["Location"]).query)["state"][0]
        self.assertEqual(self.req("GET", "/auth/github/callback?code=code-token-12345&state=" + state,
                                  {"Cookie": STATE_COOKIE + "=wrong-state"})[0], 403)
        self.provider.user_id = 2
        self.assertEqual(self.req("GET", "/auth/github/callback?code=code-token-12345&state=" + state,
                                  {"Cookie": STATE_COOKIE + "=" + state})[0], 403)
        self.assertEqual(self.req("GET", "/api/overview")[0], 401)


if __name__ == "__main__":
    unittest.main()
