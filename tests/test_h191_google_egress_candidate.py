"""H191 public-only Google egress candidate - deterministic, no live OAuth/nft."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts import h191_google_egress_candidate as h191

NOW = datetime(2026, 11, 1, 19, 0, tzinfo=timezone.utc)
GOOGLE_V4 = "142.250.1.9"
GOOGLE_V6 = "2607:f8b0::9"
UID = 975


def example():
    return {
        "schema": h191.SCHEMA,
        "host": h191.HOST,
        "captured_at": "2026-11-01T18:59:00Z",
        "sources": {"goog": h191.GOOG_URL, "cloud": h191.CLOUD_URL},
        "goog": {"prefixes": [
            {"ipv4Prefix": "142.250.0.0/15"},
            {"ipv6Prefix": "2607:f8b0::/32"},
        ]},
        "cloud": {"prefixes": [
            {"ipv4Prefix": "34.128.0.0/10"},
            {"ipv6Prefix": "2600:1900::/28"},
        ]},
        "resolved": {
            "oauth2.googleapis.com": [GOOGLE_V4],
            "www.googleapis.com": [GOOGLE_V6],
        },
        "dns_nameservers": ["127.0.0.53"],
    }


class H191GoogleEgressCandidateTests(unittest.TestCase):
    def test_exact_host_pins_not_provider_cidrs(self):
        pins = h191.evaluate(example(), uid=UID, now=NOW)
        self.assertEqual(pins, (GOOGLE_V4 + "/32", GOOGLE_V6 + "/128"))
        self.assertNotIn("142.250.0.0/15", pins)
        self.assertNotIn("2607:f8b0::/32", pins)

    def test_preview_is_clear_that_nothing_is_active_or_applied(self):
        pins = h191.evaluate(example(), uid=UID, now=NOW)
        body = h191.render_candidate(pins, uid=UID)
        for text in (
            "H191_EGRESS_PLAN=CANDIDATE_ONLY",
            "H191_NETWORK_CHANGED=NO",
            "H191_SECRET_ACCESSED=NO",
            "H191_OAUTH_RUN=NO",
            "H191_TIMER_ENABLED=NO",
            "Requires=hermes-gsc-egress-guard.service",
            "PrivateNetwork=no",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "IPAddressAllow=localhost",
            f"IPAddressAllow={GOOGLE_V4}/32",
            f"IPAddressAllow={GOOGLE_V6}/128",
            "meta skuid 975 ip daddr 127.0.0.53 udp dport 53 accept",
            "meta skuid 975 ip daddr 127.0.0.53 tcp dport 53 accept",
            "meta skuid 975 ip daddr @google_v4 tcp dport 443 accept",
            "meta skuid 975 ip6 daddr @google_v6 tcp dport 443 accept",
            "meta skuid 975 drop",
            "NOT APPLICABLE AS-IS",
        ):
            with self.subTest(text=text):
                self.assertIn(text, body)
        self.assertNotIn("IPAddressAllow=any", body)
        self.assertNotIn("IPAddressAllow=0.0.0.0/0", body)
        self.assertNotIn("IPAddressAllow=::/0", body)
        self.assertEqual(body.count("meta skuid 975 drop"), 1)
        self.assertLess(body.index("tcp dport 443 accept"), body.index("meta skuid 975 drop"))

    def test_reject_broad_and_unknown_pins(self):
        for bad in ("0.0.0.0/0", "::/0", "10.1.1.1/32", "142.250.0.0/15"):
            with self.subTest(bad=bad), self.assertRaises(h191.CandidateError):
                h191.render_candidate((bad,), uid=UID)

    def test_schema_and_provenance_fail_closed(self):
        cases = [
            ("missing field", lambda v: v.pop("sources")),
            ("extra field", lambda v: v.update(extra="evil")),
            ("fake source", lambda v: v["sources"].update(goog="http://evil.test")),
            ("wrong host", lambda v: v.update(host="another-vps")),
            ("wrong schema", lambda v: v.update(schema="wrong")),
            ("missing endpoint", lambda v: v["resolved"].pop("www.googleapis.com")),
            ("extra endpoint", lambda v: v["resolved"].update({"evil.example": [GOOGLE_V4]})),
            ("no dns stub", lambda v: v.update(dns_nameservers=[])),
            ("extra DNS", lambda v: v.update(dns_nameservers=["127.0.0.53", "8.8.8.8"])),
        ]
        for name, mut in cases:
            with self.subTest(name=name), self.assertRaises(h191.CandidateError):
                d = deepcopy(example())
                mut(d)
                h191.evaluate(d, uid=UID, now=NOW)

    def test_expired_future_and_naive_timestamp_rejected(self):
        for timestamp in (
            "2026-10-30T19:00:00Z",
            "2026-11-01T19:06:00Z",
            "2026-11-01T19:00:00",
            "nonsense",
        ):
            with self.subTest(timestamp=timestamp), self.assertRaises(h191.CandidateError):
                d = example()
                d["captured_at"] = timestamp
                h191.evaluate(d, uid=UID, now=NOW)

    def test_external_dns_only_google_ip_not_cloud_customer(self):
        for addr in ("127.0.0.1", "10.0.0.2", "192.168.0.1",
                     "8.8.8.8", "34.200.1.2", "1.1.1.1", "bad; nft flush ruleset"):
            with self.subTest(addr=addr), self.assertRaises(h191.CandidateError):
                d = example()
                d["resolved"]["oauth2.googleapis.com"] = [addr]
                h191.evaluate(d, uid=UID, now=NOW)

    def test_empty_excessive_and_non_list_dns_denied(self):
        for invalid in ([], [GOOGLE_V4] * 17, "142.250.1.9", None):
            with self.subTest(value=str(invalid)[:40]), self.assertRaises(h191.CandidateError):
                d = example()
                d["resolved"]["oauth2.googleapis.com"] = invalid
                h191.evaluate(d, uid=UID, now=NOW)

    def test_untrusted_source_prefixes_denied(self):
        bad_rows = (
            [{"ipv4Prefix": "0.0.0.0/0"}],
            [{"ipv4Prefix": "142.250.1.1/15"}],
            [{"ipv4Prefix": "142.250.0.0/15", "ipv6Prefix": "2607:f8b0::/32"}],
            [{"ipv4Prefix": "2607:f8b0::/32"}],
            [],
            "not-a-list",
        )
        for value in bad_rows:
            with self.subTest(value=str(value)[:60]), self.assertRaises(h191.CandidateError):
                d = example()
                d["goog"]["prefixes"] = value
                h191.evaluate(d, uid=UID, now=NOW)

    def test_untrusted_cloud_ipv6_and_goog_v4_overlap_denied(self):
        d = example()
        d["cloud"]["prefixes"].append({"ipv4Prefix": "142.250.0.0/15"})
        with self.assertRaisesRegex(h191.CandidateError, "dns_address_in_cloud_customer_ranges"):
            h191.evaluate(d, uid=UID, now=NOW)
        d = example()
        d["cloud"]["prefixes"].append({"ipv6Prefix": "2607:f8b0::/32"})
        with self.assertRaisesRegex(h191.CandidateError, "dns_address_in_cloud_customer_ranges"):
            h191.evaluate(d, uid=UID, now=NOW)

    def test_invalid_uid_rejected(self):
        for uid in (0, -1, True, "975", 2**32):
            with self.subTest(uid=uid), self.assertRaises(h191.CandidateError):
                h191.evaluate(example(), uid=uid, now=NOW)
        with self.assertRaises(h191.CandidateError):
            h191.render_candidate((GOOGLE_V4 + "/32",), uid=0)

    def test_json_strict_bounded_and_no_duplicate_fields(self):
        data = json.dumps(example()).encode("utf-8")
        self.assertEqual(h191._decode(data)["schema"], h191.SCHEMA)
        for raw in (b"", b"a" * (h191.MAX_JSON_BYTES + 1), b"\xff" * 20,
                    b'{"schema":"good","schema":"bad"}',
                    b'{"foo":NaN}', b"null", b"[]"):
            with self.subTest(raw=raw[:28]), self.assertRaises(h191.CandidateError):
                h191._decode(raw)

    def test_live_capture_requires_correct_host_before_network(self):
        with patch.object(h191.socket, "gethostname", return_value="other"), \
             patch.object(h191, "_fetch_public_ranges") as fetch:
            with self.assertRaisesRegex(h191.CandidateError, "wrong_host"):
                h191.public_preview_evidence()
            fetch.assert_not_called()

    def test_live_capture_uses_only_two_fixed_public_sources_and_google_dns(self):
        fetched = []
        resolved = []
        def fake_fetch(url):
            fetched.append(url)
            return example()["goog"] if url == h191.GOOG_URL else example()["cloud"]
        def fake_getaddr(host, port, **kwargs):
            resolved.append((host, port, kwargs))
            value = GOOGLE_V4 if host == h191.TARGETS[0] else GOOGLE_V6
            return [(socket_type, 0, 0, "", (value, 443))]
        socket_type = 2  # structure irrelevant to the consumed address tuple
        with patch.object(h191.socket, "gethostname", return_value=h191.HOST), \
             patch.object(h191, "_fetch_public_ranges", side_effect=fake_fetch), \
             patch.object(h191, "_dns_nameservers", return_value=[h191.DNS_STUB]), \
             patch.object(h191.socket, "getaddrinfo", side_effect=fake_getaddr):
            result = h191.public_preview_evidence()
        self.assertEqual(fetched, [h191.GOOG_URL, h191.CLOUD_URL])
        self.assertEqual([item[0] for item in resolved], list(h191.TARGETS))
        self.assertTrue(all(item[1] == 443 for item in resolved))
        self.assertEqual(set(result["resolved"]), set(h191.TARGETS))

    def test_public_fetch_does_not_follow_redirects_or_use_proxies(self):
        from unittest.mock import Mock
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, limit): return b'{"prefixes":[{"ipv4Prefix":"142.250.0.0/15"}]}'
        class Opener:
            def open(self, req, timeout):
                self.assert_no_secrets = not req.has_header("Authorization")
                return Response()
        with patch.object(h191, "build_opener", return_value=Opener()) as mock_build:
            result = h191._fetch_public_ranges(h191.GOOG_URL)
        self.assertEqual(result["prefixes"][0]["ipv4Prefix"], "142.250.0.0/15")
        self.assertTrue(any(isinstance(h, h191.ProxyHandler) for h in mock_build.call_args.args))
        self.assertTrue(any(isinstance(h, h191._NoRedirect) for h in mock_build.call_args.args))
        with self.assertRaisesRegex(h191.CandidateError, "unapproved_public_source"):
            h191._fetch_public_ranges("https://evil.example/api")

    def test_no_apply_and_no_secret_access_by_source_contract(self):
        source = Path(h191.__file__).read_text(encoding="utf-8")
        for forbidden in ("systemctl start", "systemctl enable", "subprocess.run",
                          "os.system(", "nft -f", "requests.post(", "service-account.json",
                          "/etc/hermes-gsc", "--credentials", "--apply"):
            with self.subTest(forbidden=forbidden):
                # The user-visible no-apply docstring may mention --apply, so skip it.
                if forbidden == "--apply":
                    self.assertNotIn('add_argument("--apply"', source)
                else:
                    self.assertNotIn(forbidden, source)
        self.assertIn("H191_NETWORK_CHANGED=NO", source)
        self.assertIn("H191_SECRET_ACCESSED=NO", source)


if __name__ == "__main__":
    unittest.main()
