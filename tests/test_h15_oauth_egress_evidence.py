"""No-network evidence tests: broad, stale, wrong host, private IP all denied."""
from datetime import datetime, timezone, timedelta
import tempfile
import unittest
from pathlib import Path

from scripts.h15_oauth_egress_evidence import plan, read_evidence, EgressEvidenceError

NOW = datetime(2026, 10, 16, 19, 0, tzinfo=timezone.utc)


def valid():
    return {
        "source": "https://api.github.com/meta",
        "captured_at": "2026-10-16T18:55:00Z",
        "ranges": {
            "web": ["140.82.112.0/20", "2606:50c0::/32"],
            "api": ["140.82.112.0/20", "2606:50c0::/32"],
        },
        "resolved": {
            "github.com": ["140.82.114.4"],
            "api.github.com": ["140.82.113.6"],
        },
    }


class EvidenceTests(unittest.TestCase):
    def test_only_pinned_host_masks_are_suggested(self):
        result = plan(valid(), now=NOW)
        self.assertEqual(result, ("IPAddressAllow=140.82.113.6/32",
                                  "IPAddressAllow=140.82.114.4/32"))
        self.assertNotIn("IPAddressAllow=0.0.0.0/0", result)

    def test_negative_evidence_fail_closed(self):
        cases = [
            ("bad source", lambda d: d.update(source="https://evil.invalid/meta")),
            ("extra hostname", lambda d: d["resolved"].update({"evil.invalid": ["140.82.113.6"]})),
            ("missing host", lambda d: d["resolved"].pop("api.github.com")),
            ("private address", lambda d: d["resolved"].update({"api.github.com": ["127.0.0.1"]})),
            ("unmatched DNS", lambda d: d["resolved"].update({"api.github.com": ["8.8.8.8"]})),
            ("broad IP range", lambda d: d["ranges"].update({"web": ["0.0.0.0/0"]})),
            ("bad CIDR", lambda d: d["ranges"].update({"web": ["140.82.112.1/20"]})),
            ("missing api range", lambda d: d["ranges"].pop("api")),
            ("empty DNS", lambda d: d["resolved"].update({"github.com": []})),
            ("too many", lambda d: d["resolved"].update({"github.com": ["140.82.114.4"] * 9})),
            ("wrong timestamp", lambda d: d.update(captured_at="2025-01-01T00:00:00Z")),
            ("timezone missing", lambda d: d.update(captured_at="2026-10-16T18:55:00")),
            ("missing source key", lambda d: d.pop("source")),
        ]
        for name, change in cases:
            with self.subTest(name=name), self.assertRaises(EgressEvidenceError):
                d = valid()
                change(d)
                plan(d, now=NOW)

    def test_local_evidence_file_guards_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "evidence.json"
            candidate.write_text('{"source":"first","source":"second"}', encoding="utf8")
            with self.assertRaises(EgressEvidenceError):
                read_evidence(candidate)
            candidate.write_text("null", encoding="utf8")
            with self.assertRaises(EgressEvidenceError):
                read_evidence(candidate)
            candidate.write_text("{" + ("x" * 150_001) + "}", encoding="utf8")
            with self.assertRaises(EgressEvidenceError):
                read_evidence(candidate)
            candidate.write_text('{"source":"https://api.github.com/meta"}', encoding="utf8")
            self.assertEqual(read_evidence(candidate)["source"], "https://api.github.com/meta")
            with self.assertRaises(EgressEvidenceError):
                read_evidence(root / "nonexistent.json")
            link = root / "shortcut.json"
            try:
                link.symlink_to(candidate)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(EgressEvidenceError):
                    read_evidence(link)

    def test_future_observation_denied(self):
        with self.assertRaises(EgressEvidenceError):
            plan(valid(), now=NOW - timedelta(minutes=10))

    def test_ipv6_only_exact_host(self):
        d=valid()
        d["resolved"]["github.com"]=["2606:50c0::111"]
        d["resolved"]["api.github.com"]=["2606:50c0::222"]
        self.assertEqual(plan(d, now=NOW),
                         ("IPAddressAllow=2606:50c0::111/128",
                          "IPAddressAllow=2606:50c0::222/128"))


if __name__=="__main__":
    unittest.main()
