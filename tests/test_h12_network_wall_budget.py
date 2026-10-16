"""H-12 process timer guard: no external DNS/HTTP in these tests."""
from __future__ import annotations

import os
import signal
import time
import unittest
from unittest.mock import patch

from statejnik_integration import network_boundary as net


class WallBudgetTests(unittest.TestCase):
    def test_default_denies_even_if_deadline_unavailable(self):
        with patch.object(net, "_wall_budget", side_effect=AssertionError("should not run")):
            with self.assertRaisesRegex(net.NetworkDenied, "network_not_enabled"):
                net.fetch_public_html(
                    "https://news.example.org/",
                    allowed_hosts=frozenset({"news.example.org"}),
                )

    def test_invalid_deadline_values_are_rejected(self):
        for timeout in (-1, 0, False, None, "2", 31, float("nan")):
            with self.subTest(timeout=str(timeout)):
                with self.assertRaises(net.NetworkDenied):
                    with net._wall_budget(timeout):
                        self.fail("deadline admitted invalid input")

    def test_multithreaded_caller_fails_closed_without_installing_alarm(self):
        with patch.object(net.threading, "active_count", return_value=2):
            with self.assertRaisesRegex(net.NetworkDenied, "wall_budget_unavailable"):
                with net._wall_budget(1):
                    self.fail("multithreaded network should be blocked")

    @unittest.skipUnless(os.name == "posix", "POSIX alarm required")
    def test_existing_alarm_fails_closed(self):
        with patch.object(net.signal, "getitimer", return_value=(2.0, 0.0)):
            with self.assertRaisesRegex(net.NetworkDenied, "wall_budget_busy"):
                with net._wall_budget(0.2):
                    self.fail("must not overwrite another timer")

    @unittest.skipUnless(os.name == "posix", "POSIX alarm required")
    def test_process_absolute_budget_interrupts_slow_body(self):
        existing = signal.getsignal(signal.SIGALRM)
        before = signal.getitimer(signal.ITIMER_REAL)
        if existing not in (signal.SIG_DFL, signal.SIG_IGN) or before[0]:
            self.skipTest("test runner already owns SIGALRM")
        start = time.monotonic()
        with self.assertRaisesRegex(net.NetworkDenied, "wall_budget_exceeded"):
            with net._wall_budget(0.045):
                time.sleep(0.3)
        self.assertLess(time.monotonic() - start, 0.25)
        self.assertEqual(signal.getsignal(signal.SIGALRM), existing)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    @unittest.skipUnless(os.name == "posix", "POSIX alarm required")
    def test_real_fetch_budget_covers_fake_http_body_trickle(self):
        class SlowResponse:
            status = 200

            def getheader(self, name):
                if name == "Content-Type":
                    return "text/html"
                return None

            def read(self, limit):
                while True:
                    time.sleep(0.005)

        class SlowConnection:
            closed = False
            def __init__(self, *_args, **_kwargs):
                pass
            def request(self, *_args, **_kwargs):
                pass
            def getresponse(self):
                return SlowResponse()
            def close(self):
                self.closed = True

        connections = []
        def factory(*args, **kwargs):
            obj = SlowConnection(*args, **kwargs)
            connections.append(obj)
            return obj

        import socket
        def resolver(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                     "", ("93.184.216.34", 443))]

        with patch.object(net, "MAX_WALL_SECONDS", 0.045):
            with self.assertRaisesRegex(net.NetworkDenied, "wall_budget_exceeded"):
                net.fetch_public_html(
                    "https://news.example.org/",
                    allowed_hosts=frozenset({"news.example.org"}),
                    authorized=True, resolver=resolver,
                    connection_factory=factory,
                )
        self.assertEqual(len(connections), 1)
        self.assertTrue(connections[0].closed)


if __name__ == "__main__":
    unittest.main()
