"""Offline #294 infrastructure collector, authenticated API and untrusted snapshot tests."""
from __future__ import annotations

import datetime as dt
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig, OAuthService, ORIGIN
from control_center.infrastructure import (
    build, cpu_percent, hosts, history, memory, network, save,
)
from control_center.server import make_handler


def fixture(host="hermes", now=None):
    # Three-digit no-network /proc synthetic sample.
    data = build(
        host, before="cpu 100 0 0 100 0 0 0 0 0 0",
        after="cpu 125 0 0 125 0 0 0 0 0 0",
        meminfo="MemTotal: 100000 kB\nMemAvailable: 40000 kB\n"
                "SwapTotal: 10000 kB\nSwapFree: 7000 kB\n",
        loadavg="0.12 0.34 0.56 1/2 345",
        uptime="3600.12 0",
        disk=SimpleNamespace(f_blocks=1000, f_frsize=1024, f_bavail=400),
        dev="header1\nheader2\neth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n"
            "lo: 999 0 0 0 0 0 0 0 888 0 0 0 0 0 0 0\n",
        now=now,
    )
    return data


class CollectorTests(unittest.TestCase):
    def test_cpu_deltas_and_regression(self):
        self.assertEqual(cpu_percent(
            "cpu 100 0 0 100 0", "cpu 125 0 0 125 0"), 50)
        self.assertIsNone(cpu_percent(
            "cpu 100 0 0 100 0", "cpu 99 0 0 90 0"))
        self.assertIsNone(cpu_percent(
            "cpu 100 0 0 100 0", "cpu 100 0 0 100 0"))

    def test_memory_validation(self):
        self.assertEqual(memory("MemTotal: 100 kB\nMemAvailable: 60 kB\n")
                         ["ram_used_percent"], 40)
        with self.assertRaises(ValueError):
            memory("MemTotal: 100 kB\nMemAvailable: 120 kB\n")

    def test_interface_counters_are_not_doubled(self):
        data = fixture()["metrics"]
        self.assertEqual(data["network_interfaces"], {"eth0": {"rx_bytes": 10, "tx_bytes": 20}})
        self.assertEqual(data["cpu_used_percent"], 50)
        self.assertEqual(data["ram_used_percent"], 60)
        self.assertEqual(data["disk_used_percent"], 60)
        self.assertEqual(data["uptime_seconds"], 3600)
        self.assertEqual(data["load1"], 0.12)

    def test_fixed_hosts_only(self):
        with self.assertRaises(ValueError):
            fixture("internal-external-host")

    def test_live_and_unconnected_hosts_separate(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            save(fixture(), folder)
            records = hosts(folder)["hosts"]
            self.assertEqual([r["host"] for r in records], ["hermes", "yfc"])
            self.assertEqual(records[0]["status"], "online")
            self.assertEqual(records[1]["status"], "not_connected")
            self.assertNotIn("metrics", records[1])
            self.assertNotIn("network_interfaces", records[0]["metrics"])
            samples = history(folder, "hermes", 1)["samples"]
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0]["cpu"], 50)

    def test_stale_is_not_online(self):
        with tempfile.TemporaryDirectory() as root:
            older = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=7)
            Path(root, "hermes.json").write_text(json.dumps(fixture(now=older)))
            state = hosts(Path(root))["hosts"][0]
            self.assertEqual(state["status"], "stale")
            self.assertEqual(state["metrics"]["cpu_used_percent"], 50)

    def test_missing_bad_spoof_future_and_oversized(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root, "yfc.json")
            expected = hosts(Path(root))["hosts"][1]
            self.assertEqual(expected["status"], "not_connected")
            p.write_text("{broken json")
            self.assertEqual(hosts(Path(root))["hosts"][1]["status"], "unknown")
            p.write_text(json.dumps(fixture("hermes")))
            self.assertEqual(hosts(Path(root))["hosts"][1]["status"], "unknown")
            p.write_text(json.dumps(fixture(
                "yfc", now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))))
            self.assertEqual(hosts(Path(root))["hosts"][1]["status"], "unknown")
            p.write_text("x" * 20000)
            self.assertEqual(hosts(Path(root))["hosts"][1]["status"], "unknown")

    def test_forged_metrics_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            value = fixture()
            value["metrics"]["ram_used_percent"] = 190
            Path(root, "hermes.json").write_text(json.dumps(value))
            self.assertEqual(hosts(Path(root))["hosts"][0]["status"], "unknown")

    def test_symlink_snapshot_refused(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            target = folder / "target.json"
            target.write_text(json.dumps(fixture()))
            (folder / "hermes.json").symlink_to(target)
            self.assertEqual(hosts(folder)["hosts"][0]["status"], "not_connected")

    def test_history_requests_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(history(Path(root), "yfc", 7)["samples"], [])
            for host, days in (("../etc", 1), ("yfc", 60), ("yfc", 0)):
                with self.assertRaises(ValueError):
                    history(Path(root), host, days)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name) / "infrastructure"
        self.srv = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(Path(self.tmp.name) / "missing-overview.json",
                         infrastructure_dir=self.directory))
        self.thread = Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def request(self, path):
        req = Request(f"http://127.0.0.1:{self.srv.server_port}{path}",
                      headers={"Host": "hermes.mikemoore.top"})
        try:
            response = urlopen(req, timeout=2)
        except HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def test_read_only_hosts_and_history(self):
        status, headers, raw = self.request("/api/infrastructure/hosts")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual([x["status"] for x in json.loads(raw)["hosts"]],
                         ["not_connected", "not_connected"])
        save(fixture(), self.directory)
        status, _, raw = self.request("/api/infrastructure/hosts")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["hosts"][0]["status"], "online")
        status, _, raw = self.request("/api/infrastructure/history?host=hermes&days=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(raw)["samples"]), 1)

    def test_bad_queries_and_assets(self):
        for path in (
            "/api/infrastructure/hosts?test=1",
            "/api/infrastructure/history?host=../../etc&days=1",
            "/api/infrastructure/history?host=hermes&days=366",
            "/api/infrastructure/history?host=hermes&days=1&days=7",
            "/api/infrastructure/history?host=hermes",
        ):
            status, _, _ = self.request(path)
            self.assertIn(status, (400, 404), path)
        for path in ("/infrastructure.js", "/infrastructure.css"):
            status, _, raw = self.request(path)
            self.assertEqual(status, 200)
            self.assertGreater(len(raw), 100)

    def test_owner_only_denies_anonymous(self):
        config = AuthConfig(
            "github", ORIGIN, "Ov23abcdefghijk", "test-client-secret-long-enough",
            42142321, b"test signing secret longer than 32 characters")
        oauth = OAuthService(config)
        srv = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(Path(self.tmp.name) / "overview.json",
                         infrastructure_dir=self.directory,
                         auth_config=config, oauth_service=oauth))
        thread = Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ("/api/infrastructure/hosts",
                         "/api/infrastructure/history?host=hermes&days=1"):
                req = Request(f"http://127.0.0.1:{srv.server_port}{path}",
                              headers={"Host": "hermes.mikemoore.top"})
                with self.assertRaises(HTTPError) as exc:
                    urlopen(req, timeout=2)
                self.assertEqual(exc.exception.code, 401)
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
