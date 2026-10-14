"""Strict idempotent Hermes firewall checks with no Docker/nft side effects."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts import ensure_cloudflare_egress as guard


ROOT = Path(__file__).resolve().parents[1]


def response(code: int, stdout: str = ""):
    from subprocess import CompletedProcess
    return CompletedProcess([], code, stdout, "")


def nft_json() -> dict:
    allow = [
        guard.match_eq("meta", "iifname", guard.BRIDGE),
        guard.match_eq("ip", "saddr", guard.AGENT),
        guard.match_eq("ip", "daddr", guard.GATEWAY),
        guard.match_eq("tcp", "dport", guard.PORT),
        {"accept": None},
    ]
    deny = [guard.match_eq("meta", "iifname", guard.BRIDGE), {"drop": None}]
    return {"nftables": [
        {"metainfo": {"version": "1.0"}},
        {"table": {"family": "inet", "name": guard.TABLE}},
        {"chain": {"name": "input", "family": "inet", "table": guard.TABLE,
                   "type": "filter", "hook": "input", "prio": -110, "policy": "accept"}},
        {"chain": {"name": "forward", "family": "inet", "table": guard.TABLE,
                   "type": "filter", "hook": "forward", "prio": -110, "policy": "accept"}},
        {"rule": {"family": "inet", "table": guard.TABLE, "chain": "input", "expr": allow}},
        {"rule": {"family": "inet", "table": guard.TABLE, "chain": "input", "expr": deny}},
        {"rule": {"family": "inet", "table": guard.TABLE, "chain": "forward", "expr": deny}},
    ]}


def network_json() -> list[dict]:
    return [{
        "Name": guard.NETWORK, "Driver": "bridge", "Internal": True,
        "EnableIPv6": False, "Attachable": False, "Ingress": False,
        "Options": {"com.docker.network.bridge.name": guard.BRIDGE},
        "IPAM": {"Config": [{"Subnet": guard.SUBNET, "Gateway": guard.GATEWAY}]},
    }]


class FirewallGateTests(unittest.TestCase):
    def test_exact_accepted_state(self):
        self.assertTrue(guard.rules_are_exact(nft_json()))
        self.assertTrue(guard.network_is_exact(network_json()))

    def test_any_changed_port_source_hook_or_extra_rule_denied(self):
        for changed in ("port", "source", "hook", "extra"):
            with self.subTest(changed=changed):
                payload = nft_json()
                if changed == "port":
                    payload["nftables"][4]["rule"]["expr"][3]["match"]["right"] = 22
                elif changed == "source":
                    payload["nftables"][4]["rule"]["expr"][1]["match"]["right"] = "0.0.0.0/0"
                elif changed == "hook":
                    payload["nftables"][2]["chain"]["hook"] = "output"
                else:
                    payload["nftables"].append(payload["nftables"][5])
                self.assertFalse(guard.rules_are_exact(payload))

    def test_non_internal_bridge_denied(self):
        net = network_json()
        net[0]["Internal"] = False
        self.assertFalse(guard.network_is_exact(net))

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(True, True))
    @patch.object(guard, "get_nft", return_value=(True, True))
    @patch.object(guard, "process")
    def test_idempotent_ensure_does_not_write_existing_network(self, run, *_):
        self.assertEqual(guard.ensure(mutate=True), "verified")
        run.assert_not_called()

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(True, True))
    @patch.object(guard, "get_nft", return_value=(True, False))
    @patch.object(guard, "process")
    def test_existing_rule_drift_fails_without_mutation(self, run, *_):
        with self.assertRaisesRegex(guard.GuardError, "existing_isolation_drift"):
            guard.ensure(mutate=True)
        run.assert_not_called()

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(False, False))
    @patch.object(guard, "get_nft", return_value=(False, False))
    @patch.object(guard, "process")
    def test_missing_bridge_is_not_silently_created_in_check_mode(self, run, *_):
        with self.assertRaisesRegex(guard.GuardError, "isolation_missing"):
            guard.ensure(mutate=False)
        run.assert_not_called()


    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(True, True))
    @patch.object(guard, "get_nft", side_effect=[(False, False), (True, True), (True, True)])
    @patch.object(guard, "process", return_value=response(0))
    def test_missing_firewall_rebuilt_without_touching_existing_bridge(self, run, nft, *_):
        self.assertEqual(guard.ensure(mutate=True), "verified")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["nft", "-f", "-"])
        self.assertIn("add table inet hermes_agent_isolation", run.call_args.kwargs["stdin"])
        self.assertEqual(nft.call_count, 3)

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", side_effect=[(False, False), (True, True)])
    @patch.object(guard, "get_nft", side_effect=[(False, False), (True, True), (True, True)])
    @patch.object(guard, "process",
                  side_effect=[response(0), response(0, ""), response(0)])
    def test_both_missing_restored_firewall_first_then_internal_bridge(self, run, *_):
        self.assertEqual(guard.ensure(mutate=True), "verified")
        commands = [c.args[0] for c in run.call_args_list]
        self.assertEqual(commands[0], ["nft", "-f", "-"])
        self.assertEqual(commands[1], ["ip", "-4", "route", "show", guard.SUBNET])
        self.assertEqual(commands[2][:3], ["docker", "network", "create"])
        self.assertIn("--internal", commands[2])

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(False, False))
    @patch.object(guard, "get_nft", return_value=(False, False))
    @patch.object(guard, "process", return_value=response(1))
    def test_firewall_creation_failure_never_creates_network(self, run, *_):
        with self.assertRaisesRegex(guard.GuardError, "firewall_create_failed"):
            guard.ensure(mutate=True)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["nft", "-f", "-"])

    @patch.object(guard, "process",
                  side_effect=[response(1), response(0, "table inet hermes_agent_isolation")])
    def test_failed_nft_table_inspection_does_not_forge_absence(self, run):
        with self.assertRaisesRegex(guard.GuardError, "nft_inspection_failed"):
            guard.get_nft()
        self.assertEqual(run.call_count, 2)

    @patch.object(guard.os, "geteuid", return_value=0)
    @patch.object(guard, "get_network", return_value=(True, False))
    @patch.object(guard, "get_nft", return_value=(False, False))
    @patch.object(guard, "process")
    def test_modified_existing_network_is_never_repaired_or_overwritten(self, run, *_):
        with self.assertRaisesRegex(guard.GuardError, "existing_isolation_drift"):
            guard.ensure(mutate=True)
        run.assert_not_called()

    def test_proxy_checks_exact_network_again_before_listening(self):
        proxy = (ROOT / "deploy/hermes-cloudflare-proxy.service").read_text()
        self.assertIn(
            "ExecStartPre=+/usr/bin/python3 "
            "/opt/hermes-agent-owner/scripts/ensure_cloudflare_egress.py --check",
            proxy,
        )
        self.assertIn("User=hermes-egress", proxy)
        self.assertIn("NoNewPrivileges=yes", proxy)
        self.assertIn("CapabilityBoundingSet=" + chr(10), proxy)
        runner = (ROOT / "scripts/agent_turn_probe.py").read_text()
        self.assertIn('"--check"', runner)
        self.assertIn("ensure_cloudflare_egress.py", runner)

    def test_proxy_service_requires_guard_unit(self):
        unit = (ROOT / "deploy/hermes-cloudflare-proxy.service").read_text()
        self.assertIn("Requires=docker.service hermes-cloudflare-network-guard.service", unit)
        guard_unit = (ROOT / "deploy/hermes-cloudflare-network-guard.service").read_text()
        self.assertIn("AssertPathExists=", guard_unit)
        self.assertIn("RemainAfterExit=yes", guard_unit)
        self.assertNotIn("ExecStop=", guard_unit)
        self.assertNotIn("flush ruleset", guard_unit)


if __name__ == "__main__":
    unittest.main()
