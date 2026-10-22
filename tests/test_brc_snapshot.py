"""Fail-closed, privacy-safe read-only BRC snapshot adapter tests (#455)."""
from __future__ import annotations

import copy
import json
import unittest
from control_center.brc_snapshot import DEVICES, PROJECTS, SnapshotRejected, normalize

NOW = 1_792_698_000_000
DEVICE_IDS = ("h15-win-05be75515428", "h15-hermes-ab005bc0e0ea",
              "h15-yfc-c6ee0d53e858")


def fixtures():
    devices = {"devices": [
        {"name": name, "deviceId": identity, "online": True, "paused": False,
         "lastSeen": NOW - 1000, "access_token": "SECRET_SENTINEL"}
        for name, identity in zip(DEVICES, DEVICE_IDS)
    ]}
    catalog = {"schema": 1, "status": "catalog", "workspaces": [
        {"name": name, "root": "/workspace/projects/" + name,
         "branch": branch, "scope": "sandbox", "git_verified": False,
         "origin": "https://github.com/MikeMoore1337/" + name + ".git",
         "deviceId": DEVICE_IDS[0], "device_status": "online",
         "oauth_token": "SECRET_SENTINEL"}
        for name, branch in PROJECTS.items()
    ]}
    return devices, catalog


class BrcSnapshotTests(unittest.TestCase):
    def test_happy_path_never_claims_shell_or_host_permission(self):
        devices, catalog = fixtures()
        result = normalize(devices, catalog, now_ms=NOW)
        self.assertEqual(result["status"], "online")
        self.assertEqual(len(result["devices"]), 3)
        self.assertEqual(len(result["workspaces"]), 4)
        self.assertFalse(result["execution_verified"])
        self.assertFalse(result["onboarding_enabled"])
        self.assertFalse(result["native_host_access"])
        self.assertTrue(all(d["command_execution"] == "not_verified"
                            for d in result["devices"]))
        self.assertTrue(all(w["git_verified"] is False for w in result["workspaces"]))
        blob = json.dumps(result)
        self.assertNotIn("SECRET_SENTINEL", blob)
        self.assertNotIn("h15-win-", blob)
        self.assertNotIn("oauth_token", blob)

    def test_shuffled_device_and_project_order_is_stable(self):
        dev, cat = fixtures()
        dev["devices"].reverse()
        cat["workspaces"].reverse()
        result = normalize(dev, cat, now_ms=NOW)
        self.assertEqual([d["name"] for d in result["devices"]], list(DEVICES))
        self.assertEqual([w["name"] for w in result["workspaces"]], list(PROJECTS))

    def test_paused_offline_stale_and_partial_are_distinct(self):
        dev, cat = fixtures()
        dev["devices"][1]["online"] = False
        dev["devices"][2]["lastSeen"] = NOW - 301000
        result = normalize(dev, cat, now_ms=NOW)
        self.assertEqual(result["status"], "partial")
        self.assertEqual([d["status"] for d in result["devices"]],
                         ["online", "offline", "stale"])
        dev["devices"][0]["paused"] = True
        result = normalize(dev, cat, now_ms=NOW)
        self.assertEqual(result["devices"][0]["status"], "paused")
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(all(w["state"] == "not_ready" for w in result["workspaces"]))

    def test_reject_malformed_devices(self):
        a, b = fixtures()
        cases = [
            lambda v: v.update({"extra": "SECRET_SENTINEL"}),
            lambda v: v["devices"].pop(),
            lambda v: v["devices"][0].update({"online": 1}),
            lambda v: v["devices"][1].update({"paused": "false"}),
            lambda v: v["devices"][0].update({"lastSeen": NOW + 100000}),
            lambda v: v["devices"][0].update({"lastSeen": 0.5}),
            lambda v: v["devices"][2].update({"name": v["devices"][0]["name"]}),
            lambda v: v["devices"][2].update({"deviceId": v["devices"][0]["deviceId"]}),
            lambda v: v["devices"][0].update({"deviceId": "../../root"}),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                v = copy.deepcopy(a)
                mutate(v)
                with self.assertRaises(SnapshotRejected):
                    normalize(v, b, now_ms=NOW)

    def test_reject_forged_workspace_catalog(self):
        a, b = fixtures()
        cases = [
            lambda c: c.update({"status": "resolved"}),
            lambda c: c["workspaces"].pop(),
            lambda c: c["workspaces"][0].update({"root": "/host-private/hermes"}),
            lambda c: c["workspaces"][0].update({"scope": "host"}),
            lambda c: c["workspaces"][0].update({"git_verified": True}),
            lambda c: c["workspaces"][0].update({"deviceId": DEVICE_IDS[1]}),
            lambda c: c["workspaces"][0].update({"branch": "dev"}),
            lambda c: c["workspaces"][0].update({"origin": "file:///private"}),
            lambda c: c["workspaces"][1].update({"name": "hermes"}),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                cat = copy.deepcopy(b)
                mutate(cat)
                with self.assertRaises(SnapshotRejected):
                    normalize(a, cat, now_ms=NOW)

    def test_reject_clock_and_no_network_effects(self):
        a, b = fixtures()
        for value in (None, True, -1, 4.2, 123):
            with self.subTest(value=value), self.assertRaises(SnapshotRejected):
                normalize(a, b, now_ms=value)


if __name__ == "__main__":
    unittest.main()
