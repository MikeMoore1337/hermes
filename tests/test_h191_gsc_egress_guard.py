"""H191 Google-only nft/systemd guard: offline, synthetic and fail-closed."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from unittest import TestCase, mock

from scripts import h191_gsc_egress_guard as guard

V4 = "142.250.1.9/32"
V6 = "2607:f8b0::9/128"
UID = 975
GID = 971
PINS = (V4, V6)


def match(proto, key, value):
    return guard._match(proto, key, value)


def valid_nft():
    name = guard.TABLE
    user = match("meta", "skuid", UID)
    return {"nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": name, "handle": 1}},
        {"set": {"family": "inet", "table": name, "name": "google_v4",
                 "type": "ipv4_addr", "elem": ["142.250.1.9"], "handle": 2}},
        {"set": {"family": "inet", "table": name, "name": "google_v6",
                 "type": "ipv6_addr", "elem": ["2607:f8b0::9"], "handle": 3}},
        {"chain": {"family": "inet", "table": name, "name": "outbound",
                   "type": "filter", "hook": "output", "prio": -110,
                   "policy": "accept", "handle": 1}},
        {"rule": {"family": "inet", "table": name, "chain": "outbound",
                  "expr": [user, match("ip", "daddr", "127.0.0.53"),
                           match("udp", "dport", 53), {"accept": None}]}},
        {"rule": {"family": "inet", "table": name, "chain": "outbound",
                  "expr": [user, match("ip", "daddr", "127.0.0.53"),
                           match("tcp", "dport", 53), {"accept": None}]}},
        {"rule": {"family": "inet", "table": name, "chain": "outbound",
                  "expr": [user, match("ip", "daddr", "@google_v4"),
                           match("tcp", "dport", 443), {"accept": None}]}},
        {"rule": {"family": "inet", "table": name, "chain": "outbound",
                  "expr": [user, match("ip6", "daddr", "@google_v6"),
                           match("tcp", "dport", 443), {"accept": None}]}},
        {"rule": {"family": "inet", "table": name, "chain": "outbound",
                  "expr": [user, {"drop": None}]}},
    ]}


class H191GoogleEgressGuardTests(TestCase):
    def test_nft_program_is_uid_scoped_port_limited_and_default_drops(self):
        text = guard.nft_program(PINS, UID)
        self.assertTrue(text.startswith("create table inet " + guard.TABLE))
        self.assertIn("meta skuid 975 ip daddr 127.0.0.53 udp dport 53 accept", text)
        self.assertIn("meta skuid 975 ip daddr 127.0.0.53 tcp dport 53 accept", text)
        self.assertIn("meta skuid 975 ip daddr @google_v4 tcp dport 443 accept", text)
        self.assertIn("meta skuid 975 ip6 daddr @google_v6 tcp dport 443 accept", text)
        self.assertTrue(text.rstrip().endswith("meta skuid 975 drop"))
        for forbidden in ("flush ruleset", "delete table", "0.0.0.0/0", "::/0",
                          "meta skuid 0", "tcp dport 80", "udp dport 443"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("accept"), 5)  # chain + 4 whitelisted rules

    def test_nft_json_exact_kernel_format_accepted(self):
        self.assertTrue(guard.nft_is_exact(valid_nft(), PINS, UID))

    def test_nft_json_refuses_extra_rules_and_removed_drop(self):
        base = valid_nft()
        variants = []
        x = deepcopy(base); x["nftables"].append(deepcopy(x["nftables"][-1])); variants.append(x)
        x = deepcopy(base); x["nftables"].pop(); variants.append(x)
        x = deepcopy(base); x["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}; variants.append(x)
        x = deepcopy(base); x["nftables"][5]["rule"]["expr"][0]["match"]["right"] = 0; variants.append(x)
        x = deepcopy(base); x["nftables"][4]["chain"]["policy"] = "drop"; variants.append(x)
        x = deepcopy(base); x["nftables"][1]["table"]["name"] = "other"; variants.append(x)
        x = deepcopy(base); x["nftables"][2]["set"]["elem"] = ["8.8.8.8"]; variants.append(x)
        x = deepcopy(base); x["nftables"][2]["set"]["flags"] = ["timeout"]; variants.append(x)
        x = deepcopy(base); x["nftables"][6], x["nftables"][7] = x["nftables"][7], x["nftables"][6]; variants.append(x)
        for i, v in enumerate(variants):
            with self.subTest(case=i):
                self.assertFalse(guard.nft_is_exact(v, PINS, UID))

    def test_pin_safety_refuses_private_broad_duplicate_and_injected(self):
        for pins in (
            ("0.0.0.0/0",), ("::/0",),
            ("10.0.0.1/32",), ("127.0.0.1/32",),
            ("142.250.0.0/15",), (V4, V4),
            ("142.250.1.9/32; nft flush ruleset",),
            (), tuple([V4] * 40),
        ):
            with self.subTest(pins=pins[:2]), self.assertRaises(guard.GuardError):
                guard.nft_program(pins, UID)
        for uid in (0, -1, True):
            with self.subTest(uid=uid), self.assertRaises(guard.GuardError):
                guard.nft_program(PINS, uid)

    def test_one_family_rules_still_default_deny(self):
        p = guard.nft_program((V4,), UID)
        self.assertIn("@google_v4", p)
        self.assertNotIn("google_v6", p)
        self.assertTrue(p.rstrip().endswith("meta skuid 975 drop"))
        p = guard.nft_program((V6,), UID)
        self.assertIn("@google_v6", p)
        self.assertNotIn("google_v4", p)

    def test_systemd_dropin_has_guard_dependency_and_only_exact_pins(self):
        text = guard.dropin_text(PINS)
        self.assertIn("Requires=hermes-gsc-egress-guard.service", text)
        self.assertIn("After=hermes-gsc-egress-guard.service", text)
        self.assertIn("PrivateNetwork=no", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", text)
        self.assertIn("IPAddressAllow=localhost", text)
        self.assertIn("IPAddressAllow=" + V4, text)
        self.assertIn("IPAddressAllow=" + V6, text)
        self.assertNotIn("IPAddressDeny=", text)  # inherited from original DENY_ALL
        self.assertNotIn("IPAddressAllow=0.0.0.0/0", text)
        self.assertNotIn("IPAddressAllow=::/0", text)

    def test_guard_unit_is_on_demand_only_and_has_no_gsc_activation(self):
        text = guard.guard_unit_text()
        self.assertIn("Type=oneshot", text)
        self.assertIn("--ensure", text)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", text)
        self.assertIn("NoNewPrivileges=yes", text)
        self.assertIn("MemoryMax=96M", text)
        self.assertNotIn("WantedBy=", text)
        self.assertNotIn("systemctl start", text)
        self.assertNotIn("ExecStart=/opt/hermes-gsc/venv/", text)
        self.assertNotIn("webmasters", text)

    def test_current_dns_change_fails_closed_before_nft_mutation(self):
        with mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_current_pins", return_value=(V4, "142.251.1.10/32")), \
             mock.patch.object(guard, "_nft_state") as state, \
             mock.patch.object(guard, "_nft_create") as create:
            with self.assertRaisesRegex(guard.GuardError, "google_ip_rotation_requires_review"):
                guard.check(UID, GID, ensure=True)
            state.assert_not_called()
            create.assert_not_called()

    def test_check_offline_does_not_fetch_dns_or_modify_nft(self):
        with mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_current_pins") as live, \
             mock.patch.object(guard, "_nft_state", return_value="EXACT") as state, \
             mock.patch.object(guard, "_nft_create") as create:
            guard.check(UID, GID, ensure=False)
            live.assert_not_called()
            create.assert_not_called()
            state.assert_called_once_with(PINS, UID)

    def test_ensure_reinstalls_only_missing_verified_guard(self):
        with mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_current_pins", return_value=(V4,)), \
             mock.patch.object(guard, "_nft_state", side_effect=["MISSING", "EXACT"]), \
             mock.patch.object(guard, "_nft_create") as create:
            guard.check(UID, GID, ensure=True)
            create.assert_called_once_with(PINS, UID)

    def test_install_rejects_preexisting_files_before_nft(self):
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard.POLICY, "exists", return_value=True), \
             mock.patch.object(guard, "_nft_create") as nft:
            with self.assertRaisesRegex(guard.GuardError, "preexisting_policy_files"):
                guard.install(UID, GID)
            nft.assert_not_called()

    def test_install_stages_guard_before_widening_systemd(self):
        from unittest.mock import call
        order = []
        def count_nft(*args): order.append("nft")
        def count_files(path, *_args):
            if path == guard.POLICY: order.append("pins")
            elif path == guard.GUARD_FILE: order.append("guard_unit")
            elif path == guard.DROPIN: order.append("dropin")
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard.POLICY, "exists", return_value=False), \
             mock.patch.object(guard.POLICY, "is_symlink", return_value=False), \
             mock.patch.object(guard.DROPIN, "exists", return_value=False), \
             mock.patch.object(guard.DROPIN, "is_symlink", return_value=False), \
             mock.patch.object(guard.GUARD_FILE, "exists", return_value=False), \
             mock.patch.object(guard.GUARD_FILE, "is_symlink", return_value=False), \
             mock.patch.object(guard.DROPIN.parent, "is_symlink", return_value=False), \
             mock.patch.object(guard.DROPIN.parent, "mkdir"), \
             mock.patch.object(guard.DROPIN.parent, "stat") as stat_mock, \
             mock.patch.object(guard, "_current_pins", return_value=PINS), \
             mock.patch.object(guard, "_nft_create", side_effect=count_nft), \
             mock.patch.object(guard, "_store_text", side_effect=count_files), \
             mock.patch.object(guard, "_run") as run, \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"):
            stat_mock.return_value.st_uid = 0
            stat_mock.return_value.st_mode = 0o40755
            run.side_effect = ["", "", "no"]
            guard.install(UID, GID)
        self.assertEqual(order, ["nft", "pins", "guard_unit", "dropin"])

    def test_no_activation_or_credentials_open_in_source(self):
        content = Path(guard.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "systemctl enable", "systemctl start", "systemctl restart",
            "nft flush ruleset", "iptables", "requests.post(", "--oauth",
            "webmasters/v3", ".read_bytes()" + "  # private",
        ):
            with self.subTest(fragment=forbidden):
                self.assertNotIn(forbidden, content)
        self.assertIn("service-account.json", content)  # metadata only via lstat
        self.assertIn("path.lstat()", content)
        self.assertNotIn('open("/etc/hermes-gsc/service-account.json"', content)

    def test_public_only_plan_cannot_enter_installer(self):
        with mock.patch.object(guard, "_identity", return_value=(UID, GID)), \
             mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_current_pins", return_value=PINS), \
             mock.patch.object(guard, "_nft_state", return_value="MISSING"), \
             mock.patch.object(guard, "_run"), \
             mock.patch.object(guard, "_nft_create") as nft:
            self.assertEqual(guard.main(["--plan"]), 0)
            nft.assert_not_called()

    def test_mutating_install_needs_explicit_owner_flag(self):
        with mock.patch.object(guard, "_identity", return_value=(UID, GID)), \
             mock.patch.object(guard, "_lock") as lock, \
             mock.patch.object(guard, "install") as installer:
            self.assertEqual(guard.main(["--install"]), 2)
            lock.assert_not_called()
            installer.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
