"""H191 Google-only nft/systemd guard: offline, synthetic and fail-closed."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
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
    def test_pin_refresh_requires_explicit_owner_flag(self):
        with mock.patch.object(guard, "_identity", return_value=(UID, GID)), \
             mock.patch.object(guard, "_lock") as lock, \
             mock.patch.object(guard, "refresh_pins") as refresh:
            self.assertEqual(guard.main(["--refresh-pins"]), 2)
            lock.assert_not_called()
            refresh.assert_not_called()

    def test_pin_refresh_rejects_policy_drift_before_google_dns(self):
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_nft_state", return_value="MISSING"), \
             mock.patch.object(guard, "_current_pins") as dns, \
             mock.patch.object(guard, "_run") as command:
            with self.assertRaisesRegex(guard.GuardError, "refresh_existing_guard_not_exact"):
                guard.refresh_pins(UID, GID)
            dns.assert_not_called()
            command.assert_not_called()

    def test_pin_refresh_unchanged_leaves_nft_and_files_intact(self):
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "_read_root_file", return_value="old_record"), \
             mock.patch.object(guard, "_current_pins", return_value=PINS), \
             mock.patch.object(guard, "_sha", return_value="a" * 40), \
             mock.patch.object(guard, "_run") as command, \
             mock.patch.object(guard, "_replace_pinned_file") as writer:
            self.assertEqual(guard.refresh_pins(UID, GID), "UNCHANGED")
            command.assert_not_called()
            writer.assert_not_called()

    def test_atomic_pin_refresh_applies_nft_before_any_systemd_write(self):
        new = ("142.250.2.9/32", "2607:f8b0::42/128")
        events = []
        def run(parts, **kwargs):
            events.append("nft_check" if parts[:3] == ["nft", "-c", "-f"]
                          else "nft_apply" if parts[:2] == ["nft", "-f"]
                          else "systemd_reload" if parts[:2] == ["systemctl", "daemon-reload"]
                          else "unexpected")
            return ""
        def writer(path, _data, _mode):
            events.append("policy_write" if path == guard.POLICY else "dropin_write")
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "_read_root_file", return_value="old_record"), \
             mock.patch.object(guard, "_current_pins", return_value=new), \
             mock.patch.object(guard, "_pins_record", return_value="new_record"), \
             mock.patch.object(guard, "_sha", return_value="a" * 40), \
             mock.patch.object(guard, "_run", side_effect=run), \
             mock.patch.object(guard, "_replace_pinned_file", side_effect=writer):
            self.assertEqual(guard.refresh_pins(UID, GID), "UPDATED")
        self.assertEqual(events, [
            "nft_check", "nft_apply", "policy_write", "dropin_write", "systemd_reload",
        ])
        batch = "delete table inet " + guard.TABLE + "\n" + guard.nft_program(new, UID)
        self.assertNotIn("flush ruleset", batch)
        self.assertIn("meta skuid 975 drop", batch)

    def test_refresh_after_partial_failure_restores_owned_files_and_nft(self):
        changed = ("142.250.2.9/32", "2607:f8b0::42/128")
        old_record = "old_record"
        new_record = "new_record"
        old_dropin = guard.dropin_text(PINS)
        in_memory = {guard.POLICY: old_record, guard.DROPIN: old_dropin}
        calls = []
        def read(path, *_args):
            return in_memory[path]
        def writer(path, contents, mode):
            self.assertEqual(mode, 0o600 if path == guard.POLICY else 0o644)
            in_memory[path] = contents
            calls.append("write")
        def command(parts, **kwargs):
            if parts[0] == "nft" and parts[1] == "-f":
                calls.append("nft_apply")
            return ""
        def installed(pins):
            if pins == changed:
                raise guard.GuardError("simulated_failed_postinstall")
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted", side_effect=installed), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "_read_root_file", side_effect=read), \
             mock.patch.object(guard, "_current_pins", return_value=changed), \
             mock.patch.object(guard, "_pins_record", return_value=new_record), \
             mock.patch.object(guard, "_sha", return_value="a" * 40), \
             mock.patch.object(guard, "_run", side_effect=command), \
             mock.patch.object(guard, "_replace_pinned_file", side_effect=writer):
            with self.assertRaisesRegex(guard.GuardError, "refresh_failed_rolled_back"):
                guard.refresh_pins(UID, GID)
        self.assertEqual(in_memory[guard.POLICY], old_record)
        self.assertEqual(in_memory[guard.DROPIN], old_dropin)
        self.assertEqual(calls.count("nft_apply"), 2)

    def test_pin_refresh_replacement_only_accepts_two_private_owned_files(self):
        with self.assertRaisesRegex(guard.GuardError, "refresh_path_not_allowlisted"):
            guard._replace_pinned_file(guard.GUARD_FILE, "invalid", 0o644)
        with self.assertRaisesRegex(guard.GuardError, "refresh_path_not_allowlisted"):
            guard._replace_pinned_file(guard.POLICY, "invalid", 0o644)

    def test_systemd_release_credential_reads_private_sha_copy_only(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base) / guard.GUARD
            folder.mkdir()
            (folder / guard.RELEASE_CREDENTIAL).write_text("a" * 40 + "\n", encoding="ascii")
            with mock.patch.object(guard, "RELEASE_CREDENTIALS_ROOT", Path(base)), \
                 mock.patch.dict(guard.os.environ, {"CREDENTIALS_DIRECTORY": str(folder)}), \
                 mock.patch.object(guard, "DEPLOY_SHA") as original:
                self.assertEqual(guard._sha(), "a" * 40)
                original.read_text.assert_not_called()

    def test_release_credential_directory_spoof_and_bad_sha_denied(self):
        with mock.patch.dict(guard.os.environ, {"CREDENTIALS_DIRECTORY": "/tmp/fake"}):
            with self.assertRaisesRegex(guard.GuardError, "release_credential_directory_invalid"):
                guard._sha()
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base) / guard.GUARD
            folder.mkdir()
            (folder / guard.RELEASE_CREDENTIAL).write_text("not-a-sha", encoding="ascii")
            with mock.patch.object(guard, "RELEASE_CREDENTIALS_ROOT", Path(base)), \
                 mock.patch.dict(guard.os.environ, {"CREDENTIALS_DIRECTORY": str(folder)}):
                with self.assertRaisesRegex(guard.GuardError, "deployed_release_invalid"):
                    guard._sha()

    def test_root_cli_reads_original_marker_without_credentials_env(self):
        with mock.patch.dict(guard.os.environ, {}, clear=True), \
             mock.patch.object(guard, "DEPLOY_SHA") as marker:
            marker.read_text.return_value = "b" * 40 + "\n"
            self.assertEqual(guard._sha(), "b" * 40)
            marker.read_text.assert_called_once_with(encoding="ascii")

    def test_guard_loadcredential_template_keeps_caps_and_one_writable_lock(self):
        text = guard.guard_unit_text()
        directive = f"LoadCredential={guard.RELEASE_CREDENTIAL}:{guard.DEPLOY_SHA}\n"
        self.assertIn(directive, text)
        self.assertEqual(text.count("LoadCredential="), 1)
        self.assertEqual(guard.legacy_guard_unit_text(), text.replace(directive, ""))
        self.assertIn("NoNewPrivileges=yes", text)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("ReadWritePaths=/run/lock", text)
        self.assertNotIn("CAP_DAC_READ_SEARCH", text)
        self.assertNotIn("ReadWritePaths=/var", text)
        self.assertNotIn("WantedBy=", text)

    def test_owner_upgrade_rejects_unreviewed_guard_unit_before_writing(self):
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "_run", return_value=""), \
             mock.patch.object(guard, "_read_root_file",
                               side_effect=lambda path, *_: ("tampered" if path == guard.GUARD_FILE
                                                            else guard.dropin_text(PINS))), \
             mock.patch.object(guard, "_replace_guard_unit") as replace:
            with self.assertRaisesRegex(guard.GuardError, "guard_unit_legacy_drift"):
                guard.upgrade_unit(UID, GID)
            replace.assert_not_called()

    def test_owner_upgrade_only_replaces_exact_guard_unit_once(self):
        replaced = []
        def approved(path, *_args):
            if path == guard.GUARD_FILE:
                return guard.legacy_guard_unit_text()
            if path == guard.DROPIN:
                return guard.dropin_text(PINS)
            raise AssertionError("unapproved_file_read")
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "_run", return_value="") as run, \
             mock.patch.object(guard, "_read_root_file", side_effect=approved), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_replace_guard_unit",
                               side_effect=lambda body: replaced.append(body)):
            guard.upgrade_unit(UID, GID)
            self.assertEqual(replaced, [guard.guard_unit_text()])
            self.assertTrue(any(args[0][0] == ["systemctl", "daemon-reload"]
                                for args in run.call_args_list))
            self.assertFalse(any(args[0][0][0] == "nft"
                                 for args in run.call_args_list if args[0]))

    def test_owner_upgrade_must_have_explicit_confirmation(self):
        with mock.patch.object(guard, "_identity", return_value=(UID, GID)), \
             mock.patch.object(guard, "_lock") as lock, \
             mock.patch.object(guard, "upgrade_unit") as action:
            self.assertEqual(guard.main(["--upgrade-unit"]), 2)
            lock.assert_not_called()
            action.assert_not_called()

    def test_isolated_python_cli_loads_adjacent_source_not_cwd(self):
        # ExecStart is /usr/bin/python3 -I -B /absolute/path.py --ensure.
        # --help exercises top-level imports without privileges/network.
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "h191_google_egress_candidate.py").write_text(
                "raise RuntimeError(\"untrusted cwd import\")",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(guard.__file__).resolve()), "--help"],
                cwd=tmp, text=True, capture_output=True, timeout=12, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr[:400])
        self.assertIn("--plan", result.stdout)
        self.assertNotIn("untrusted cwd", result.stderr)

    def test_isolated_python_cli_rejects_world_writable_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "h191_gsc_egress_guard.py"
            sibling = root / "h191_google_egress_candidate.py"
            shutil.copy2(Path(guard.__file__), script)
            shutil.copy2(Path(guard.__file__).with_name(sibling.name), sibling)
            sibling.chmod(0o666)
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(script), "--help"],
                cwd=tmp, text=True, capture_output=True, timeout=12, check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public_candidate_source_untrusted", result.stderr)

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
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("ReadWritePaths=/run/lock", text)
        self.assertEqual(guard.LOCK.parent, Path("/run/lock"))
        self.assertNotIn("ReadWritePaths=/\n", text)
        self.assertNotIn("ReadWritePaths=/etc", text)
        self.assertIn("MemoryMax=96M", text)
        self.assertNotIn("WantedBy=", text)
        self.assertNotIn("systemctl start", text)
        self.assertNotIn("ExecStart=/opt/hermes-gsc/venv/", text)
        self.assertNotIn("webmasters", text)

    def test_effective_systemd_guard_and_exact_ip_allowlist(self):
        allow = "127.0.0.0/8 ::1/128 " + " ".join(PINS)
        base = iter(["no", "0.0.0.0/0 ::/0", guard.USER, guard.USER,
                     str(guard.DROPIN), "AF_UNIX AF_INET AF_INET6",
                     allow, "loaded"])
        with mock.patch.object(guard, "_run",
                               side_effect=lambda *_args, **_kw: next(base)):
            guard._installed_unit_trusted(PINS)

    def test_effective_systemd_rejects_broad_ip_allowlist(self):
        bad = iter(["no", "0.0.0.0/0 ::/0", guard.USER, guard.USER,
                    str(guard.DROPIN), "AF_UNIX AF_INET AF_INET6",
                    "127.0.0.0/8 ::1/128 0.0.0.0/0 " + " ".join(PINS)])
        with mock.patch.object(guard, "_run",
                               side_effect=lambda *_args, **_kw: next(bad)):
            with self.assertRaisesRegex(guard.GuardError, "effective_ip_allowlist_drift"):
                guard._installed_unit_trusted(PINS)

    def test_current_dns_change_fails_closed_before_nft_mutation(self):
        with mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
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
             mock.patch.object(guard, "_installed_unit_trusted"), \
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
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_current_pins", return_value=(V4,)), \
             mock.patch.object(guard, "_nft_state", side_effect=["MISSING", "EXACT"]), \
             mock.patch.object(guard, "_nft_create") as create:
            guard.check(UID, GID, ensure=True)
            create.assert_called_once_with(PINS, UID)

    def test_disabled_units_use_successful_show_metadata_not_is_enabled(self):
        # Real Ubuntu systemctl is-enabled disabled prints "disabled" but exits 1.
        # _run(check=False) rejects any nonzero exit; show -P UnitFileState is 0.
        actual = []
        def fake_run(command, **_kwargs):
            actual.append(command)
            if command[3] in ("ActiveState", "UnitFileState"):
                return "inactive" if command[3] == "ActiveState" else "disabled"
            raise AssertionError("unexpected systemctl command")
        with mock.patch.object(guard, "_run", side_effect=fake_run):
            guard._unit_state(install=True)
        self.assertEqual(actual, [
            ["systemctl", "show", "-P", "ActiveState", guard.UNIT],
            ["systemctl", "show", "-P", "UnitFileState", guard.UNIT],
            ["systemctl", "show", "-P", "ActiveState", guard.TIMER],
            ["systemctl", "show", "-P", "UnitFileState", guard.TIMER],
        ])

    def test_enabled_or_masked_units_still_refuse_install(self):
        for state in ("enabled", "masked", "static", "indirect"):
            with self.subTest(state=state):
                def fake_run(command, **_kwargs):
                    return "inactive" if command[3] == "ActiveState" else state
                with mock.patch.object(guard, "_run", side_effect=fake_run):
                    with self.assertRaisesRegex(guard.GuardError, "gsc_unit_not_disabled"):
                        guard._unit_state(install=True)

    def test_untrusted_base_service_blocks_nft_install(self):
        with mock.patch.object(guard, "_run", side_effect=[
            "yes", "0.0.0.0/0 ::/0", "", "AF_UNIX AF_INET",
        ]):
            with self.assertRaisesRegex(guard.GuardError, "original_service_boundary_drift"):
                guard._base_unit_trusted()

    def test_trusted_base_service_has_all_required_fail_closed_properties(self):
        expected = iter(["yes", "0.0.0.0/0 ::/0", "", "AF_UNIX",
                         guard.USER, guard.USER, ""])
        with mock.patch.object(guard, "_run", side_effect=lambda *_args, **_kw: next(expected)):
            guard._base_unit_trusted()

    def test_install_rejects_preexisting_files_before_nft(self):
        policy = mock.Mock()
        policy.exists.return_value = True
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_base_unit_trusted"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "POLICY", policy), \
             mock.patch.object(guard, "_nft_create") as nft:
            with self.assertRaisesRegex(guard.GuardError, "preexisting_policy_files"):
                guard.install(UID, GID)
            nft.assert_not_called()

    def test_install_stages_guard_before_widening_systemd(self):
        order = []
        policy, unit, dropin = (mock.Mock() for _ in range(3))
        for item in (policy, unit, dropin):
            item.exists.return_value = False
            item.is_symlink.return_value = False
        dropin.parent.is_symlink.return_value = False
        policy.parent.lstat.return_value.st_uid = 0
        policy.parent.lstat.return_value.st_gid = GID
        policy.parent.lstat.return_value.st_mode = 0o40750
        dropin.parent.stat.return_value.st_uid = 0
        dropin.parent.stat.return_value.st_mode = 0o40755
        def count_nft(*args): order.append("nft")
        def count_files(path, *_args):
            if path is policy: order.append("pins")
            elif path is unit: order.append("guard_unit")
            elif path is dropin: order.append("dropin")
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_base_unit_trusted"), \
             mock.patch.object(guard, "_key_metadata"), \
             mock.patch.object(guard, "POLICY", policy), \
             mock.patch.object(guard, "GUARD_FILE", unit), \
             mock.patch.object(guard, "DROPIN", dropin), \
             mock.patch.object(guard, "_current_pins", return_value=PINS), \
             mock.patch.object(guard, "_sha", return_value="a" * 40), \
             mock.patch.object(guard, "_nft_create", side_effect=count_nft), \
             mock.patch.object(guard, "_store_text", side_effect=count_files), \
             mock.patch.object(guard, "_run", side_effect=["", "", "no"]), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_installed_unit_trusted"), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"):
            guard.install(UID, GID)
        self.assertEqual(order, ["nft", "pins", "guard_unit", "dropin"])

    def test_owner_rollback_restores_default_deny_before_dropping_owned_nft(self):
        events = []
        policy, unit, dropin = (mock.Mock() for _ in range(3))
        for item in (policy, unit, dropin):
            item.is_file.return_value = True
            item.is_symlink.return_value = False
        policy.unlink.side_effect = lambda: events.append("policy")
        unit.unlink.side_effect = lambda: events.append("guard")
        dropin.unlink.side_effect = lambda: events.append("dropin")
        def run_cmd(parts, **kwargs):
            events.append("systemctl" if parts[0] == "systemctl" else "nft_delete")
            if "PrivateNetwork" in parts:
                return "yes"
            if "RestrictAddressFamilies" in parts:
                return "AF_UNIX"
            return ""
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_base_unit_trusted"), \
             mock.patch.object(guard, "_nft_state", side_effect=["EXACT", "MISSING"]), \
             mock.patch.object(guard, "POLICY", policy), \
             mock.patch.object(guard, "GUARD_FILE", unit), \
             mock.patch.object(guard, "DROPIN", dropin), \
             mock.patch.object(guard, "_run", side_effect=run_cmd):
            guard.rollback(UID, GID)
        self.assertEqual(events[:3], ["dropin", "guard", "policy"])
        self.assertEqual(events[-1], "nft_delete")
        self.assertGreater(events.index("nft_delete"), events.index("systemctl"))

    def test_rollback_unsafe_files_refuse_before_changes(self):
        dropin = mock.Mock()
        dropin.is_file.return_value = False
        with mock.patch.object(guard, "_unit_state"), \
             mock.patch.object(guard, "_read_record", return_value=PINS), \
             mock.patch.object(guard, "_verify_files"), \
             mock.patch.object(guard, "_nft_state", return_value="EXACT"), \
             mock.patch.object(guard, "DROPIN", dropin):
            with self.assertRaisesRegex(guard.GuardError, "rollback_file_untrusted"):
                guard.rollback(UID, GID)
            dropin.unlink.assert_not_called()

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
