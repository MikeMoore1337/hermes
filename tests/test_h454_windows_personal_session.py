"""Personal profile: local synthetic credentials, no real pairing or network."""
from __future__ import annotations

import base64
import json
import os
import ssl
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from device_fabric import windows_personal_session as personal
from device_fabric import native_private_tls as private_tls
from device_fabric.native_brc_enrollment import Paired
from device_fabric.windows_native_dpapi import seal_for_current_user
from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h454_windows_personal_worker as worker
from scripts import h454_windows_personal_state as state

DEVICE = "h454-win-native-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 48
OWNER = "S-1-5-21-1-2-3-1001"
CA_SHA = "d" * 64
FAKE_CA = b"-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----\n"


def config(*, created=900, sealed=b"x" * 64, device=DEVICE):
    obj = {"schema": personal.SCHEMA, "release_sha": "c" * 40, "owner_sid": OWNER, "ca_sha256": CA_SHA,
           "device_id": device, "sealed_bearer_b64": base64.b64encode(sealed).decode(),
           "created_at": created}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class PersonalContracts(unittest.TestCase):
    def test_setup_seals_only_the_fresh_owner_device_without_plaintext(self):
        paired = Paired("windows", DEVICE, TOKEN, "wss://mcp.mikemoore.top/ws")
        seal = Mock(return_value=b"x" * 64)
        raw = personal.prepare_config(paired, owner_sid=OWNER, release_sha="c" * 40,
                                      ca=FAKE_CA, now=1000, seal=seal)
        candidate, owner, ca_hash = personal.parse_config(raw)
        self.assertEqual(owner, OWNER)
        self.assertEqual(candidate.expires_at, 4600)
        self.assertNotIn(TOKEN.encode(), raw)
        seal.assert_called_once_with(TOKEN, manifest_sha256=personal.policy_digest(ca_hash), device_id=DEVICE)

    def test_setup_refuses_revoked_device_and_untrusted_ca(self):
        for paired, ca in ((Paired("windows", "h454-win-01335a1f6e6705b4", TOKEN, "wss://mcp.mikemoore.top/ws"), FAKE_CA),
                           (Paired("yfc-vps", DEVICE, TOKEN, "wss://mcp.mikemoore.top/ws"), FAKE_CA),
                           (Paired("windows", DEVICE, TOKEN, "wss://mcp.mikemoore.top/ws"), b"not-a-ca")):
            seal = Mock()
            with self.assertRaises(personal.PersonalSessionDenied):
                personal.prepare_config(paired, owner_sid=OWNER, release_sha="c" * 40,
                                        ca=ca, now=1000, seal=seal)
            seal.assert_not_called()

    def test_personal_transport_uses_only_existing_loopback_tunnel(self):
        relay = private_tls.PrivateRelay("windows", "c" * 40, private_tls.WINDOWS_LOOPBACK, b"ca")
        with patch.object(private_tls.socket, "create_connection", return_value=object()) as connect:
            private_tls._raw_socket(relay, 8)
        connect.assert_called_once_with(("127.0.0.1", 38184), timeout=8)
        wrong = private_tls.PrivateRelay("yfc-vps", "c" * 40, private_tls.WINDOWS_LOOPBACK, b"ca")
        with self.assertRaises(private_tls.PrivateTLSDenied):
            private_tls._raw_socket(wrong, 8)

    def test_invalid_or_ambiguous_config_fails_closed(self):
        for raw in (b"{}", config(device="h454-win-01335a1f6e6705b4"),
                    config() + b" ", config(sealed=b"x"), config(created=True),
                    b'{"schema":"a","schema":"b"}'):
            with self.subTest(raw=raw[:32]), self.assertRaises(personal.PersonalSessionDenied):
                personal.parse_config(raw)

    def test_owner_future_time_and_revocation_prevent_network(self):
        for verify, created, active in ((False, 900, True), (True, 1001, True),
                                        (True, 900, False)):
            with self.subTest(verify=verify, created=created, active=active):
                connector = Mock()
                unseal = Mock(return_value=TOKEN)
                with patch.object(personal, "run_once") as runner:
                    with self.assertRaises(personal.PersonalSessionDenied):
                        personal.run(config(created=created), user_verified=lambda: OWNER if verify else "S-1-5-18",
                                     connector=connector, unseal=unseal,
                                     owner_status=lambda **_: lambda: active, utcnow=lambda: 1000)
                    runner.assert_not_called()
                connector.assert_not_called()
                if not verify or created > 1000:
                    unseal.assert_not_called()

    def test_old_personal_credential_gets_only_a_fresh_one_hour_session(self):
        now = 90 * 86400
        with patch.object(personal, "run_once", return_value="read_budget_exhausted") as runner:
            personal.run(config(created=900), user_verified=lambda: OWNER, connector=Mock(),
                         unseal=lambda *_a, **_k: TOKEN, owner_status=lambda **_: lambda: True,
                         utcnow=lambda: now)
        self.assertEqual(runner.call_args.args[0].expires_at, now + 3600)

    def test_temporary_outage_retries_but_revocation_denies(self):
        for value, expected in ((None, "temporary_outage"), (False, None)):
            runner = Mock()
            with self.subTest(value=value), patch.object(personal, "run_once", runner):
                if expected is None:
                    with self.assertRaises(personal.PersonalSessionDenied):
                        personal.run(config(), user_verified=lambda: OWNER, connector=Mock(),
                                     unseal=lambda *_a, **_k: TOKEN,
                                     owner_status=lambda **_: lambda: value, utcnow=lambda: 1000)
                else:
                    self.assertEqual(personal.run(config(), user_verified=lambda: OWNER, connector=Mock(),
                        unseal=lambda *_a, **_k: TOKEN, owner_status=lambda **_: lambda: value,
                        utcnow=lambda: 1000), expected)
                runner.assert_not_called()

    def test_expired_session_is_retried_after_live_owner_check(self):
        clock = Mock(side_effect=[1000, 4600])
        with patch.object(personal, "run_once", side_effect=ValueError()):
            result = personal.run(config(), user_verified=lambda: OWNER, connector=Mock(),
                                  unseal=lambda *_a, **_k: TOKEN,
                                  owner_status=lambda **_: lambda: True, utcnow=clock)
        self.assertEqual(result, "session_expired")

    def test_outage_or_revocation_during_session_never_authorizes_io(self):
        for later in (None, False):
            checks = iter((True, later))
            def session(_candidate, **kwargs):
                self.assertFalse(kwargs["owner_pair_verified"]())
                raise ValueError()
            with self.subTest(later=later), patch.object(personal, "run_once", side_effect=session):
                arguments = dict(user_verified=lambda: OWNER, connector=Mock(),
                                 unseal=lambda *_a, **_k: TOKEN,
                                 owner_status=lambda **_: lambda: next(checks), utcnow=lambda: 1000)
                if later is None:
                    self.assertEqual(personal.run(config(), **arguments), "temporary_outage")
                else:
                    with self.assertRaises(personal.PersonalSessionDenied):
                        personal.run(config(), **arguments)

    def test_tls_outage_does_not_turn_bad_certificate_into_retry(self):
        relay = private_tls.PrivateRelay("windows", "c" * 40, private_tls.WINDOWS_LOOPBACK, b"ca")
        for error, expected in ((ConnectionRefusedError(), None), (ssl.SSLError(), False)):
            with self.subTest(error=type(error).__name__), \
                 patch.object(private_tls, "_connection", side_effect=error):
                self.assertIs(private_tls.bearer_state(relay, target="windows", device_id=DEVICE,
                                                       bearer=TOKEN), expected)
                self.assertFalse(private_tls.current_bearer(relay, target="windows", device_id=DEVICE,
                                                             bearer=TOKEN))

    def test_live_owner_status_and_policy_bound_dpapi_are_forwarded(self):
        unseal = Mock(return_value=TOKEN)
        status = Mock(return_value=lambda: True)
        with patch.object(personal, "run_once", return_value="read_budget_exhausted") as runner:
            result = personal.run(config(), user_verified=lambda: OWNER, connector=Mock(),
                                  unseal=unseal, owner_status=status, utcnow=lambda: 1000)
        self.assertEqual(result, "read_budget_exhausted")
        unseal.assert_called_once_with(b"x" * 64, manifest_sha256=personal.policy_digest(CA_SHA), device_id=DEVICE)
        self.assertTrue(runner.call_args.kwargs["bounded_reconnect"])
        self.assertNotIn(TOKEN, repr(personal.parse_config(config())))


@unittest.skipUnless(os.name == "nt", "real Windows DPAPI is required")
class RealWindowsPersonalSession(unittest.TestCase):
    def test_budget_reconnect_reuses_durable_claims_and_stops_on_failure(self):
        from types import SimpleNamespace, ModuleType
        candidate = SimpleNamespace(release_sha="c" * 40, expires_at=int(time.time()) + 120)
        journal = Mock()
        ws = ModuleType("websockets")
        sync = ModuleType("websockets.sync")
        client = ModuleType("websockets.sync.client")
        client.connect = Mock()
        with patch.object(worker.sys, "argv", ["worker", "--run"]), \
             patch.dict(worker.sys.modules, {"websockets": ws, "websockets.sync": sync,
                                             "websockets.sync.client": client}), \
             patch.object(worker, "load_config", return_value=b"synthetic"), \
             patch.object(worker.personal, "parse_config", return_value=(candidate, OWNER, CA_SHA)), \
             patch.object(worker, "load_ca", return_value=FAKE_CA), \
             patch.object(worker, "PersonalReplay", return_value=journal), \
             patch.object(worker.private_tls, "private_websocket_connector", return_value=Mock()), \
             patch.object(worker.personal, "run", side_effect=["read_budget_exhausted", "session_expired",
                          "temporary_outage", "reconnect_budget_exhausted", "fatal"]) as run, \
             patch.object(worker.time, "sleep") as sleep:
            self.assertEqual(worker.main(), 2)
        self.assertEqual(run.call_count, 5)
        self.assertTrue(all(call.kwargs["claim_call"] == journal.claim for call in run.call_args_list))
        self.assertTrue(all(call.kwargs["legacy_catalog"] is True for call in run.call_args_list))
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 5, 60, 60])

    def test_one_time_private_state_does_not_overwrite(self):
        paired = Paired("windows", DEVICE, TOKEN, "wss://mcp.mikemoore.top/ws")
        with tempfile.TemporaryDirectory(prefix="h454-personal-fixture-") as folder, \
             patch.dict(os.environ, {"LOCALAPPDATA": folder}), \
             patch.object(state, "load_ca", return_value=FAKE_CA), \
             patch.object(state.private_tls, "current_bearer", return_value=True):
            state.persist_new(paired, release_sha="c" * 40, ca=FAKE_CA)
            path = Path(folder) / "HermesCommanderPersonal" / "device.json"
            before = path.read_bytes()
            self.assertNotIn(TOKEN.encode(), before)
            candidate, sid, _ = personal.parse_config(before)
            self.assertEqual(sid, worker.current_sid())
            self.assertEqual(candidate.device_id, DEVICE)
            command = ("Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop; "
                "$a=Get-Acl -LiteralPath $env:H454_TEST_DIR; "
                "$u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
                "$allowed=@($u,'S-1-5-18','S-1-5-32-544'); "
                "if (-not $a.AreAccessRulesProtected -or "
                "$a.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $u) {exit 1}; "
                "$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); "
                "if ($rules.Count -ne 3) {exit 3}; foreach($r in $rules) "
                "{if ($r.IsInherited -or $r.AccessControlType -ne 'Allow' -or "
                "$r.IdentityReference.Value -notin $allowed -or "
                "($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne "
                "[Security.AccessControl.FileSystemRights]::FullControl) {exit 2}}")
            env = {**os.environ, "H454_TEST_DIR": str(path.parent)}
            result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32" /
                "WindowsPowerShell" / "v1.0" / "powershell.exe"), "-NoProfile", "-NonInteractive",
                "-Command", command], env=env, capture_output=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, "private DACL check failed: " + result.stderr.decode(errors="replace"))
            with self.assertRaises(personal.PersonalSessionDenied):
                state.persist_new(paired, release_sha="c" * 40, ca=FAKE_CA)
            self.assertEqual(path.read_bytes(), before)

    def test_process_sid_is_real_and_another_user_is_denied(self):
        sid = worker.current_sid()
        self.assertRegex(sid, personal.SID)
        self.assertNotEqual(sid, "S-1-5-18")
        unseal = Mock(return_value=TOKEN)
        with self.assertRaises(personal.PersonalSessionDenied):
            personal.run(config(), user_verified=worker.current_sid, connector=Mock(),
                         unseal=unseal, owner_status=Mock(), utcnow=lambda: 1000)
        unseal.assert_not_called()

    def test_dpapi_and_transport_read_use_the_actual_current_user(self):
        sealed = seal_for_current_user(TOKEN, manifest_sha256=personal.policy_digest(CA_SHA), device_id=DEVICE)
        now = int(time.time())
        class Socket:
            def __init__(self): self.index = 0
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def send(self, _message): pass
            def recv(self, timeout=None):
                self.index += 1
                if self.index == 1:
                    return json.dumps({"type": "welcome", "protocol": 1,
                                       "relayVersion": "test", "serverTime": now})
                return json.dumps({"type": "call", "id": f"test-{self.index}",
                    "tool": "native_file_stat", "args": {"project": "hermes", "relative": "README.md"}})
        result = {"status": "ok", "project": "hermes", "relative": "README.md",
                  "action": "stat", "kind": "file", "size_bytes": 3}
        with patch.object(mcp.native, "handle_native_request", return_value=result) as reader:
            outcome = personal.run(config(created=now, sealed=sealed),
                user_verified=lambda: OWNER, connector=lambda *_a, **_k: Socket(),
                owner_status=lambda **_: lambda: True)
        self.assertEqual(outcome, "read_budget_exhausted")
        self.assertEqual(reader.call_count, 16)

    def test_changed_ca_hash_cannot_decrypt_the_saved_bearer(self):
        sealed = seal_for_current_user(TOKEN, manifest_sha256=personal.policy_digest(CA_SHA), device_id=DEVICE)
        obj = json.loads(config(created=int(time.time()), sealed=sealed))
        obj["ca_sha256"] = "e" * 64
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        status = Mock()
        with self.assertRaises(personal.PersonalSessionDenied):
            personal.run(raw, user_verified=lambda: OWNER, connector=Mock(), owner_status=status)
        status.assert_not_called()


def load_tests(loader, tests, pattern):
    return tests if os.name == "nt" else loader.loadTestsFromTestCase(PersonalContracts)
