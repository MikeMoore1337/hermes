"""Synthetic paired-upgrade host admission; no real host or credential."""
from types import SimpleNamespace
from contextlib import ExitStack
from pathlib import Path
import hashlib
import os
import stat
import unittest
from unittest.mock import patch

from scripts import h454_native_paired_host as host
from scripts.h454_native_paired_rebind import RebindDenied


def properties(*, active="failed"):
    return {
        "FragmentPath": "/etc/systemd/system/hermes-commander-native.service",
        "LoadState": "loaded", "ActiveState": active, "UnitFileState": "disabled",
        "User": "hermes-commander-native", "Group": "hermes-commander-native",
        "DropInPaths": "", "NeedDaemonReload": "no", "RestrictSUIDSGID": "no",
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "PrivateNetwork": "no",
        "IPAddressDeny": "::/0 0.0.0.0/0", "IPAddressAllow": "172.29.251.2/32",
    }


class PairedHostAdmissionTests(unittest.TestCase):
    def test_failed_disabled_service_with_complete_deny_is_inert(self):
        with patch.object(host, "raw_show", return_value=properties()), \
             patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=b"MainPID=0\nSubState=failed\n")):
            host._check_unit("hermes-commander-native.service", "172.29.251.2")

    def test_running_weakened_or_widened_service_is_rejected(self):
        cases = (
            {"ActiveState": "active"}, {"UnitFileState": "enabled"},
            {"DropInPaths": "/unexpected"}, {"NeedDaemonReload": "yes"},
            {"IPAddressDeny": "0.0.0.0/0"}, {"IPAddressAllow": "172.29.251.2/32 8.8.8.8/32"},
            {"NoNewPrivileges": "no"},
        )
        for change in cases:
            with self.subTest(change=change), patch.object(host, "raw_show",
                    return_value={**properties(), **change}), \
                 patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout=b"MainPID=0\nSubState=failed\n")), \
                 self.assertRaises(RebindDenied):
                host._check_unit("hermes-commander-native.service", "172.29.251.2")
        with patch.object(host, "raw_show", return_value=properties()), \
             patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=b"MainPID=123\nSubState=failed\n")), \
             self.assertRaises(RebindDenied):
            host._check_unit("hermes-commander-native.service", "172.29.251.2")

    def test_plan_repr_never_discloses_secret_values(self):
        plan = host.HostPlan(None, b"private-path", b"synthetic-bearer", b"private-trust",
                             {}, b"bundle", b"receipt", b"wheel", 972, 968)
        self.assertEqual(repr(plan), "HostPlan([REDACTED])")

    @unittest.skipUnless(os.name == "posix", "Linux host admission only")
    def test_inspection_binds_snapshots_and_fails_on_service_user_process(self):
        import pwd
        manifest, device, trust, ca, unit = (b"synthetic-manifest", b"synthetic-device",
                                             b"synthetic-trust", b"synthetic-ca", b"synthetic-unit")
        values = {
            "manifest.json": manifest, "device.json": device, "private-relay.json": trust,
            "ca.crt": ca, "h454-native-linux-readonly.tar.gz": b"bundle",
            "h454-native-bundle-receipt.json": b"receipt", "websockets-17.2-py3-none-any.whl": b"wheel",
            "hermes-commander-native.service": unit,
            "hermes-commander-native-preflight.service": unit,
            "synthetic.py": b"source",
        }
        uid, gid = 12345, 12346
        meta = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_gid=gid)
        transition = object()
        def get_file(path, *args, **kwargs):
            return values[path.name]
        def patches(stack, pgrep_result):
            stack.enter_context(patch.object(host.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(host.socket, "gethostname", return_value="vps1777112993"))
            stack.enter_context(patch.object(pwd, "getpwnam", return_value=SimpleNamespace(
                pw_uid=uid, pw_gid=gid, pw_shell="/usr/sbin/nologin")))
            stack.enter_context(patch.object(Path, "lstat", return_value=meta))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
            stack.enter_context(patch.object(host, "owned_directory"))
            stack.enter_context(patch.object(host, "checked_file", side_effect=get_file))
            stack.enter_context(patch.object(host, "MANIFEST_SHA", hashlib.sha256(manifest).hexdigest()))
            stack.enter_context(patch.object(host, "TRUST_SHA", hashlib.sha256(trust).hexdigest()))
            stack.enter_context(patch.object(host, "CA_SHA", hashlib.sha256(ca).hexdigest()))
            stack.enter_context(patch.object(host, "WHEEL_SHA", hashlib.sha256(b"wheel").hexdigest()))
            stack.enter_context(patch.object(host, "OLD_BLOBS", {"device_fabric/synthetic.py": host._blob(b"source")}))
            stack.enter_context(patch.object(host, "UNIT_SHA", {name: hashlib.sha256(unit).hexdigest()
                for name in ("hermes-commander-native.service", "hermes-commander-native-preflight.service")}))
            stack.enter_context(patch.object(host, "load_private_relay", return_value=SimpleNamespace(relay_ipv4="172.29.251.2")))
            stack.enter_context(patch.object(host, "_check_unit"))
            stack.enter_context(patch.object(host.subprocess, "run", return_value=SimpleNamespace(returncode=pgrep_result)))
            stack.enter_context(patch.object(host, "verify_wheel"))
            stack.enter_context(patch.object(host, "build_transition", return_value=transition))
        with ExitStack() as stack:
            patches(stack, 1)
            plan = host.inspect()
            self.assertIs(plan.transition, transition)
            self.assertNotIn("synthetic-device", repr(plan))
        with ExitStack() as stack:
            patches(stack, 0)
            with self.assertRaisesRegex(RebindDenied, "^native_paired_host_denied$"):
                host.inspect()


if __name__ == "__main__":
    unittest.main()
