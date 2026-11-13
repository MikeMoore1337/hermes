"""H454 Stage 2A native Linux systemd READ worker, no real host activation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from device_fabric.native_install_preview import SCHEMA, SERVICE
from scripts import h454_native_linux_active_unit as unit
from scripts import h454_native_linux_service as service

RELEASE = "a" * 40
TARGET = "hermes-vps"
ROOTS = [{"project": "hermes", "path": "/srv/hermes/source"}]


def manifest(*, target: str = TARGET, roots=None) -> bytes:
    name, identity = SERVICE[target]
    data = {
        "schema": SCHEMA, "target": target, "release_sha": RELEASE,
        "artifact_sha256": "c" * 64,
        "service_name": name, "service_identity": identity,
        "start_state": "DISABLED", "access_mode": "READ_ONLY",
        "roots": ROOTS if roots is None else roots,
    }
    return json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()


def render(*, target: str = TARGET, roots=None, relay: str = "8.8.4.4",
           dns: str = "1.1.1.1", source: bytes | None = None) -> str:
    raw = manifest(target=target,roots=roots) if source is None else source
    return unit.render_active_unit(
        raw, target=target, release_sha=RELEASE,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        relay_ipv4=relay, dns_ipv4=dns,
    )


def kernel_status(*, uid: int = 2001, gid: int = 2001,
                  caps: str = "0000000000000000",
                  privilege: str = "1", seccomp: str = "2") -> str:
    return "\n".join([
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}",
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}",
        f"NoNewPrivs:\t{privilege}",
        f"Seccomp:\t{seccomp}",
        *[f"{key}:\t{caps}" for key in service.PROC_CAPS],
    ])


def hardening_properties() -> str:
    return "\n".join(
        [f"{key}={value}" for key,value in service.EXPECTED_HARDENING.items()]
        + ["IPAddressDeny=any", "IPAddressAllow=8.8.4.4/32 1.1.1.1/32",
           "CapabilityBoundingSet="]
    )


class RealLinuxUnitRenderTests(unittest.TestCase):
    def test_explicit_original_read_roots_disabled_until_owner_enables(self):
        for target in ("hermes-vps","yfc-vps"):
            with self.subTest(target=target):
                text=render(target=target)
                self.assertIn("Type=exec", text)
                self.assertIn("User=hermes-commander-native", text)
                self.assertIn("Group=hermes-commander-native", text)
                self.assertIn("NoNewPrivileges=yes", text)
                self.assertIn("CapabilityBoundingSet=\n", text)
                self.assertIn("ProtectSystem=strict", text)
                self.assertIn("PrivateNetwork=no", text)
                self.assertIn("IPAddressDeny=any", text)
                self.assertIn("IPAddressAllow=8.8.4.4/32", text)
                self.assertIn("IPAddressAllow=1.1.1.1/32", text)
                self.assertIn("ReadOnlyPaths=/srv/hermes/source", text)
                self.assertIn("ReadOnlyPaths=/var/lib/hermes-commander-native", text)
                pinned="/opt/hermes-commander-native/deps/main-"+RELEASE
                self.assertIn("Environment=PYTHONPATH="+pinned, text)
                self.assertIn("AssertPathExists="+pinned+"/websockets/sync/client.py", text)
                self.assertIn("ReadOnlyPaths="+pinned, text)
                self.assertIn("--run-once --target "+target, text)
                self.assertIn("--manifest-sha256 ", text)
                self.assertIn("Restart=on-success", text)
                self.assertIn("RuntimeMaxSec=300s", text)
                self.assertIn("[Install]\nWantedBy=multi-user.target", text)
                self.assertNotIn("ExecStartPre=/bin/sh", text)
                self.assertNotIn("ReadWritePaths=", text)
                self.assertNotIn("ExecStart=/bin/bash", text)

    def test_openat2_requires_seccomp_compatible_fixed_service_identity(self):
        # systemd's RestrictSUIDSGID=yes blocks openat2 even for O_PATH.
        # Do not replace the native FD adapter with an unsafe openat fallback.
        text = render()
        self.assertIn("RestrictSUIDSGID=no\n", text)
        self.assertNotIn("RestrictSUIDSGID=yes", text)
        for protection in (
            "User=hermes-commander-native",
            "Group=hermes-commander-native",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=\n",
            "AmbientCapabilities=\n",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "PrivateTmp=yes",
            "RestrictNamespaces=yes",
            "MemoryDenyWriteExecute=yes",
            "SystemCallFilter=~@mount @reboot @swap",
            "IPAddressDeny=any",
        ):
            self.assertIn(protection, text)
        self.assertEqual(service.EXPECTED_HARDENING["RestrictSUIDSGID"], "no")
        self.assertTrue(service._properties_are_hardened(hardening_properties()))
        for invalid in ("yes", "", "unknown"):
            with self.subTest(invalid=invalid):
                wrong = hardening_properties().replace(
                    "RestrictSUIDSGID=no", "RestrictSUIDSGID=" + invalid)
                self.assertFalse(service._properties_are_hardened(wrong))

    def test_dual_relay_and_host_local_dns_stub_are_exactly_bounded(self):
        text = render(
            relay="104.21.57.247,172.67.167.145",
            dns="127.0.0.53",
        )
        for address in (
            "104.21.57.247", "172.67.167.145", "127.0.0.53",
        ):
            self.assertIn("IPAddressAllow=" + address + "/32", text)
        self.assertEqual(text.count("IPAddressAllow="), 3)
        self.assertIn("IPAddressDeny=any", text)
        self.assertTrue(service._properties_are_hardened(
            hardening_properties().replace(
                "IPAddressAllow=8.8.4.4/32 1.1.1.1/32",
                "IPAddressAllow=104.21.57.247/32 "
                "172.67.167.145/32 127.0.0.53/32",
            )
        ))
        self.assertFalse(service._properties_are_hardened(
            hardening_properties().replace(
                "IPAddressAllow=8.8.4.4/32 1.1.1.1/32",
                "IPAddressAllow=104.21.57.247/32 "
                "172.67.167.145/32 127.0.0.1/32",
            )
        ))
        self.assertFalse(service._properties_are_hardened(
            hardening_properties().replace(
                "IPAddressAllow=8.8.4.4/32 1.1.1.1/32",
                "IPAddressAllow=104.21.57.247/32 "
                "172.67.167.145/32 10.0.0.1/32",
            )
        ))

    def test_untrusted_ipv4_broad_or_widened_paths_fail_closed(self):
        cases=[
            {"relay":"127.0.0.1"},
            {"relay":"8.8.4.4,8.8.4.4"},
            {"relay":"8.8.4.4, 9.9.9.9"},
            {"relay":"8.8.4.4,9.9.9.9,1.1.1.1"},
            {"relay":"8.8.4.4,127.0.0.53"},
            {"relay":"10.0.0.1"},
            {"relay":"169.254.169.254"},
            {"dns":"192.168.0.1"},
            {"dns":"127.0.0.1"},
            {"dns":"8.8.4.4"},
            {"relay":"8.8.4.4/0"},
            {"relay":"evil.example"},
            {"roots":[{"project":"hermes","path":"/etc"}]},
            {"roots":[{"project":"hermes","path":"/srv/source with spaces"}]},
            {"source":manifest()+b"\n"},
            {"target":"windows"},
        ]
        for change in cases:
            with self.subTest(case=str(change)[:90]), \
                 self.assertRaises(unit.LinuxActiveUnitDenied):
                render(**change)

    @unittest.skipUnless(sys.platform=="linux" and shutil.which("systemd-analyze"),
                         "actual systemd syntax verifier only on Linux CI")
    def test_systemd_analyze_accepts_real_service_unit(self):
        with tempfile.TemporaryDirectory(prefix="h454-active-unit-syntax-") as tmp:
            dest=Path(tmp)/unit.UNIT_NAME
            dest.write_text(render())
            result=subprocess.run(
                ["systemd-analyze","verify",str(dest)],
                capture_output=True,timeout=10,check=False,
            )
        self.assertEqual(result.returncode,0,"H454_ACTIVE_SYSTEMD_SYNTAX_INVALID")


class OSIsolationKernelTests(unittest.TestCase):
    def test_actual_kernel_status_and_systemd_hardening_contract(self):
        expected_cgroup="0::/system.slice/hermes-commander-native.service\n"
        invocation="e"*32
        self.assertTrue(service._kernel_evidence(
            kernel_status(),expected_cgroup,invocation,uid=2001,gid=2001))
        self.assertTrue(service._properties_are_hardened(hardening_properties()))
        for changed in (
            {"caps":"0000000000000001"},
            {"privilege":"0"},
            {"seccomp":"0"},
            {"uid":0},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(service._kernel_evidence(
                    kernel_status(**changed),expected_cgroup,invocation,
                    uid=2001,gid=2001))
        for cg in (
            "0::/user.slice/session-3.scope",
            "0::/system.slice/docker.scope",
            "0::/system.slice/hermes-commander-native.service/child",
            "0::/system.slice/other.service",
            "bad\n",
        ):
            with self.subTest(cgroup=cg):
                self.assertFalse(service._kernel_evidence(
                    kernel_status(),cg,invocation,uid=2001,gid=2001))
        for bad in (
            hardening_properties().replace("ProtectSystem=strict","ProtectSystem=full"),
            hardening_properties().replace("PrivateNetwork=no","PrivateNetwork=yes"),
            hardening_properties().replace("IPAddressDeny=any","IPAddressDeny="),
            hardening_properties().replace("NoNewPrivileges=yes","NoNewPrivileges=no"),
            hardening_properties()+"\nUser=root",
        ):
            with self.subTest(policy=bad[:100]):
                self.assertFalse(service._properties_are_hardened(bad))

    def test_python_system_package_does_not_satisfy_pinned_wheel(self):
        # Hosted CI is not an original VPS, and system/global pip is never
        # a release-scoped dependency proof.
        self.assertFalse(service._pinned_websocket_dependency(RELEASE))
        self.assertFalse(service._pinned_websocket_dependency("invalid"))

    def test_unprivileged_host_without_real_systemd_is_denied(self):
        with patch.object(service,"_service_identity"), \
             patch.object(service,"STATUS",SimpleNamespace(
                 read_text=lambda **_: kernel_status())), \
             patch.object(service,"CGROUP",SimpleNamespace(
                 read_text=lambda **_: "0::/user.slice/session-3.scope")), \
             patch.dict(service.os.environ,{"INVOCATION_ID":"e"*32}):
            self.assertFalse(service.real_os_isolation_verified())


class LiveWorkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fake=SimpleNamespace(device=SimpleNamespace(
            device_id="h454-linux-hermes-"+"c"*32,
            token="brc_dev_"+"x"*64,target="hermes-vps"))
        self.transport=Mock()
        self.os_gate=Mock(return_value=True)
        self.status_factory=Mock(return_value=lambda:False)

    def test_real_worker_composes_existing_native_wss_and_owner_revocation(self):
        with patch.object(service,"_service_identity"), \
             patch.object(service,"load_local_runtime",return_value=self.fake) as load, \
             patch.object(service,"run_once",return_value="session_deadline") as read:
            outcome=service.run_trusted_once(
                target=TARGET,release_sha=RELEASE,
                manifest_sha256="d"*64,
                connector=self.transport,os_gate=self.os_gate,
                status_factory=self.status_factory,
            )
        self.assertEqual(outcome,"session_deadline")
        self.status_factory.assert_called_once_with(
            target=TARGET,device_id=self.fake.device.device_id,
            bearer=self.fake.device.token,base_url=service.PUBLIC)
        read.assert_called_once()
        self.assertIs(read.call_args.kwargs["connector"],self.transport)
        self.assertTrue(callable(read.call_args.kwargs["is_device_revoked"]))
        self.assertIs(read.call_args.kwargs["is_os_isolation_verified"],self.os_gate)
        self.assertGreaterEqual(self.os_gate.call_count,3)
        self.assertEqual(load.call_args.kwargs["manifest_path"],
                         Path(service.MANIFEST_PATH))
        self.assertEqual(load.call_args.kwargs["config_path"],
                         Path(service.CONFIG_PATH))

    def test_revoked_or_isolation_denied_before_network(self):
        for gates in ((False,lambda:False),(True,lambda:True)):
            with self.subTest(gates=gates), \
                 patch.object(service,"_service_identity"), \
                 patch.object(service,"load_local_runtime",
                     return_value=self.fake), \
                 patch.object(service,"run_once") as read:
                with self.assertRaises(service.NativeLinuxServiceDenied):
                    service.run_trusted_once(
                        target=TARGET,release_sha=RELEASE,
                        manifest_sha256="d"*64,connector=self.transport,
                        os_gate=lambda:gates[0],
                        status_factory=lambda **_:gates[1])
                read.assert_not_called()

    def test_user_controlled_cli_cannot_bypass_os_proof(self):
        args=[
            "--run-once","--target",TARGET,
            "--release-sha",RELEASE,
            "--manifest-sha256","d"*64,
        ]
        with patch.object(service,"real_os_isolation_verified",
                          return_value=False), \
             patch.object(service,"_service_identity"), \
             patch.object(service,"load_local_runtime") as load:
            self.assertEqual(service.main(args),2)
            load.assert_not_called()
        with patch.object(service,"real_os_isolation_verified",
                          return_value=False):
            with self.assertRaises(SystemExit) as exc:
                service.main(args+["--bypass-os"])
            self.assertEqual(exc.exception.code, 2)


if __name__=="__main__":
    unittest.main()
