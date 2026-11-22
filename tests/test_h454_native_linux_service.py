"""H454 Stage 2A native Linux systemd READ worker, no real host activation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
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
                self.assertIn("InaccessiblePaths=-/srv/hermes/source/.git", text)
                self.assertIn("ReadOnlyPaths=/var/lib/hermes-commander-native", text)
                pinned="/opt/hermes-commander-native/deps/main-"+RELEASE
                self.assertIn("Environment=PYTHONPATH="+pinned, text)
                self.assertIn("AssertPathExists="+pinned+"/websockets/asyncio/client.py", text)
                self.assertIn("TemporaryFileSystem=/run:ro\n", text)
                self.assertIn("BindReadOnlyPaths="+service.AUDIT_DIRECTORY+"\n", text)
                self.assertIn("LimitNOFILE=32768\n", text)
                self.assertIn("Requires=hermes-commander-audit.socket\n", text)
                self.assertNotIn("Requires=hermes-commander-tunnel.service\n", text)
                self.assertIn("ReadOnlyPaths="+pinned, text)
                self.assertIn("--run-once --target "+target, text)
                self.assertIn("--manifest-sha256 ", text)
                self.assertIn("Restart=on-success", text)
                self.assertIn("RestartSec=5s", text)
                self.assertIn("StartLimitBurst=3", text)
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
            from scripts.h454_native_linux_audit_unit import render_audit_units
            socket_unit,audit_unit=render_audit_units()
            (Path(tmp)/'hermes-commander-audit.socket').write_text(socket_unit)
            (Path(tmp)/'hermes-commander-audit@.service').write_text(audit_unit)
            dest=Path(tmp)/unit.UNIT_NAME
            dest.write_text(render())
            result=subprocess.run(
                ["systemd-analyze","verify",str(dest)],
                capture_output=True,timeout=10,check=False,
            )
        self.assertEqual(result.returncode,0,"H454_ACTIVE_SYSTEMD_SYNTAX_INVALID")


class OSIsolationKernelTests(unittest.TestCase):
    def test_git_mask_must_match_every_protected_root(self):
        roots = ("/srv/hermes/source", "/srv/other/source")
        text = hardening_properties() + (
            "\nInaccessiblePaths=-/srv/hermes/source/.git -/srv/other/source/.git")
        self.assertTrue(service._properties_are_hardened(text, git_roots=roots))
        self.assertFalse(service._properties_are_hardened(
            text.replace(" -/srv/other/source/.git", ""), git_roots=roots))
        self.assertFalse(service._properties_are_hardened(
            text.replace("-/srv/hermes/source/.git", "-/srv/hermes/other/.git"),
            git_roots=roots))

    def test_effective_git_access_denies_isolation_even_with_manager_mask(self):
        root = "/srv/hermes/source"
        properties = hardening_properties() + "\nInaccessiblePaths=-" + root + "/.git"
        proc = SimpleNamespace(returncode=0, stdout=properties.encode("ascii"))
        with patch.object(service, "_service_identity"), \
             patch.object(service, "_kernel_evidence", return_value=True), \
             patch.object(service, "STATUS", SimpleNamespace(read_text=lambda **_: "status")), \
             patch.object(service, "CGROUP", SimpleNamespace(read_text=lambda **_: "cgroup")), \
             patch.object(service.subprocess, "run", return_value=proc), \
             patch.dict(service.os.environ, {"INVOCATION_ID":"e"*32}), \
             patch.object(Path, "lstat", return_value=SimpleNamespace()), \
             patch.object(service.os, "access", return_value=False) as access:
            self.assertTrue(service.real_os_isolation_verified(git_roots=(root,)))
            access.assert_any_call(Path(root) / ".git", os.R_OK)
            access.assert_any_call(Path(root) / ".git", os.X_OK)
            access.side_effect = lambda _path, mode: mode == os.X_OK
            self.assertFalse(service.real_os_isolation_verified(git_roots=(root,)))

    def test_absent_git_is_allowed_but_unexpected_metadata_error_denied(self):
        root = "/srv/hermes/source"
        properties = hardening_properties() + "\nInaccessiblePaths=-" + root + "/.git"
        proc = SimpleNamespace(returncode=0, stdout=properties.encode("ascii"))
        with patch.object(service, "_service_identity"), \
             patch.object(service, "_kernel_evidence", return_value=True), \
             patch.object(service, "STATUS", SimpleNamespace(read_text=lambda **_: "status")), \
             patch.object(service, "CGROUP", SimpleNamespace(read_text=lambda **_: "cgroup")), \
             patch.object(service.subprocess, "run", return_value=proc), \
             patch.dict(service.os.environ, {"INVOCATION_ID":"e"*32}), \
             patch.object(Path, "lstat", side_effect=FileNotFoundError) as stat:
            self.assertTrue(service.real_os_isolation_verified(git_roots=(root,)))
            stat.side_effect = OSError
            self.assertFalse(service.real_os_isolation_verified(git_roots=(root,)))

    def test_systemd_all_address_denials_accept_both_families_only(self):
        public = hardening_properties()
        private = public.replace("IPAddressAllow=8.8.4.4/32 1.1.1.1/32",
                                 "IPAddressAllow=172.29.251.2/32")
        for properties, relay in ((public, None), (private, "172.29.251.2")):
            for deny in ("any", "0.0.0.0/0 ::/0", "::/0 0.0.0.0/0"):
                with self.subTest(relay=relay, deny=deny):
                    self.assertTrue(service._properties_are_hardened(
                        properties.replace("IPAddressDeny=any", "IPAddressDeny=" + deny),
                        private_relay_ip=relay))
            for deny in ("", "0.0.0.0/0", "::/0", "0.0.0.0/1 ::/0",
                         "0.0.0.0/0 ::/0 127.0.0.1/32", "any 0.0.0.0/0",
                         "0.0.0.0/0 ::/0 ::/0"):
                with self.subTest(relay=relay, deny=deny):
                    self.assertFalse(service._properties_are_hardened(
                        properties.replace("IPAddressDeny=any", "IPAddressDeny=" + deny),
                        private_relay_ip=relay))

    def test_yfc_kernel_must_deny_both_inet_socket_families(self):
        with patch.object(service.socket, 'socket', side_effect=PermissionError(service.errno.EPERM, 'denied')) as create:
            self.assertTrue(service._inet_socket_creation_denied())
            self.assertEqual(create.call_count, 4)
        opened=Mock()
        with patch.object(service.socket, 'socket', return_value=opened):
            self.assertFalse(service._inet_socket_creation_denied())
            opened.close.assert_called_once()
        with patch.object(service.socket, 'socket', side_effect=OSError(service.errno.EMFILE, 'full')):
            self.assertFalse(service._inet_socket_creation_denied())

    def test_yfc_run_mount_must_be_read_only_tmpfs(self):
        line='33 1 0:42 / /run ro,nosuid - tmpfs tmpfs ro,size=1024\n'
        self.assertTrue(service._private_run_mount(line))
        self.assertFalse(service._private_run_mount(line.replace(' - tmpfs ', ' - ext4 ')))
        self.assertFalse(service._private_run_mount(line.replace('/run ro,', '/run rw,')))
        self.assertFalse(service._private_run_mount(line+line))
        self.assertFalse(service._private_run_mount('malformed'))

    def test_audit_socket_requires_root_manager_and_bounded_response(self):
        folder=SimpleNamespace(st_mode=service.stat.S_IFDIR | 0o755,st_uid=0)
        endpoint=SimpleNamespace(st_mode=service.stat.S_IFSOCK | 0o660,st_uid=0,st_gid=321)
        client=Mock()
        client.getsockopt.return_value=service.struct.pack('3i',1,0,0)
        client.recv.side_effect=[b'PrivateNetwork=yes\n',b'']
        sock=Mock();sock.__enter__=Mock(return_value=client);sock.__exit__=Mock(return_value=False)
        with patch.object(Path,'lstat',side_effect=[folder,endpoint]), \
             patch.object(service.os,'getegid',return_value=321), \
             patch.object(service.socket,'socket',return_value=sock):
            self.assertEqual(service._audit_properties(),'PrivateNetwork=yes\n')
        client.getsockopt.return_value=service.struct.pack('3i',222,0,0)
        with patch.object(Path,'lstat',side_effect=[folder,endpoint]), \
             patch.object(service.os,'getegid',return_value=321), \
             patch.object(service.socket,'socket',return_value=sock), \
             self.assertRaises(service.NativeLinuxServiceDenied):
            service._audit_properties()
        client.getsockopt.return_value=service.struct.pack('3i',1,0,0)
        client.recv.side_effect=[b'x'*16385]
        with patch.object(Path,'lstat',side_effect=[folder,endpoint]), \
             patch.object(service.os,'getegid',return_value=321), \
             patch.object(service.socket,'socket',return_value=sock), \
             self.assertRaises(service.NativeLinuxServiceDenied):
            service._audit_properties()
        bad=SimpleNamespace(st_mode=service.stat.S_IFSOCK | 0o666,st_uid=0,st_gid=321)
        with patch.object(Path,'lstat',side_effect=[folder,bad]), \
             patch.object(service.os,'getegid',return_value=321), \
             patch.object(service.socket,'socket') as create, \
             self.assertRaises(service.NativeLinuxServiceDenied):
            service._audit_properties()
        create.assert_not_called()

    def test_yfc_gate_denies_if_kernel_allows_inet(self):
        with patch.object(service.sys, 'platform', 'linux'), \
             patch.object(service, '_service_identity'), \
             patch.object(service.os, 'geteuid', return_value=1234), \
             patch.object(service.os, 'getegid', return_value=1234), \
             patch.object(service, 'STATUS', SimpleNamespace(read_text=lambda **_: 'status')), \
             patch.object(service, 'CGROUP', SimpleNamespace(read_text=lambda **_: 'cgroup')), \
             patch.object(service, '_kernel_evidence', return_value=True), \
             patch.object(service, '_inet_socket_creation_denied', return_value=False) as denied, \
             patch.object(service.subprocess, 'run') as systemctl, \
             patch.dict(service.os.environ, {'INVOCATION_ID':'e'*32}):
            self.assertFalse(service.real_os_isolation_verified(
                private_relay_ip=service.UNIX_ENDPOINT,target='yfc-vps',expected_identity=(1234,1234)))
            denied.assert_called_once()
            systemctl.assert_not_called()

    def test_yfc_gate_rejects_changed_cached_identity(self):
        read=Mock()
        with patch.object(service.sys,'platform','linux'), \
             patch.object(service.os,'geteuid',return_value=1234), \
             patch.object(service.os,'getegid',return_value=1234), \
             patch.object(service,'STATUS',SimpleNamespace(read_text=read)):
            self.assertFalse(service.real_os_isolation_verified(
                private_relay_ip=service.UNIX_ENDPOINT,target='yfc-vps',expected_identity=(1235,1234)))
            read.assert_not_called()

    def test_hermes_gate_rechecks_identity_and_uses_only_audit_socket(self):
        values=dict(service.EXPECTED_HARDENING,LimitNOFILE='32768',StandardInput='null',
            StandardOutput='journal',StandardError='journal',TemporaryFileSystem='/run:ro',
            BindPaths='',BindReadOnlyPaths=service.AUDIT_DIRECTORY+':'+service.AUDIT_DIRECTORY+':rbind',
            RestrictAddressFamilies='AF_INET AF_INET6 AF_UNIX',IPAddressDeny='any',
            IPAddressAllow='172.29.251.2/32',CapabilityBoundingSet='')
        properties='\n'.join(k+'='+v for k,v in values.items())
        with patch.object(service.sys,'platform','linux'), \
             patch.object(service.os,'geteuid',return_value=1234), \
             patch.object(service.os,'getegid',return_value=1234), \
             patch.object(service,'STATUS',SimpleNamespace(read_text=lambda **_:'status')), \
             patch.object(service,'CGROUP',SimpleNamespace(read_text=lambda **_:'cgroup')), \
             patch.object(service,'_kernel_evidence',return_value=True), \
             patch.object(service,'_private_run_mount',return_value=True), \
             patch.object(service,'_audit_properties',return_value=properties) as audit, \
             patch.object(service,'_service_identity',side_effect=AssertionError('NSS after confinement')), \
             patch.object(service.subprocess,'run',side_effect=AssertionError('process after confinement')), \
             patch.dict(service.os.environ,{'INVOCATION_ID':'e'*32}):
            self.assertTrue(service.real_os_isolation_verified(private_relay_ip='172.29.251.2',
                target='hermes-vps',expected_identity=(1234,1234)))
            audit.assert_called_once()
            self.assertFalse(service.real_os_isolation_verified(private_relay_ip='172.29.251.2',
                target='hermes-vps',expected_identity=(1235,1234)))

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
            token="brc_dev_"+"x"*64,target="hermes-vps"),
            project_roots=(("hermes", "/srv/hermes/source"),))
        self.transport=Mock()
        self.os_gate=Mock(return_value=True)
        self.status_factory=Mock(return_value=lambda:False)

    def test_cli_uses_default_live_guards_before_connecting(self):
        private = SimpleNamespace(relay_ipv4="172.29.251.2")
        revoked = Mock(return_value=False)
        ws = ModuleType("websockets")
        ws.__path__ = []
        asynchronous = ModuleType("websockets.asyncio")
        asynchronous.__path__ = []
        client = ModuleType("websockets.asyncio.client")
        client.connect = Mock()
        args = ["--run-once", "--target", TARGET, "--release-sha", RELEASE,
                "--manifest-sha256", "d" * 64]
        with patch.dict(sys.modules, {"websockets": ws, "websockets.asyncio": asynchronous,
                                     "websockets.asyncio.client": client}), \
             patch.object(service.os, "geteuid", return_value=1234), \
             patch.object(service.os, "getegid", return_value=1234), \
             patch.object(service, "load_private_relay", return_value=private), \
             patch.object(service, "_service_identity"), \
             patch.object(service, "real_os_isolation_verified", return_value=True) as gate, \
             patch.object(service, "load_local_runtime", return_value=self.fake), \
             patch.object(service, "private_revoked_provider", return_value=revoked), \
             patch.object(service, "_pinned_websocket_dependency", return_value=True), \
             patch.object(service, "private_websocket_connector", return_value=self.transport), \
             patch.object(service, "run_once", return_value="session_deadline") as session:
            self.assertEqual(service.main(args), 0)
            self.assertGreaterEqual(gate.call_count, 3)
            self.assertEqual(gate.call_args_list[0].kwargs,
                             {"private_relay_ip": private.relay_ipv4, "git_roots": (), "target": "hermes-vps", "expected_identity": (1234,1234)})
            self.assertTrue(all(call.kwargs == {
                "private_relay_ip": private.relay_ipv4, "target": "hermes-vps",
                "git_roots": ("/srv/hermes/source",), "expected_identity": (1234,1234)}
                for call in gate.call_args_list[1:]))
            self.assertTrue(session.call_args.kwargs['landlock_read'])
            self.assertIs(session.call_args.kwargs["connector"], self.transport)
            self.assertFalse(session.call_args.kwargs["is_device_revoked"]())

    def test_cli_denies_unmasked_git_before_bearer_or_network(self):
        private = SimpleNamespace(relay_ipv4="172.29.251.2")
        args = ["--run-once", "--target", TARGET, "--release-sha", RELEASE,
                "--manifest-sha256", "d" * 64]
        with patch.object(service, "load_private_relay", return_value=private), \
             patch.object(service, "_service_identity"), \
             patch.object(service, "real_os_isolation_verified",
                          side_effect=lambda **kw: not kw.get("git_roots")) as gate, \
             patch.object(service, "load_local_runtime", return_value=self.fake) as load, \
             patch.object(service, "private_revoked_provider") as status, \
             patch.object(service, "run_once") as session:
            self.assertEqual(service.main(args), 2)
            load.assert_called_once()
            self.assertEqual(gate.call_args_list[-1].kwargs["git_roots"],
                             ("/srv/hermes/source",))
            status.assert_not_called()
            session.assert_not_called()

    def test_yfc_cli_requires_landlock_and_verified_identity(self):
        private=SimpleNamespace(relay_ipv4=service.UNIX_ENDPOINT)
        prepared=SimpleNamespace(device=SimpleNamespace(device_id='h454-linux-yfc-'+'a'*32,
            token='brc_dev_'+'x'*64),project_roots=(('your-fitness-coach','/srv/yfc/source'),))
        ws=ModuleType('websockets');ws.__path__=[]
        asynchronous=ModuleType('websockets.asyncio');asynchronous.__path__=[]
        client=ModuleType('websockets.asyncio.client');client.connect=Mock()
        args=['--run-once','--target','yfc-vps','--release-sha',RELEASE,'--manifest-sha256','d'*64]
        with patch.dict(sys.modules,{'websockets':ws,'websockets.asyncio':asynchronous,'websockets.asyncio.client':client}), \
             patch.object(service.os,'geteuid',return_value=1234), \
             patch.object(service.os,'getegid',return_value=1234), \
             patch.object(service,'load_private_relay',return_value=private), \
             patch.object(service,'_service_identity') as identity_check, \
             patch.object(service,'real_os_isolation_verified',return_value=True) as gate, \
             patch.object(service,'load_local_runtime',return_value=prepared), \
             patch.object(service,'private_revoked_provider',return_value=lambda:False), \
             patch.object(service,'_pinned_websocket_dependency',return_value=True) as pinned, \
             patch.object(service,'sync_adapter',return_value=Mock()) as adapter, \
             patch.object(service,'private_websocket_connector',return_value=self.transport) as private_connector, \
             patch.object(service,'run_once',return_value='session_deadline') as session:
            self.assertEqual(service.main(args),0)
            pinned.assert_called_once_with(RELEASE,'yfc-vps')
            adapter.assert_called_once_with(client.connect)
            private_connector.assert_called_once_with(private,adapter.return_value)
            identity_check.assert_called_once_with('yfc-vps')
            self.assertTrue(session.call_args.kwargs['landlock_read'])
            self.assertTrue(all(c.kwargs['expected_identity']==(1234,1234) for c in gate.call_args_list))

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
        denied = read.call_args.kwargs["is_device_revoked"]
        self.assertFalse(denied())
        self.os_gate.return_value = False
        self.assertTrue(denied())
        self.assertEqual(load.call_args.kwargs["manifest_path"],
                         Path(service.MANIFEST_PATH))
        self.assertEqual(load.call_args.kwargs["config_path"],
                         Path(service.CONFIG_PATH))

    def test_revoked_or_isolation_denied_before_network(self):
        for target, gates in ((t, g) for t in ('hermes-vps','yfc-vps')
                              for g in ((False,lambda:False),(True,lambda:True))):
            with self.subTest(target=target,gates=gates), \
                 patch.object(service,"_service_identity"), \
                 patch.object(service,"load_local_runtime",
                     return_value=self.fake), \
                 patch.object(service,"run_once") as read:
                for _ in range(3):
                    with self.assertRaises(service.NativeLinuxServiceDenied):
                        service.run_trusted_once(
                            target=target,release_sha=RELEASE,
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
        with patch.object(service,"load_private_relay",
                          return_value=SimpleNamespace(relay_ipv4="172.29.251.2")), \
             patch.object(service,"real_os_isolation_verified",
                          return_value=False) as gate, \
             patch.object(service,"_service_identity"), \
             patch.object(service,"load_local_runtime") as load:
            self.assertEqual(service.main(args),2)
            self.assertEqual(gate.call_args.kwargs['private_relay_ip'],"172.29.251.2")
            self.assertEqual(gate.call_args.kwargs['target'],"hermes-vps")
            load.assert_not_called()
        with patch.object(service,"real_os_isolation_verified",
                          return_value=False):
            with self.assertRaises(SystemExit) as exc:
                service.main(args+["--bypass-os"])
            self.assertEqual(exc.exception.code, 2)

    def test_non_callable_explicit_os_gate_is_denied(self):
        with patch.object(service, "load_private_relay") as load:
            with self.assertRaises(service.NativeLinuxServiceDenied):
                service.run_trusted_once(target=TARGET, release_sha=RELEASE,
                                         manifest_sha256="d" * 64, os_gate=False)
            load.assert_not_called()


if __name__=="__main__":
    unittest.main()
