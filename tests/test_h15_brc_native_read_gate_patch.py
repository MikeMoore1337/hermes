"""Offline owner-bound native relay patch regression tests for Hermes #454."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.h15_brc_native_read_gate_patch import (
    apply, AuditError, SERVER_IMPORT, SERVER_LIST,
    INVOKE_IMPORT, GATE, PAUSED_START,
)

PAUSED = (PAUSED_START + chr(96) + "Device " + chr(36) +
          "{dev.info.name} is paused by its owner." + chr(96) + " };")
SERVER = (SERVER_IMPORT + "\n" + SERVER_LIST + "\n")
INVOKE = (INVOKE_IMPORT + "\n"
          + "  const args = { ...(rawArgs ?? {}) };\n" + GATE + "\n}\n"
          + "  const requested = typeof args.deviceId === 'string' && args.deviceId ? args.deviceId : undefined;\n"
          + "  const dev = hub.get(deviceId);\n"
          + "  if (!dev || dev.ownerId !== ctx.userId) return null;\n"
          + PAUSED + "\n")


class RelayNativeGateTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        d = self.root / "packages/relay/src/mcp"
        d.mkdir(parents=True)
        self.server, self.invoke, self.module = [d / name for name in (
            "server.ts", "invoke.ts", "hermes-native-read-gate.ts")]
        self.server.write_text(SERVER, encoding="utf-8")
        self.invoke.write_text(INVOKE, encoding="utf-8")
        guard = patch("scripts.h15_brc_native_read_gate_patch.evaluate")
        guard.start()
        self.addCleanup(guard.stop)

    def test_source_only_patch_after_owner_check(self):
        result = apply(self.root)
        self.assertFalse(result["live_deployment"])
        self.assertFalse(result["native_host_execution"])
        a, b, c = self.server.read_text(), self.invoke.read_text(), self.module.read_text()
        self.assertIn("originalWindowsReadToolCatalog()", a)
        self.assertIn("HERMES_NATIVE_DEVICE_DENIED", b)
        self.assertLess(b.index("dev.ownerId !== ctx.userId"),
                        b.index("HERMES_NATIVE_DEVICE_DENIED"))
        self.assertIn("isNativeOriginalDevice(requested", b)
        self.assertIn("HERMES_NATIVE_READ_DEVICE_ID", c)

    def test_drift_and_repeat_fail_closed(self):
        self.invoke.write_text(INVOKE.replace(GATE, "if (unreviewed) {"))
        with self.assertRaisesRegex(AuditError, "pinned_gateway_source_drift"):
            apply(self.root)
        self.assertFalse(self.module.exists())
        self.assertEqual(self.server.read_text(), SERVER)
        self.invoke.write_text(INVOKE)
        apply(self.root)
        old = self.server.read_bytes(), self.invoke.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(old, (self.server.read_bytes(), self.invoke.read_bytes()))

    def test_wrong_pin_and_symlink_denied(self):
        with self.assertRaisesRegex(AuditError, "upstream_sha_mismatch"):
            apply(self.root, "0"*40)
        self.invoke.unlink()
        victim = self.root / "victim"
        victim.write_text(INVOKE)
        self.invoke.symlink_to(victim)
        with self.assertRaisesRegex(AuditError, "unsafe_relay_path"):
            apply(self.root)
        self.assertEqual(victim.read_text(), INVOKE)

    def test_native_typescript_owner_gate_when_tsc_installed(self):
        if not shutil.which("tsc") or not shutil.which("node"):
            self.skipTest("node or tsc unavailable")
        apply(self.root)
        out = self.root / "compiled"
        c = subprocess.run(["tsc", "--strict", "--target", "ES2022",
            "--module", "commonjs", "--outDir", str(out), str(self.module)],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(c.returncode, 0, c.stderr+c.stdout)
        js = """
const a=require(process.argv[1]),assert=require('node:assert/strict');
delete process.env.HERMES_NATIVE_READ_DEVICE_ID;
assert.equal(a.originalWindowsReadToolCatalog().length,0);
process.env.HERMES_NATIVE_READ_DEVICE_ID='h15-native-readonly-1234';
assert.equal(a.originalWindowsReadToolCatalog().length,3);
const dev={deviceId:'h15-native-readonly-1234',name:'H15 Windows native read-only',platform:'win32'};
const caps=[{name:'native_file_read'},{name:'native_file_stat'},{name:'native_file_list'}];
assert.equal(a.isNativeOriginalDevice(dev.deviceId,true,dev,caps),true);
for(const [id,owner,info,tools] of [
  ['bad',true,dev,caps],[dev.deviceId,false,dev,caps],
  [dev.deviceId,true,{...dev,platform:'linux'},caps],
  [dev.deviceId,true,dev,[...caps,{name:'start_process'}]],
])assert.equal(a.isNativeOriginalDevice(id,owner,info,tools),false);
assert.equal(a.isNativeOriginalReadRequest('native_file_read',{project:'hermes',relative:'README.md'}),true);
for(const args of [
 {project:'hermes',relative:'..\\\\private.md'},
 {project:'hermes',relative:'.env'},
 {project:'hermes',relative:'vault\\\\secret.md'},
 {project:'hermes',relative:'README.md',approved:true},
 {project:'hermes',relative:'README.exe'}])
 assert.equal(a.isNativeOriginalReadRequest('native_file_read',args),false);
console.log('H454_NATIVE_GATE_PASS');
"""
        t = subprocess.run(["node", "-e", js, str(out / "hermes-native-read-gate.js")],
                           capture_output=True, text=True, timeout=12)
        self.assertEqual(t.returncode, 0, t.stdout+t.stderr)
        self.assertIn("H454_NATIVE_GATE_PASS", t.stdout)


if __name__ == "__main__":
    unittest.main()
