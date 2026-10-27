"""H15 #454: fail-closed server patch and generated TypeScript execution."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.h15_brc_workspace_gateway import apply, AuditError
REGISTRY = Path(__file__).resolve().parents[1] / "deploy/h15/workspace-registry.json"

class H15WorkspaceMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        p = self.root / "packages/relay/src/mcp"
        p.mkdir(parents=True)
        self.server = p / "server.ts"
        self.module = p / "hermes-workspaces.ts"
        self.server.write_text(
            "import { pinnedToolCatalog } from './hermes-tool-catalog.js';\n"
            "      ...pinnedToolCatalog().map(t => ({ ...t, inputSchema: withDeviceId(t.inputSchema) }))] };\n"
            "    const out = await invokeTool(hub, store, ctx, name, args as Record<string, unknown> | undefined);\n")
        (p / "hermes-policy.ts").write_text("export function isPermittedRemoteTool() {}\n")
        (p / "hermes-tool-catalog.ts").write_text("export function pinnedToolCatalog() {}\n")
        control = patch("scripts.h15_brc_workspace_gateway.evaluate")
        control.start()
        self.addCleanup(control.stop)

    def test_patch_serverside_and_no_fixed_id(self):
        result = apply(self.root, REGISTRY)
        self.assertFalse(result["live_deployment"])
        content = self.server.read_text()
        self.assertIn("listUserDevices(hub, store, ctx.userId)", content)
        self.assertLess(content.index("name === 'resolve_workspace'"), content.index("const out = await invokeTool"))
        self.assertNotIn("h15-win-05be75515428", self.module.read_text())

    def test_duplicate_refused_without_changes(self):
        apply(self.root, REGISTRY)
        prior = self.server.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root, REGISTRY)
        self.assertEqual(prior, self.server.read_bytes())

    def test_source_drift_denied(self):
        self.server.write_text(self.server.read_text().replace("const out = await invokeTool", "const bad = await invokeTool"))
        with self.assertRaisesRegex(AuditError, "gateway_source_marker_drift"):
            apply(self.root, REGISTRY)
        self.assertFalse(self.module.exists())

    def test_permission_widening_denied(self):
        p = self.root / "packages/relay/src/mcp/hermes-policy.ts"
        p.write_text("export function isPermittedRemoteTool() {} 'resolve_workspace'\n")
        with self.assertRaisesRegex(AuditError, "remote_invocation_policy_unreviewed"):
            apply(self.root, REGISTRY)

    def test_wrong_registry_denied(self):
        obj = json.loads(REGISTRY.read_text())
        obj["workspace_root"] = "/host-private"
        bad = self.root / "bad.json"
        bad.write_text(json.dumps(obj))
        with self.assertRaises(AuditError):
            apply(self.root, bad)

    def test_wrong_sha_denied(self):
        with self.assertRaises(AuditError):
            apply(self.root, REGISTRY, "0" * 40)

    def test_real_typescript_runtime(self):
        if not shutil.which("node") or not shutil.which("tsc"):
            self.skipTest("Node/TypeScript compiler absent")
        apply(self.root, REGISTRY)
        dest = self.root / "out"
        comp = subprocess.run(
            ["tsc", "--strict", "--target", "ES2022", "--module", "commonjs",
             "--skipLibCheck", "--outDir", str(dest), str(self.module)],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(comp.returncode, 0, comp.stderr + comp.stdout)
        js = """
const assert=require('node:assert/strict'),api=require(process.argv[1]);
const win={name:'H15 Windows permanent sandbox',deviceId:'h15-win-05be75515428',online:true,paused:false};
const other={name:'H15 YFC VPS sandbox',deviceId:'h15-yfc-c6ee0d53e858',online:true,paused:false};
assert.equal(api.listApprovedWorkspaces([win,other]).workspaces.length,4);
assert.equal(api.listApprovedWorkspaces([win,other]).workspaces.every(w=>w.process_execution_verified===false),true);
assert.equal(api.resolveApprovedWorkspace({project:'YFC'},[win]).root,'/workspace/projects/your-fitness-coach');
assert.equal(api.resolveApprovedWorkspace({project:'adt'},[win]).workspace,'ai-development-toolkit');
assert.equal(api.resolveApprovedWorkspace({project:'Second_Brain'},[win]).workspace,'second-brain');
assert.equal(api.resolveApprovedWorkspace({project:'hermes'},[win]).git_verified,false);
assert.equal(api.resolveApprovedWorkspace({project:'hermes'},[win]).process_execution_verified,false);
for (const args of [{project:'../../private'}, {project:'random'}, {project:'yfc',deviceId:'forced'}, {}])
 assert.equal(api.resolveApprovedWorkspace(args,[win]).status,'refused');
for (const devices of [[],[other],[{...win,online:false}],[{...win,paused:true}],[win,win]])
 assert.equal(api.resolveApprovedWorkspace({project:'yfc'},devices).status,'refused');
assert.equal(api.listApprovedWorkspaces([other]).workspaces.length,0);
console.log('H15_454_TS_RUNTIME=PASS');
"""
        proc = subprocess.run(["node", "-e", js, str(dest / "hermes-workspaces.js")],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("H15_454_TS_RUNTIME=PASS", proc.stdout)

if __name__ == "__main__":
    unittest.main()
