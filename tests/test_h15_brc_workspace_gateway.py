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
(async () => {
const win={name:'H15 Windows permanent sandbox',deviceId:'h15-win-05be75515428',online:true,paused:false};
const other={name:'H15 YFC VPS sandbox',deviceId:'h15-yfc-c6ee0d53e858',online:true,paused:false};
const personal={name:'H454 Windows personal Commander',deviceId:'h454-win-personal-'+'a'.repeat(32),platform:'win32',online:true,paused:false};
const resolvedPersonal=api.resolveApprovedWorkspace({project:'YFC dev'},[win,personal]);
assert.equal(resolvedPersonal.status,'resolved');
assert.equal(resolvedPersonal.root,'D:\\\\Pet-projects\\\\yfc-dev');
assert.equal(resolvedPersonal.scope,'native-personal');
assert.equal(resolvedPersonal.deviceId,personal.deviceId);
assert.equal(resolvedPersonal.git_verified,false);
assert.equal(resolvedPersonal.verification_required_before_write,true);
assert.equal(api.resolveApprovedWorkspace({project:'yfc'},[win,personal]).scope,'sandbox');
assert.equal(api.listApprovedWorkspaces([win,personal]).workspaces.find(w=>w.name==='yfc-dev').deviceId,personal.deviceId);
assert.equal(api.listApprovedWorkspaces([personal]).workspaces.length,1);
for (const devices of [[],[{...personal,online:false}],[{...personal,paused:true}],
  [{...personal,platform:'linux'}],[{...personal,deviceId:'h454-win-native-'+'a'.repeat(32)}],
  [personal,personal]])
  assert.equal(api.resolveApprovedWorkspace({project:'yfc-dev'},devices).reason,'personal_device_unavailable');
assert.equal(api.listApprovedWorkspaces([win,other]).workspaces.length,5);
assert.equal(api.listApprovedWorkspaces([win,other]).workspaces.every(w=>w.process_execution_verified===false),true);
assert.equal(api.resolveApprovedWorkspace({project:'YFC'},[win]).root,'/workspace/projects/your-fitness-coach');
assert.equal(api.resolveApprovedWorkspace({project:'adt'},[win]).workspace,'ai-development-toolkit');
assert.equal(api.resolveApprovedWorkspace({project:'fh'},[win]).root,'/workspace/projects/financial-horizon');
assert.equal(api.resolveApprovedWorkspace({project:'Second_Brain'},[win]).workspace,'second-brain');
assert.equal(api.resolveApprovedWorkspace({project:'hermes'},[win]).git_verified,false);
assert.equal(api.resolveApprovedWorkspace({project:'hermes'},[win]).process_execution_verified,false);
for (const args of [{project:'../../private'}, {project:'random'}, {project:'yfc',deviceId:'forced'}, {}])
 assert.equal(api.resolveApprovedWorkspace(args,[win]).status,'refused');
for (const devices of [[],[other],[{...win,online:false}],[{...win,paused:true}],[win,win]])
 assert.equal(api.resolveApprovedWorkspace({project:'yfc'},devices).status,'refused');
assert.equal(api.listApprovedWorkspaces([other]).workspaces.length,0);
let dispatched=[];
const output={status:'verified',workspace:'new-project',root:'/workspace/projects/new-project',
 origin:'https://github.com/MikeMoore1337/new-project.git',branch:'main',head:'a'.repeat(40)};
const invoke=async (tool,args) => { dispatched.push({tool,args}); return {ok:true,result:{content:[{type:'text',text:'Process started with PID 42 (shell: /bin/sh)\\nInitial output:\\n'+JSON.stringify(output)}]}}; };
const added=await api.sandboxProjectAction({project:'new-project'},[win],invoke);
assert.equal(added.status,'resolved'); assert.equal(added.git_verified,true);
assert.equal(dispatched[0].tool,'start_process'); assert.equal(dispatched[0].args.deviceId,win.deviceId);
const resolved=await api.sandboxProjectAction({project:'new-project'},[win],invoke);
assert.equal(resolved.workspace,'new-project');
assert.equal((await api.sandboxProjectAction({project:'../escape'},[win],invoke)).status,'refused');
assert.equal((await api.sandboxProjectAction({project:'new-project'},[other],invoke)).status,'refused');
assert.equal(dispatched.length,2);
const waiting=await api.sandboxProjectAction({project:'new-project'},[win],async()=>({ok:true,result:{content:[{type:'text',text:'Process started with PID 42 (shell: /bin/sh)'}]}}));
assert.equal(waiting.status,'pending'); assert.equal(waiting.process_id,42);
const missing=await api.sandboxProjectAction({project:'new-project'},[win],async()=>({ok:true,result:{isError:true,content:[{type:'text',text:'Process 42 exited with code 2\\nOutput:\\n'+JSON.stringify({status:'refused',reason:'project_not_found'})}]}}));
assert.equal(missing.reason,'project_not_found');
const exited=await api.sandboxProjectAction({project:'new-project'},[win],async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(output)}]}}));
assert.equal(exited.status,'resolved');
const listPayload={status:'catalog',projects:[output],incomplete:false};
const listInvoke=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(listPayload)}]}});
const withExtra=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],listInvoke);
assert.equal(withExtra.discovery_status,'complete'); assert.equal(withExtra.workspaces.length,6);
assert.equal(withExtra.workspaces[5].name,'new-project'); assert.equal(withExtra.workspaces[5].git_verified,true);
const worktree={...output,workspace:'feature-worktree',repository:'new-project',root:'/workspace/projects/feature-worktree',branch:'feature'};
const worktreeInvoke=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(worktree)}]}});
assert.equal((await api.sandboxProjectAction({project:'feature-worktree'},[win],worktreeInvoke)).status,'resolved');
const worktreeList=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify({status:'catalog',projects:[worktree],incomplete:false})}]}});
const worktreeResult=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],worktreeList);
assert.equal(worktreeResult.discovery_status,'complete'); assert.equal(worktreeResult.workspaces[5].name,'feature-worktree');
const detached={...worktree,branch:null,detached:true};
const detachedInvoke=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(detached)}]}});
assert.equal((await api.sandboxProjectAction({project:'feature-worktree'},[win],detachedInvoke)).detached,true);
const fakeDetached={...detached,detached:false};
const fakeInvoke=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(fakeDetached)}]}});
assert.equal((await api.sandboxProjectAction({project:'feature-worktree'},[win],fakeInvoke)).status,'refused');
const partial=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],async()=>({ok:true,result:{content:[{type:'text',text:'Process started with PID 42 (shell: /bin/sh)'}]}}));
assert.equal(partial.discovery_status,'pending'); assert.equal(partial.workspaces.length,5);
const offline=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([{...win,online:false}]),[{...win,online:false}],async()=>{throw Error('unexpected call')});
assert.equal(offline.discovery_status,'unavailable'); assert.equal(offline.workspaces.length,5);
console.log('H15_454_TS_RUNTIME=PASS');
})().catch(e=>{console.error(e);process.exit(1)});
"""
        proc = subprocess.run(["node", "-e", js, str(dest / "hermes-workspaces.js")],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("H15_454_TS_RUNTIME=PASS", proc.stdout)

if __name__ == "__main__":
    unittest.main()
