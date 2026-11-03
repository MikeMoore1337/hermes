"""H15 #454: fail-closed server patch and generated TypeScript execution."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.h15_brc_workspace_gateway import apply, AuditError, DEVICE_HELP, WORKSPACE_DEVICE_HELP
from scripts.h15_brc_native_read_gateway import apply as apply_native
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
            + DEVICE_HELP + "\n"
            "      ...pinnedToolCatalog().map(t => ({ ...t, inputSchema: withDeviceId(t.inputSchema) }))] };\n"
            "    const out = await invokeTool(hub, store, ctx, name, args as Record<string, unknown> | undefined);\n")
        (p / "hermes-policy.ts").write_text("export function isPermittedRemoteTool() {}\n")
        (p / "hermes-tool-catalog.ts").write_text("export function pinnedToolCatalog() {}\n")
        control = patch("scripts.h15_brc_workspace_gateway.evaluate")
        control.start()
        self.addCleanup(control.stop)

    def test_patch_serverside_with_pinned_device_id(self):
        result = apply(self.root, REGISTRY)
        self.assertFalse(result["live_deployment"])
        content = self.server.read_text()
        self.assertIn("listUserDevices(hub, store, ctx.userId)", content)
        self.assertLess(content.index("name === 'resolve_workspace'"), content.index("const out = await invokeTool"))
        self.assertLess(content.index("routeWorkspaceCall(name, args"), content.index("const out = await invokeTool"))
        self.assertIn("args.deviceId = route.deviceId", content)
        self.assertIn(WORKSPACE_DEVICE_HELP, content)
        self.assertIn('"h15-win-05be75515428"', self.module.read_text())

    def test_duplicate_refused_without_changes(self):
        apply(self.root, REGISTRY)
        prior = self.server.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root, REGISTRY)
        self.assertEqual(prior, self.server.read_bytes())

    def test_native_gateway_remains_compatible_with_workspace_routing(self):
        apply(self.root, REGISTRY)
        (self.server.parent / "invoke.ts").write_text("export {};\n")
        with patch("scripts.h15_brc_native_read_gateway.evaluate"):
            apply_native(self.root)
        content = self.server.read_text()
        self.assertLess(content.index("routeWorkspaceCall(name, args"), content.index("name === 'native_file_read'"))
        self.assertLess(content.index("name === 'native_file_read'"), content.index("const out = await invokeTool"))

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
for (const devices of [[],[other],[{...win,online:false}],[{...win,paused:true}],[win,win],
                       [{...win,deviceId:'h15-win-foreign12345'}],[{...win,name:'Different device'}],
                       [win,{...win,name:'Different device'}]])
 assert.equal(api.resolveApprovedWorkspace({project:'yfc'},devices).status,'refused');
assert.equal(api.listApprovedWorkspaces([other]).workspaces.length,0);
assert.equal(api.listApprovedWorkspaces([{...win,deviceId:'h15-win-foreign12345'}]).status,'not_connected');
const good='/workspace/projects/hermes/src/main.py', outside='/workspace/identity.txt';
const route=(name,args,devices=[win,other])=>api.routeWorkspaceCall(name,args,devices);
for (const name of ['read_file','write_file','list_directory','get_file_info','create_directory','start_search'])
 assert.deepEqual(route(name,{path:good}),{status:'routed',deviceId:win.deviceId});
assert.deepEqual(route('list_directory',{path:'/workspace/projects/hermes/'}),
 {status:'routed',deviceId:win.deviceId});
assert.deepEqual(route('edit_block',{file_path:good}),{status:'routed',deviceId:win.deviceId});
assert.deepEqual(route('move_file',{source:good,destination:'/workspace/projects/your-fitness-coach/file'}),
 {status:'routed',deviceId:win.deviceId});
assert.deepEqual(route('read_multiple_files',{paths:[good,'/workspace/projects/hermes/README.md']}),
 {status:'routed',deviceId:win.deviceId});
assert.deepEqual(route('write_pdf',{path:good,outputPath:'/workspace/projects/hermes/out.pdf',
 content:[{type:'insert',sourcePdfPath:'/workspace/projects/hermes/in.pdf'}]}),
 {status:'routed',deviceId:win.deviceId});
for (const [name,args] of [
 ['move_file',{source:good,destination:outside}],
 ['read_multiple_files',{paths:[good,outside]}],
 ['read_multiple_files',{paths:[good,42]}],
 ['read_multiple_files',{paths:Array(65).fill(good)}],
 ['write_pdf',{path:good,outputPath:outside}],
 ['write_pdf',{path:good,content:Array(65).fill({type:'delete'})}],
 ['write_pdf',{path:good,content:[{type:'insert',sourcePdfPath:outside}]}],
 ['read_file',{path:'/workspace/projects/hermes/../private'}],
 ['read_file',{path:'/workspace/projects/hermes//bad'}],
 ['read_file',{path:'/workspace//projects/hermes/README.md'}],
 ['read_file',{path:'/workspace//projects/hermes/../../secret'}],
 ['read_file',{path:'/workspace/projects/elsewhere/../hermes/../../secret'}],
 ['read_file',{path:'/workspace/projects/elsewhere/../hermes/README.md'}],
 ['read_file',{path:'/workspace\\\\projects\\\\hermes\\\\README.md'}],
 ['read_file',{path:'/workspace/projects/hermes/a\\\\..\\\\private'}],
]) assert.equal(route(name,args).status,'refused');
assert.equal(route('read_file',{path:'/workspace//projects/hermes/README.md'},[other]).status,'refused');
assert.equal(route('read_multiple_files',{paths:Array(65).fill(good)},[other]).status,'refused');
for (const devices of [[],[other],[{...win,online:false}],[{...win,paused:true}],
 [win,win],[{...win,deviceId:'h15-win-foreign12345'}]])
 assert.equal(route('read_file',{path:good},devices).reason,'owner_device_unavailable');
for (const deviceId of ['',null,0])
 assert.equal(route('read_file',{path:good,deviceId},[other]).reason,'invalid_device_id');
for (const [name,args] of [['read_file',{path:outside}],['read_file',{path:good,deviceId:'ci-native-two'}],
 ['start_process',{command:'cat '+good}],
 ['get_more_search_results',{sessionId:'fixture'}],['native_file_read',{path:good}]])
 assert.equal(route(name,args).status,'unchanged');
let socket={}; const hub={get:id=>id===win.deviceId?{socket}:undefined};
const startArgs={path:good}; const startRoute=route('start_search',startArgs);
const start=api.prepareWorkspaceSearch('start_search',startArgs,startRoute,hub,[win,other]);
assert.equal(start.status,'start');
assert.equal(api.finishWorkspaceSearch({content:[{type:'text',text:'unexpected success'}]},start,hub).reason,
 'search_response_unrecognized');
assert.equal(api.finishWorkspaceSearch({isError:true,content:[{type:'text',text:'invalid request'}]},start,hub).status,'ok');
const started={content:[{type:'text',text:'Started file search session: search_1_1793680000000\\nPattern: fixture\\n'}]};
assert.equal(api.finishWorkspaceSearch(started,start,hub).status,'ok');
const token=started.content[0].text.match(/^Started file search session: (hermes_search_[a-f0-9]{32}_search_1_1793680000000)/)?.[1];
assert.ok(token);
const start2=api.prepareWorkspaceSearch('start_search',{path:good},startRoute,hub,[win,other]);
const started2={content:[{type:'text',text:'Started content search session: search_2_1793680000001\\n'}]};
assert.equal(api.finishWorkspaceSearch(started2,start2,hub).status,'ok');
const token2=started2.content[0].text.match(/hermes_search_[a-f0-9]{32}_search_2_1793680000001/)?.[0];
assert.ok(token2);assert.notEqual(token,token2);
const followArgs={sessionId:token};
const follow=api.prepareWorkspaceSearch('get_more_search_results',followArgs,{status:'unchanged'},hub,[win,other]);
assert.equal(follow.status,'follow');assert.equal(follow.nativeId,'search_1_1793680000000');
assert.equal(api.prepareWorkspaceSearch('stop_search',{sessionId:token2,deviceId:win.deviceId},
 {status:'unchanged'},hub,[win,other]).nativeId,'search_2_1793680000001');
assert.equal(api.prepareWorkspaceSearch('stop_search',{sessionId:'search_9_1793680000000'},
 {status:'unchanged'},hub,[win,other]).status,'unchanged');
const output={content:[{type:'text',text:'Search session: search_1_1793680000000\\nfile search_1_1793680000000\\n'}]};
assert.equal(api.finishWorkspaceSearch(output,follow,hub).status,'ok');
assert.equal(output.content[0].text,'Search session: '+token+'\\nfile search_1_1793680000000\\n');
const missing={content:[{type:'text',text:'Search session search_1_1793680000000 not found or already completed.'}]};
assert.equal(api.finishWorkspaceSearch(missing,follow,hub).status,'ok');
assert.equal(missing.isError,true);assert.ok(missing.content[0].text.includes(token));
assert.equal(api.prepareWorkspaceSearch('stop_search',{sessionId:token,deviceId:other},
 {status:'unchanged'},hub,[win,other]).reason,'search_device_mismatch');
assert.equal(api.prepareWorkspaceSearch('stop_search',{sessionId:'hermes_search_bad'},
 {status:'unchanged'},hub,[win,other]).reason,'search_session_invalid');
assert.equal(api.prepareWorkspaceSearch('stop_search',{sessionId:token},
 {status:'unchanged'},hub,[{...win,paused:true},other]).reason,'owner_device_unavailable');
socket={};
assert.equal(api.prepareWorkspaceSearch('get_more_search_results',{sessionId:token},
 {status:'unchanged'},hub,[win,other]).reason,'search_session_expired');
assert.equal(api.finishWorkspaceSearch(started,start,hub).reason,'search_connection_changed');
console.log('H15_454_TS_RUNTIME=PASS');
"""
        proc = subprocess.run(["node", "-e", js, str(dest / "hermes-workspaces.js")],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("H15_454_TS_RUNTIME=PASS", proc.stdout)

if __name__ == "__main__":
    unittest.main()
