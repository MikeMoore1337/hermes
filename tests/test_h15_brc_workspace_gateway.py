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
        node = shutil.which("node")
        compiler = shutil.which("tsc")
        if not node:
            self.skipTest("Node absent")
        apply(self.root, REGISTRY)
        if compiler:
            dest = self.root / "out"
            comp = subprocess.run(
                [compiler, "--strict", "--target", "ES2022", "--module", "commonjs",
                 "--skipLibCheck", "--outDir", str(dest), str(self.module)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(comp.returncode, 0, comp.stderr + comp.stdout)
            module = dest / "hermes-workspaces.js"
        else:
            version = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout.strip()
            if int(version.removeprefix('v').split('.')[0]) < 24:
                self.skipTest("TypeScript compiler or Node 24 required")
            module = self.module
        js = """
const assert=require('node:assert/strict'),api=require(process.argv[1]);
(async () => {
const win={name:'H15 Windows permanent sandbox',deviceId:'h15-win-05be75515428',online:true,paused:false};
const other={name:'H15 YFC VPS sandbox',deviceId:'h15-yfc-c6ee0d53e858',online:true,paused:false};
const personal={name:'H454 Windows personal Commander',deviceId:'h454-win-personal-'+'a'.repeat(32),platform:'win32',online:true,paused:false};
let personalCalls=[];
const personalInfo=async(tool,args)=>{personalCalls.push({tool,args});return {ok:true,result:{content:[{type:'text',text:'size: 0\\nisDirectory: true\\nisFile: false'}]}}};
for (const [project,expected] of [['hermes windows','hermes-windows-original'],['yfc-windows','yfc-windows-original']]) {
 const out=await api.personalWindowsProjectAction({project},[personal],personalInfo);
 assert.equal(out.status,'resolved'); assert.equal(out.workspace,expected); assert.equal(out.git_verified,false);
 assert.equal(out.origin,null); assert.equal(out.deviceId,personal.deviceId);
}
assert.equal(personalCalls.length,2); assert.equal(personalCalls[0].tool,'get_file_info');
assert.equal((await api.personalWindowsProjectAction({project:'hermes-windows'},[personal],async()=>({ok:true,result:{isError:true,content:[{type:'text',text:'denied'}]}}))).reason,'personal_project_unavailable');
assert.equal((await api.personalWindowsProjectAction({project:'hermes-windows'},[personal],async()=>({ok:true,result:{content:[{type:'text',text:'isDirectory: false'}]}}))).reason,'personal_project_unavailable');
assert.equal((await api.personalWindowsProjectAction({project:'hermes-windows'},[{...personal,online:false}],personalInfo)).reason,'personal_device_unavailable');
assert.equal((await api.personalWindowsProjectAction({project:'unknown'},[personal],personalInfo)).reason,'unknown_workspace');
assert.equal(personalCalls.length,2);
const personalCatalog=api.listApprovedWorkspaces([personal]);
const enriched=await api.addPersonalWindowsWorkspaces(personalCatalog,[personal],personalInfo);
assert.deepEqual(enriched.workspaces.map(w=>w.name),['yfc-dev','hermes-windows-original','yfc-windows-original']);
assert.equal(enriched.workspaces[1].deviceId,personal.deviceId);
assert.equal(enriched.workspaces[1].git_verified,false);
assert.equal((await api.personalWindowsProjectAction({project:enriched.workspaces[1].name},[personal],personalInfo)).status,'resolved');
const selective=async(_tool,args)=>args.path.endsWith('hermes')
 ? {ok:true,result:{isError:true,content:[{type:'text',text:'denied'}]}} : personalInfo(_tool,args);
const partialPersonal=await api.addPersonalWindowsWorkspaces(personalCatalog,[personal],selective);
assert.deepEqual(partialPersonal.workspaces.map(w=>w.name),['yfc-dev','yfc-windows-original']);
const unreachable=await api.addPersonalWindowsWorkspaces(personalCatalog,[{...personal,online:false}],async()=>{throw Error('unexpected')});
assert.deepEqual(unreachable,personalCatalog);
const deduped=await api.addPersonalWindowsWorkspaces(enriched,[personal],personalInfo);
assert.equal(deduped.workspaces.length,3);
const job='a'.repeat(32), importCalls=[];
const importInvoke=async(tool,args)=>{importCalls.push({tool,args}); return {ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'started',job_id:job,workspace:'new-project',secret:'discard'})}]}};};
const imported=await api.importPublicProject({action:'start',repository:'owner/repo',workspace:'new-project'},[personal],importInvoke);
assert.equal(imported.status,'started'); assert.equal(imported.secret,undefined); assert.equal(importCalls[0].tool,'import_public_project');
assert.equal(importCalls[0].args.deviceId,personal.deviceId);
assert.equal((await api.importPublicProject({action:'start',repository:'owner/repo',workspace:'../escape'},[personal],importInvoke)).status,'refused');
assert.equal((await api.importPublicProject({action:'status',job_id:job},[{...personal,online:false}],importInvoke)).reason,'personal_device_unavailable');
assert.equal(importCalls.length,1);
const statusInvoke=async()=>({ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'installed',job_id:job,workspace:'new-project',head:'b'.repeat(40),branch:'main'})}]}});
assert.equal((await api.importPublicProject({action:'status',job_id:job},[personal],statusInvoke)).status,'installed');
const spoofInvoke=async()=>({ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'installed',job_id:job,workspace:'../escape',head:'b'.repeat(40),branch:'main'})}]}});
assert.equal((await api.importPublicProject({action:'status',job_id:job},[personal],spoofInvoke)).reason,'import_call_failed');
const vpsArgs={target:'yfc-vps',name:'fixture',path:'/opt/fixture',mode:'plan'}, vpsCalls=[];
const vpsPlan=async(tool,args)=>{vpsCalls.push({tool,args});return {ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'plan_pass'})}]}};};
assert.equal((await api.connectOriginalVpsProject(vpsArgs,[personal],vpsPlan)).status,'plan_pass');
assert.equal(vpsCalls[0].tool,'connect_original_vps_project'); assert.equal(vpsCalls[0].args.deviceId,personal.deviceId);
assert.equal((await api.connectOriginalVpsProject({...vpsArgs,name:'../bad'},[personal],vpsPlan)).status,'refused');
assert.equal((await api.connectOriginalVpsProject(vpsArgs,[{...personal,online:false}],vpsPlan)).reason,'personal_device_unavailable');
assert.equal(vpsCalls.length,1);
const vpsApplied=async()=>({ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'applied',backup:'project-registration-'+'a'.repeat(32)})}]}});
const applied=await api.connectOriginalVpsProject({...vpsArgs,mode:'execute'},[personal],vpsApplied);
assert.equal(applied.status,'applied'); assert.equal(applied.workspace,'fixture-yfc-vps-original'); assert.equal(applied.verification_required,true);
const vpsInterrupted=async()=>{throw Error('network interrupted');};
assert.equal((await api.connectOriginalVpsProject({...vpsArgs,mode:'execute'},[personal],vpsInterrupted)).reason,'operation_unconfirmed_do_not_retry');
const winArgs={path:'D:/Pet-projects/example',mode:'plan'}, winCalls=[];
const winPlan=async(tool,args)=>{winCalls.push({tool,args});return {ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'plan_pass'})}]}};};
assert.equal((await api.connectOriginalWindowsProject(winArgs,[personal],winPlan)).status,'plan_pass');
assert.equal(winCalls[0].tool,'connect_original_windows_project'); assert.equal(winCalls[0].args.deviceId,personal.deviceId);
assert.equal(winCalls[0].args.path,'D:\\\\Pet-projects\\\\example');
assert.equal((await api.connectOriginalWindowsProject({...winArgs,path:'D:\\\\Pet-projects\\\\example'},[personal],winPlan)).status,'plan_pass');
assert.equal((await api.connectOriginalWindowsProject({...winArgs,path:'D:/Pet-projects/vault'},[personal],winPlan)).status,'refused');
assert.equal((await api.connectOriginalWindowsProject(winArgs,[{...personal,online:false}],winPlan)).reason,'personal_device_unavailable');
assert.equal(winCalls.length,2);
const winApplied=async()=>({ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'applied',backup:'project-registration-'+'a'.repeat(32)})}]}});
const winResult=await api.connectOriginalWindowsProject({...winArgs,mode:'execute'},[personal],winApplied);
assert.equal(winResult.status,'applied'); assert.equal(winResult.device_reconnecting,true); assert.equal(winResult.verification_required,true);
assert.equal((await api.connectOriginalWindowsProject({...winArgs,mode:'execute'},[personal],vpsInterrupted)).reason,'operation_unconfirmed_do_not_retry');
const winBusy=async()=>({ok:true,result:{content:[{type:'text',text:JSON.stringify({status:'refused',reason:'active_sessions'})}]}});
assert.equal((await api.connectOriginalWindowsProject({...winArgs,mode:'execute'},[personal],winBusy)).reason,'active_sessions');
const hermesVps={name:'H15 Hermes VPS sandbox',deviceId:'h15-hermes-'+'b'.repeat(12),platform:'linux/docker',online:true,paused:false};
const yfcVps={...other,platform:'linux/docker'};
const hermesOriginal={name:'H454 Hermes VPS personal Commander',deviceId:'h454-linux-personal-hermes-'+'c'.repeat(32),platform:'linux',online:true,paused:false};
const yfcOriginal={name:'H454 YFC VPS personal Commander',deviceId:'h454-linux-personal-yfc-'+'d'.repeat(32),platform:'linux',online:true,paused:false};
const winRoots=['D:/Pet-projects/yfc-dev','D:/Pet-projects/financial-horizon','D:/Pet-projects/hermes','D:/Pet-projects/your-fitness-coach'];
const winEnv=roots=>`Process 42 exited with code 0\\nGIT_CONFIG_COUNT=${roots.length}\\n`+
 roots.map((root,i)=>`GIT_CONFIG_KEY_${i}=safe.directory\\nGIT_CONFIG_VALUE_${i}=${root}\\n`).join('');
const manyWinRoots=['D:/Pet-projects/yfc-dev',...Array.from({length:15},(_,i)=>'D:/Pet-projects/project-'+String(i).padStart(2,'0'))];
const manyWinInvoke=async()=>({ok:true,result:{content:[{type:'text',text:winEnv(manyWinRoots)}]}});
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'project-14-windows'},[personal],manyWinInvoke)).status,'resolved');
const tooManyWinInvoke=async()=>({ok:true,result:{content:[{type:'text',text:winEnv([...manyWinRoots,'D:/Pet-projects/project-15'])}]}});
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'project-14-windows'},[personal],tooManyWinInvoke)).reason,'personal_discovery_unavailable');
const personalDevices=[personal,hermesOriginal,yfcOriginal], discoveryCalls=[];
const discoveryInvoke=async(tool,args)=>{
 discoveryCalls.push({tool,args});
 const text=args.deviceId===personal.deviceId ? winEnv(winRoots)
   : args.deviceId===hermesOriginal.deviceId ? 'Process started with PID 9 (shell: /bin/sh)\\nInitial output:\\nH454_ROOTS=2|/workspace|/projects/demo|||\\n'
   : 'Process started with PID 10 (shell: /bin/sh)\\nInitial output:\\nH454_ROOTS=2|/workspace|/projects/coach|||\\n';
 return {ok:true,result:{content:[{type:'text',text}]}};
};
const personalDiscovered=await api.addDiscoveredPersonalWorkspaces(api.listApprovedWorkspaces(personalDevices),personalDevices,discoveryInvoke);
assert.equal(personalDiscovered.personal_discovery,'complete');
for (const expected of ['financial-horizon-windows-original','hermes-windows-original','yfc-windows-original',
                        'demo-hermes-vps-original','coach-yfc-vps-original'])
 assert.ok(personalDiscovered.workspaces.find(w=>w.name===expected),expected);
assert.equal(discoveryCalls.length,3);
assert.equal(discoveryCalls.find(call=>call.args.deviceId===personal.deviceId).args.command,'set GIT_CONFIG');
let dynamic=await api.discoveredPersonalWorkspaceAction({project:'financial-horizon-windows'},personalDevices,discoveryInvoke);
assert.equal(dynamic.root,'D:\\\\Pet-projects\\\\financial-horizon'); assert.equal(dynamic.git_verified,false);
dynamic=await api.discoveredPersonalWorkspaceAction({project:'demo-hermes-vps'},personalDevices,discoveryInvoke);
assert.equal(dynamic.root,'/projects/demo'); assert.equal(dynamic.deviceId,hermesOriginal.deviceId);
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'random'},personalDevices,discoveryInvoke)).reason,'unknown_workspace');
for (const bad of [winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/second-brain-workspace']),
 winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/yfc-dev/sub']),
 winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/vault']),
 winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/hermes/.artifacts']),
 winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/financial-horizon']).replace('safe.directory','unsafe'),
 winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/financial-horizon'])+'GIT_CONFIG_COUNT=2\\n']) {
 const response=async()=>({ok:true,result:{content:[{type:'text',text:bad}]}});
 assert.equal((await api.discoveredPersonalWorkspaceAction({project:'financial-horizon-windows'},[personal],response)).reason,'personal_discovery_unavailable');
}
const badLinux=async()=>({ok:true,result:{content:[{type:'text',text:'H454_ROOTS=2|/workspace|/projects/../private|||\\n'}]}});
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'demo-hermes-vps'},[hermesOriginal],badLinux)).reason,'personal_discovery_unavailable');
const ambiguousRoots=winEnv(['D:/Pet-projects/yfc-dev','D:/Pet-projects/team1/demo','D:/Pet-projects/team2/demo']);
const ambiguousInvoke=async()=>({ok:true,result:{content:[{type:'text',text:ambiguousRoots}]}});
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'demo-windows'},[personal],ambiguousInvoke)).reason,'ambiguous_workspace');
const ambiguousCatalog=await api.addDiscoveredPersonalWorkspaces(api.listApprovedWorkspaces([personal]),[personal],ambiguousInvoke);
assert.ok(!ambiguousCatalog.workspaces.some(w=>w.name==='demo-windows-original'));
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'demo-hermes-vps'},[{...hermesOriginal,online:false}],discoveryInvoke)).reason,'personal_device_unavailable');
assert.equal((await api.discoveredPersonalWorkspaceAction({project:'missing-windows'},[personal],discoveryInvoke)).reason,'personal_project_unavailable');
const unavailable=await api.addDiscoveredPersonalWorkspaces(api.listApprovedWorkspaces([]),[],async()=>{throw Error('unexpected')});
assert.equal(unavailable.personal_discovery,'unavailable');
for (const [alias,device,workspace] of [
 ['reminder-bot',hermesOriginal,'reminder-bot-vps-original'],
 ['fit-mini-app',yfcOriginal,'fit-mini-app-vps-original']]) {
 const out=api.resolveApprovedWorkspace({project:alias},[device]);
 assert.equal(out.status,'resolved'); assert.equal(out.workspace,workspace); assert.equal(out.root,'/workspace');
 assert.equal(out.deviceId,device.deviceId); assert.equal(out.scope,'native-personal');
 assert.equal(out.git_verified,false); assert.equal(out.origin,null); assert.equal(out.verification_required_before_write,true);
 for (const devices of [[],[{...device,online:false}],[{...device,paused:true}],
   [{...device,platform:'linux/docker'}],[{...device,deviceId:'h454-linux-native-'+'e'.repeat(32)}],[device,device]]) {
   assert.equal(api.resolveApprovedWorkspace({project:alias},devices).reason,'personal_vps_device_unavailable');
 }
}
const originalCatalog=api.listApprovedWorkspaces([hermesOriginal,yfcOriginal]);
assert.equal(originalCatalog.status,'catalog'); assert.equal(originalCatalog.workspaces.length,2);
assert.equal(originalCatalog.workspaces.find(w=>w.name==='reminder-bot-vps-original').deviceId,hermesOriginal.deviceId);
assert.equal(api.listApprovedWorkspaces([{...yfcOriginal,online:false}]).workspaces[0].device_status,'offline');
for (const [query,device,root,sparse] of [
 ['hermes vps dev',hermesVps,'/workspace/projects/hermes-vps-dev',false],
 ['yfc-vps-dev',yfcVps,'/workspace/projects/yfc-vps-dev',true]]) {
 const out=api.resolveApprovedWorkspace({project:query},[device]);
 assert.equal(out.status,'resolved'); assert.equal(out.root,root); assert.equal(out.scope,'sandbox');
 assert.equal(out.deviceId,device.deviceId); assert.equal(out.sparse,sparse);
 assert.equal(out.git_verified,false); assert.equal(out.verification_required_before_write,true);
 for (const devices of [[],[{...device,online:false}],[{...device,paused:true}],
   [{...device,platform:'linux'}],[{...device,deviceId:'h15-other-'+'b'.repeat(12)}],[device,device]])
   assert.equal(api.resolveApprovedWorkspace({project:query},devices).reason,'vps_device_unavailable');
}
const vpsCatalog=api.listApprovedWorkspaces([hermesVps,yfcVps]);
assert.equal(vpsCatalog.status,'catalog'); assert.equal(vpsCatalog.workspaces.length,2);
assert.equal(vpsCatalog.workspaces.find(w=>w.name==='yfc-vps-dev').sparse,true);
assert.equal(api.listApprovedWorkspaces([{...hermesVps,online:false}]).workspaces[0].device_status,'offline');
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
const wrap=row=>async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(row)}]}});
const withExtra=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],listInvoke);
assert.equal(withExtra.discovery_status,'complete'); assert.equal(withExtra.workspaces.length,6);
const manyProjects=Array.from({length:20},(_,i)=>({...output,repository:'new-project',workspace:`many-${i}`,root:`/workspace/projects/many-${i}`,branch:'feature-'+ 'a'.repeat(220)}));
assert.ok(JSON.stringify(manyProjects).length>8192);
const manyResult=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],wrap({status:'catalog',projects:manyProjects,incomplete:false}));
assert.equal(manyResult.discovery_status,'complete'); assert.equal(manyResult.workspaces.length,25);
const excessive=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],wrap({status:'catalog',projects:Array(33).fill(output),incomplete:false}));
assert.equal(excessive.discovery_status,'unavailable');
assert.equal(withExtra.workspaces[5].name,'new-project'); assert.equal(withExtra.workspaces[5].git_verified,true);
const worktree={...output,workspace:'feature-worktree',repository:'new-project',root:'/workspace/projects/feature-worktree',branch:'feature'};
const worktreeInvoke=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify(worktree)}]}});
assert.equal((await api.sandboxProjectAction({project:'feature-worktree'},[win],worktreeInvoke)).status,'resolved');
const worktreeList=async()=>({ok:true,result:{content:[{type:'text',text:'Process 42 exited with code 0\\nOutput:\\n'+JSON.stringify({status:'catalog',projects:[worktree],incomplete:false})}]}});
const worktreeResult=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],worktreeList);
assert.equal(worktreeResult.discovery_status,'complete'); assert.equal(worktreeResult.workspaces[5].name,'feature-worktree');
const external={...output,repository:'Project_Name.v2',origin:'https://github.com/Other-Owner/Project_Name.v2.git'};
assert.equal((await api.sandboxProjectAction({project:'new-project'},[win],wrap(external))).status,'resolved');
const externalCatalog=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],wrap({status:'catalog',projects:[external],incomplete:false}));
assert.equal(externalCatalog.workspaces[5].origin,external.origin);
for (const bad of [
 {...external,origin:'https://token@github.com/Other-Owner/Project_Name.v2.git'},
 {...external,origin:'https://github.com.evil.invalid/Other-Owner/Project_Name.v2.git'},
 {...external,origin:'https://github.com/Other-Owner/Project_Name.v2.git?token=x'},
 {...external,repository:'different'}]) {
 assert.equal((await api.sandboxProjectAction({project:'new-project'},[win],wrap(bad))).status,'refused');
 const listed=await api.addDiscoveredWorkspaces(api.listApprovedWorkspaces([win]),[win],wrap({status:'catalog',projects:[bad],incomplete:false}));
 assert.equal(listed.discovery_status,'incomplete'); assert.equal(listed.workspaces.length,5);
}
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
        proc = subprocess.run([node, "-e", js, str(module)],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("H15_454_TS_RUNTIME=PASS", proc.stdout)

if __name__ == "__main__":
    unittest.main()
