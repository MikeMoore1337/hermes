import assert from "node:assert/strict";
import test from "node:test";
import {commanderProjects,commanderDevices,parseBrcObservation,
 projectExpectedOrigin,projectSandboxRoot,parseBrcSourceCheck} from "./commander-model.js";

const clean=()=>({
 schema:1,source:"hermes_brc_mcp",status:"online",
 observed_at:new Date().toISOString(),execution_verified:false,
 native_host_access:false,onboarding_enabled:false,
 devices:commanderDevices.map(name=>({name,status:"online",
    last_seen_age_seconds:2,command_execution:"not_verified"})),
 workspaces:commanderProjects.map(p=>({name:p.repo,root:projectSandboxRoot(p),
    branch:p.branch,git_verified:false,state:"reachable_not_git_verified"}))
});
const clone=obj=>structuredClone(obj);
test("approved explorer resolves four exact project contracts",()=>{
 assert.equal(commanderProjects.length,4);
 assert.deepEqual(commanderProjects.map(p=>p.branch),["main","main","main","master"]);
 for(const p of commanderProjects){
  assert.equal(projectSandboxRoot(p),"/workspace/projects/"+p.repo);
  assert.equal(projectExpectedOrigin(p),"https://github.com/MikeMoore1337/"+p.repo+".git");
  assert.ok(p.windowsPath.startsWith("D:\\Pet-projects\\"));
 }
 const brain=commanderProjects.find(p=>p.id==="brain");
 assert.equal(brain.windowsPath,brain.parentWorkspace+"\\second-brain");
 assert.notEqual(brain.parentWorkspace,brain.windowsPath);
});
test("only valid sanitized, fresh owner-scoped observation is rendered",()=>{
 const data=clean();
 assert.deepEqual(parseBrcObservation(data),data);
});
test("forged permissions, device list and malformed data are denied",()=>{
 for(const mutate of [
  v=>v.schema=2,v=>v.source="desktop_commander_remote_mcp",
  v=>v.execution_verified=true,v=>v.native_host_access=true,
  v=>v.onboarding_enabled=true,
  v=>v.devices[0].name="unapproved device",
  v=>v.devices[1].status="healthy",
  v=>v.devices[0].deviceId="secret",
  v=>v.devices[2].last_seen_age_seconds=-1,
  v=>v.workspaces[0].root="D:\\Pet-projects\\hermes",
  v=>v.workspaces[0].git_verified=true,
  v=>v.workspaces[1].name=v.workspaces[0].name,
  v=>v.workspaces[0].branch="danger",
  v=>v.workspaces[0].unknown="oops",
  v=>v.status="critical",
  v=>v.observed_at="2000-01-01T00:00:00Z",
 ]){
   const v=clone(clean());mutate(v);
   assert.equal(parseBrcObservation(v),null);
 }
 assert.equal(parseBrcObservation(null),null);
});
test("offline and stale presence still never grant shell or host access",()=>{
 const v=clean();
 v.status="partial";
 v.devices[0].status="offline";
 v.devices[2].status="stale";
 v.workspaces.forEach(w=>{w.state="not_ready";});
 assert.deepEqual(parseBrcObservation(v),v);
 assert.equal(v.execution_verified,false);
 assert.equal(v.native_host_access,false);
});

const goodSourceCheck=()=>({
 schema:1,source:"hermes_brc_validated_snapshot",check:"snapshot_validity_only",
 checked_at:new Date().toISOString(),snapshot_age_seconds:5,status:"online",
 devices:commanderDevices.map(name=>({name,status:"online",
  last_seen_age_seconds:12,command_execution:"not_verified"})),
 verification:{snapshot:"valid",relay:"not_probed",oauth:"not_probed",
  tools:"not_probed",git:"not_probed",onboarding:"disabled",native_host:"disabled"}
});
test("source check validates only a bounded snapshot, never MCP execution",()=>{
 const valid=goodSourceCheck();
 assert.deepEqual(parseBrcSourceCheck(valid),valid);
 for(const mutate of [
  v=>v.source="owner_shell",v=>v.extra="token",
  v=>v.verification.tools="verified",v=>v.verification.native_host="enabled",
  v=>v.devices[0].command_execution="verified",v=>v.devices[1].deviceId="secret",
  v=>v.snapshot_age_seconds=999,v=>v.checked_at="2000-01-01T00:00:00Z"
 ]){
  const forged=clone(valid);mutate(forged);
  assert.equal(parseBrcSourceCheck(forged),null);
 }
});
test("snapshot refuses extra fields, inconsistent presence and state promotion",()=>{
 for(const mutate of [
  v=>v.secret="bad",v=>v.devices[0].last_seen_age_seconds=99999,
  v=>v.status="partial",v=>v.workspaces[0].state="not_ready",
  v=>v.observed_at=new Date(Date.now()-310000).toISOString()
 ]){
  const forged=clone(clean());mutate(forged);
  assert.equal(parseBrcObservation(forged),null);
 }
});

test("fork snapshot uses each workspace's device and rejects forged access",()=>{
 const value={schema:2,source:"hermes_brc_fork",status:"partial",observed_at:new Date().toISOString(),
  execution_verified:false,native_host_access:"not_verified",onboarding_enabled:false,
  devices:[{name:"Laptop",status:"online",last_seen_age_seconds:1,command_execution:"not_verified"},
   {name:"Sandbox",status:"paused",last_seen_age_seconds:2,command_execution:"not_verified"}],
  workspaces:[{name:"alpha",root:"/workspace/projects/alpha",branch:"main",device_name:"Laptop",git_verified:false,state:"reachable_not_git_verified"},
   {name:"beta",root:"/workspace/projects/beta",branch:"dev",device_name:"Sandbox",git_verified:false,state:"not_ready"}]};
 assert.deepEqual(parseBrcObservation(value),value);
 assert.equal(projectSandboxRoot({repo:"alpha",root:"/workspace/projects/other"}),"/workspace/projects/other");
 for(const mutate of [
  v=>v.devices[0].deviceId="private",v=>v.workspaces[0].device_name="Other",
  v=>v.workspaces[1].state="reachable_not_git_verified",v=>v.workspaces[0].root="/etc/secrets",
  v=>v.workspaces[0].branch="../production",v=>v.workspaces[0].git_verified=true,
  v=>v.devices[1].name="Laptop",v=>v.status="online",v=>v.onboarding_enabled=true,
  v=>v.native_host_access=false,v=>v.devices[0].last_seen_age_seconds=301,
 ]){const forged=clone(value);mutate(forged);assert.equal(parseBrcObservation(forged),null);}
 const check=goodSourceCheck();check.schema=2;check.devices=value.devices;check.status="partial";check.verification.native_host="not_probed";
 assert.deepEqual(parseBrcSourceCheck(check),check);
 const expired=clone(value);expired.devices[0].last_seen_age_seconds=299;
 assert.equal(parseBrcObservation(expired,Date.parse(expired.observed_at)+2000),null);
});

test("fork source check refuses presence that expired in transit",()=>{
 const now=Date.now(), checked=goodSourceCheck();
 checked.schema=2;checked.verification.native_host="not_probed";
 checked.devices=[{name:"Laptop",status:"online",last_seen_age_seconds:290,command_execution:"not_verified"}];
 checked.checked_at=new Date(now-10000).toISOString();
 assert.deepEqual(parseBrcSourceCheck(checked,now),checked);
 const staleHeartbeat=clone(checked);staleHeartbeat.devices[0].last_seen_age_seconds=291;
 assert.equal(parseBrcSourceCheck(staleHeartbeat,now),null);
 const staleSnapshot=clone(checked);staleSnapshot.snapshot_age_seconds=291;
 assert.equal(parseBrcSourceCheck(staleSnapshot,now),null);
});
