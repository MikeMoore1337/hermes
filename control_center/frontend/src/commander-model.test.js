import assert from "node:assert/strict";
import test from "node:test";
import {commanderProjects,commanderDevices,parseBrcObservation,
 projectExpectedOrigin,projectSandboxRoot} from "./commander-model.js";

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
 v.devices[1].status="offline";
 v.devices[2].status="stale";
 v.workspaces[0].state="not_ready";
 assert.deepEqual(parseBrcObservation(v),v);
 assert.equal(v.execution_verified,false);
 assert.equal(v.native_host_access,false);
});
