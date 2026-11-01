// Approved owner paths from Hermes Commander Redesign (#455).
// Labels are NOT filesystem mounts, permissions, or live Git verification.
export const commanderProjects=Object.freeze([
  {id:"toolkit",name:"AI Development Toolkit",short:"Toolkit",repo:"ai-development-toolkit",branch:"main",windowsPath:"D:\\Pet-projects\\ai-development-toolkit"},
  {id:"hermes",name:"Hermes",short:"Hermes",repo:"hermes",branch:"main",windowsPath:"D:\\Pet-projects\\hermes"},
  {id:"brain",name:"Second Brain",short:"Second Brain",repo:"second-brain",branch:"main",windowsPath:"D:\\Pet-projects\\second-brain-workspace\\second-brain",parentWorkspace:"D:\\Pet-projects\\second-brain-workspace"},
  {id:"yfc",name:"Your Fitness Coach",short:"YFC",repo:"your-fitness-coach",branch:"master",windowsPath:"D:\\Pet-projects\\your-fitness-coach"},
]);

export const commanderDevices=Object.freeze([
 "H15 Windows permanent sandbox",
 "H15 Hermes VPS sandbox",
 "H15 YFC VPS sandbox",
]);

export const projectSandboxRoot=project=>"/workspace/projects/"+project.repo;
export const projectExpectedOrigin=project=>"https://github.com/MikeMoore1337/"+project.repo+".git";

// Strict owner-scoped BRC metadata. A device being online never proves tool
// execution, Git state, or permission to reach the Windows host.
const exact=(value,keys)=>value!==null&&typeof value==="object"&&!Array.isArray(value)
 &&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const states=new Set(["online","offline","paused","stale"]);
const workspaceFields=["name","root","branch","git_verified","state"];
const deviceFields=["name","status","last_seen_age_seconds","command_execution"];
const projectByRepo=new Map(commanderProjects.map(p=>[p.repo,p]));
export function parseBrcObservation(value,now=Date.now()){
 if(!exact(value,["schema","source","observed_at","status","execution_verified",
     "native_host_access","onboarding_enabled","devices","workspaces"])||
    value.schema!==1||value.source!=="hermes_brc_mcp"||
    !["online","partial","unavailable"].includes(value.status)||
    value.execution_verified!==false||value.native_host_access!==false||
    value.onboarding_enabled!==false||
    typeof value.observed_at!=="string"||
    !Array.isArray(value.devices)||value.devices.length!==3||
    !Array.isArray(value.workspaces)||value.workspaces.length!==4)return null;
 const stamp=Date.parse(value.observed_at),lag=now-stamp;
 if(!Number.isFinite(stamp)||lag>300000||lag< -60000)return null;
 if(value.devices.some((d,i)=>!exact(d,deviceFields)||
    d.name!==commanderDevices[i]||!states.has(d.status)||
    d.command_execution!=="not_verified"||!Number.isSafeInteger(d.last_seen_age_seconds)||
    d.last_seen_age_seconds<0||d.last_seen_age_seconds>86400))return null;
 const online=value.devices.filter(d=>d.status==="online").length;
 if(value.status!==(online===3?"online":online?"partial":"unavailable"))return null;
 const expected=value.devices[0].status==="online"?"reachable_not_git_verified":"not_ready";
 if(value.workspaces.some(w=>{
   const p=projectByRepo.get(w?.name);
   return !exact(w,workspaceFields)||!p||w.root!==projectSandboxRoot(p)||
     w.branch!==p.branch||w.git_verified!==false||w.state!==expected;
 }))return null;
 if(new Set(value.workspaces.map(w=>w.name)).size!==4)return null;
 return value;
}

// The explicit source-check revalidates only the existing sanitized snapshot;
// relay, tools, Git, OAuth and original Windows access remain unprobed.
export function parseBrcSourceCheck(value,now=Date.now()){
 if(!exact(value,["schema","source","check","checked_at","snapshot_age_seconds",
     "status","devices","verification"])||value.schema!==1||
    value.source!=="hermes_brc_validated_snapshot"||
    value.check!=="snapshot_validity_only"||
    !["online","partial","unavailable"].includes(value.status)||
    !Number.isSafeInteger(value.snapshot_age_seconds)||
    value.snapshot_age_seconds<0||value.snapshot_age_seconds>300||
    typeof value.checked_at!=="string")return null;
 const stamp=Date.parse(value.checked_at);
 if(!Number.isFinite(stamp)||Math.abs(now-stamp)>60000)return null;
 if(!exact(value.verification,["snapshot","relay","oauth","tools","git","onboarding","native_host"])||
    value.verification.snapshot!=="valid"||
    !["relay","oauth","tools","git"].every(key=>value.verification[key]==="not_probed")||
    value.verification.onboarding!=="disabled"||
    value.verification.native_host!=="disabled")return null;
 if(!Array.isArray(value.devices)||value.devices.length!==3||
    value.devices.some((d,i)=>!exact(d,deviceFields)||
      d.name!==commanderDevices[i]||!states.has(d.status)||
      d.command_execution!=="not_verified"||!Number.isSafeInteger(d.last_seen_age_seconds)||
      d.last_seen_age_seconds<0||d.last_seen_age_seconds>86400))return null;
 const online=value.devices.filter(d=>d.status==="online").length;
 if(value.status!==(online===3?"online":online?"partial":"unavailable"))return null;
 return value;
}
