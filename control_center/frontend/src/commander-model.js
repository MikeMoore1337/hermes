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

// Strictly read the already sanitized metadata contract. Reject arbitrary
// browser/foreign fields instead of presenting them as trusted live health.
export function parseBrcObservation(value){
 if(!value || typeof value!=="object" || Array.isArray(value)
    || value.schema!==1 || value.source!=="hermes_brc_mcp"
    || !["online","partial","unavailable"].includes(value.status)
    || value.execution_verified!==false || value.native_host_access!==false
    || value.onboarding_enabled!==false
    || typeof value.observed_at!=="string"
    || !Array.isArray(value.devices) || value.devices.length!==3
    || !Array.isArray(value.workspaces) || value.workspaces.length!==4)return null;
 const stamp=Date.parse(value.observed_at);
 if(!Number.isFinite(stamp) || Math.abs(Date.now()-stamp)>360000)return null;
 if(value.devices.some((d,i)=>!d || d.name!==commanderDevices[i]
    || !["online","offline","paused","stale"].includes(d.status)
    || d.command_execution!=="not_verified"
    || !Number.isSafeInteger(d.last_seen_age_seconds) || d.last_seen_age_seconds<0
    || Object.keys(d).some(k=>!["name","status","last_seen_age_seconds","command_execution"].includes(k))))return null;
 if(value.workspaces.some((w,i)=>{
    const p=commanderProjects.find(p=>p.repo===w?.name);
    return !p || w.root!==projectSandboxRoot(p) || w.branch!==p.branch
      || w.git_verified!==false || !["reachable_not_git_verified","not_ready"].includes(w.state)
      || Object.keys(w).some(k=>!["name","root","branch","git_verified","state"].includes(k));
 }))return null;
 if(new Set(value.workspaces.map(w=>w.name)).size!==4)return null;
 return value;
}
