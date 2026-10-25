/* H455: owner-approved concept C. Read-only, no browser-side MCP execution. */
(() => {
 "use strict";
 const projects = Object.freeze([
  {id:"hermes",name:"Hermes Agent",branch:"main",caption:"Рабочее пространство Hermes"},
  {id:"your-fitness-coach",name:"Your Fitness Coach",branch:"master",caption:"Изолированный проект YFC"},
  {id:"second-brain",name:"Second Brain",branch:"main",caption:"Публичный sandbox; приватное хранилище закрыто"},
  {id:"ai-development-toolkit",name:"AI Development Toolkit",branch:"main",caption:"Инструменты разработки в sandbox"}
 ]);
 const names = Object.freeze(["H15 Windows permanent sandbox","H15 Hermes VPS sandbox","H15 YFC VPS sandbox"]);
 const nodes = {};
 for(const id of ["health","health-dot","time","device-count","project-count","refresh","error","projects",
   "selected-name","selected-caption","selected-state","path","branch","copy","devices","devices-label","read-access","diagnostic"])
   nodes[id] = document.getElementById("brc-" + id);
 let selected="hermes", observation=null, pending=false, failure="not_loaded";
 const errorText=Object.freeze({
  not_loaded:"Нет проверенного снимка BRC.",
  auth:"Сессия Control Center не подтверждена. Войдите через GitHub и обновите страницу.",
  stale:"Нет свежего наблюдения BRC. Проверьте relay и обновление снимка.",
  invalid:"Источник вернул неподтверждённые данные. Статусы скрыты.",
  network:"Не удалось получить снимок BRC. Проверьте соединение и повторите запрос."
 });
 const labels={online:"ОНЛАЙН",offline:"ОФЛАЙН",stale:"УСТАРЕЛО",paused:"ПРИОСТАНОВЛЕНО"};
 const statusLabel=state=>labels[state] || "НЕ ПРОВЕРЕНО";
 const allowedStates=new Set(Object.keys(labels));
 const exact=(object,fields)=>object && typeof object==="object" && !Array.isArray(object)
   && Object.keys(object).length===fields.length && fields.every(k=>Object.hasOwn(object,k));
 function verify(data){
   if(!exact(data,["schema","source","observed_at","status","execution_verified",
     "native_host_access","onboarding_enabled","devices","workspaces"]) ||
      data.schema!==1 || data.source!=="hermes_brc_mcp" ||
      !["online","partial","unavailable"].includes(data.status) ||
      data.execution_verified!==false || data.native_host_access!==false ||
      data.onboarding_enabled!==false || typeof data.observed_at!=="string")return null;
   const when=Date.parse(data.observed_at), lag=Date.now()-when;
   if(!Number.isFinite(when)||lag>300000||lag< -60000)return null;
   if(!Array.isArray(data.devices)||data.devices.length!==3 ||
      !Array.isArray(data.workspaces)||data.workspaces.length!==4)return null;
   for(let i=0;i<3;i++){
     const d=data.devices[i];
     if(!exact(d,["name","status","last_seen_age_seconds","command_execution"])
       ||d.name!==names[i]||!allowedStates.has(d.status)
       ||d.command_execution!=="not_verified"
       ||!Number.isSafeInteger(d.last_seen_age_seconds)
       ||d.last_seen_age_seconds<0||d.last_seen_age_seconds>86400)return null;
   }
   const online=data.devices.filter(d=>d.status==="online").length;
   if(data.status!==(online===3?"online":online?"partial":"unavailable"))return null;
   for(let i=0;i<4;i++){
     const w=data.workspaces[i],p=projects[i];
     const ready=data.devices[0].status==="online"?"reachable_not_git_verified":"not_ready";
     if(!exact(w,["name","root","branch","git_verified","state"]) ||
        w.name!==p.id || w.branch!==p.branch ||
        w.root!=="/workspace/projects/"+p.id ||
        w.git_verified!==false || w.state!==ready)return null;
   }
   return data;
 }
 function element(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e;}
 function renderDevices(){
   nodes.devices.replaceChildren();
   if(!observation){nodes.devices.append(element("li","","Свежие данные устройств недоступны"));nodes["devices-label"].textContent="Нет данных";return;}
   const online=observation.devices.filter(d=>d.status==="online").length;
   nodes["devices-label"].textContent=online+" ONLINE";
   observation.devices.forEach(d=>{
     const row=element("li"),dot=element("span","brc-device-dot "+d.status),
       details=element("div","brc-device-text"),label=element("strong","",d.name),
       lag=Math.max(0,Math.floor((Date.now()-Date.parse(observation.observed_at))/1000)),
       last=element("small","","Последний сигнал: ~"+(d.last_seen_age_seconds+lag)+" с назад (по снимку)"),
       state=element("span","brc-device-state "+d.status,statusLabel(d.status));
     dot.setAttribute("aria-hidden","true");details.append(label,last);row.append(dot,details,state);nodes.devices.append(row);
   });
 }
 function renderSelection(){
   const p=projects.find(x=>x.id===selected)||projects[0];
   nodes["selected-name"].textContent=p.name;
   nodes["selected-caption"].textContent=p.caption;
   nodes.path.textContent="/workspace/projects/"+p.id;
   nodes.branch.textContent=p.branch;
   const record=observation?.workspaces.find(x=>x.name===p.id);
   const connected=record?.state==="reachable_not_git_verified"
     ?observation.devices[0].status:undefined;
   nodes["selected-state"].className="brc-state "+(connected||"unknown");
   nodes["selected-state"].textContent=statusLabel(connected);
   for(const btn of nodes.projects.querySelectorAll("button[data-project]")){
     const isCurrent=btn.dataset.project===p.id;
     btn.classList.toggle("selected",isCurrent);
     btn.setAttribute("aria-pressed",String(isCurrent));
     btn.querySelector("small").textContent=p.branch+" · Git не проверен";
   }
 }
 function render(){
   if(observation && Date.now()-Date.parse(observation.observed_at)>300000){
     observation=null;failure="stale";
   }
   const state=observation?.status;
   nodes.health.textContent=state==="online"?"Hermes BRC · подключён":
     state==="partial"?"Hermes BRC · частичное подключение":"Hermes BRC · статус недоступен";
   nodes["health-dot"].className="brc-dot "+(state==="online"?"":state==="partial"?"warn":"muted");
   nodes.time.textContent=observation?new Date(observation.observed_at).toLocaleString("ru-RU"):"Нет проверенного снимка";
   nodes["device-count"].textContent=observation?observation.devices.filter(d=>d.status==="online").length+"/3":"—";
   nodes["project-count"].textContent=observation?observation.workspaces.filter(w=>w.state==="reachable_not_git_verified").length+"/4":"—";
   nodes["read-access"].textContent=observation?"Разрешено":"Не проверено";
   nodes.error.hidden=Boolean(observation);
   if(!observation)nodes.error.textContent=errorText[failure]||errorText.network;
   nodes.diagnostic.textContent=!observation?"Диагностика: "+(errorText[failure]||errorText.network):
     state==="online"?"Снимок свежий, 3 устройства на связи. Доступность инструментов и Git не проверены.":
     state==="partial"?"Свежий снимок: часть устройств недоступна. Проверьте соединение через Hermes MCP.":
     "Свежий снимок: устройства недоступны. Проверьте состояние relay и агентов.";
   renderDevices();renderSelection();
 }
 async function refresh(){
   if(pending)return;
   pending=true;nodes.refresh.disabled=true;
   const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);
   try{
     const response=await fetch("/api/providers/hermes-brc",{credentials:"same-origin",cache:"no-store",signal:controller.signal});
     if(response.status===401)throw Error("auth");
     if(response.status===503)throw Error("stale");
     if(!response.ok)throw Error("network");
     let raw;
     try{raw=await response.json();}catch(_){throw Error("invalid");}
     const data=verify(raw);
     if(!data)throw Error("invalid");
     observation=data;failure=null;
   }catch(error){observation=null;failure=Object.hasOwn(errorText,error.message)?error.message:"network";}
   finally{clearTimeout(timeout);pending=false;nodes.refresh.disabled=false;render();}
 }
 nodes.projects.addEventListener("click",event=>{
   const btn=event.target.closest("button[data-project]");
   if(!btn || !nodes.projects.contains(btn))return;
   if(projects.some(p=>p.id===btn.dataset.project)){selected=btn.dataset.project;renderSelection();}
 });
 nodes.copy.addEventListener("click",async()=>{
   const content=nodes.path.textContent;
   try{
     if(!navigator.clipboard?.writeText)throw Error("clipboard_unavailable");
     await navigator.clipboard.writeText(content);
     nodes.copy.textContent="Скопировано";
   }catch(_){
     const selection=window.getSelection(),range=document.createRange();
     selection.removeAllRanges();range.selectNodeContents(nodes.path);selection.addRange(range);
     nodes.copy.textContent="Путь выделен";
   }
   setTimeout(()=>{nodes.copy.textContent="Копировать";},1700);
 });
 nodes.refresh.addEventListener("click",refresh);
 document.addEventListener("visibilitychange",()=>{if(!document.hidden)void refresh();});
 window.setInterval(()=>{if(!document.hidden)void refresh();},60000);
 render();void refresh();
})();
