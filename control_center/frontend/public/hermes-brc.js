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
   "selected-name","selected-caption","selected-state","path","branch","copy","devices","devices-label","read-access","diagnostic","check-source","source-result","client-check","client-check-status"])
   nodes[id] = document.getElementById("brc-" + id);
 let selected="hermes", observation=null, pending=false, failure="not_loaded", sourcePending=false;
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
   if(dialog.open&&!onboarding.result.hidden)renderOnboardingDevice();
 }
 async function refresh(){
   if(pending)return;
   pending=true;nodes.refresh.disabled=true;
   nodes["source-result"].textContent="Проверка источника не выполнялась";
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
 async function checkSource(){
   if(sourcePending)return;
   sourcePending=true;nodes["check-source"].disabled=true;
   nodes["source-result"].textContent="Проверяется сохранённый снимок. Команды на устройства не выполняются.";
   const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),8000);
   try{
     const res=await fetch("/api/providers/hermes-brc/source-check",{
       credentials:"same-origin",cache:"no-store",signal:controller.signal
     });
     if(res.status===401)throw Error("Требуется авторизация через GitHub.");
     if(res.status===503)throw Error("Снимок недоступен или устарел.");
     if(!res.ok)throw Error("Проверка источника не выполнена.");
     const value=await res.json();
     if(!exact(value,["schema","source","check","checked_at","snapshot_age_seconds",
          "status","devices","verification"])||value.schema!==1||
        value.source!=="hermes_brc_validated_snapshot"||
        value.check!=="snapshot_validity_only"||
        !["online","partial","unavailable"].includes(value.status)||
        !Number.isSafeInteger(value.snapshot_age_seconds)||
        value.snapshot_age_seconds<0||value.snapshot_age_seconds>300||
        typeof value.checked_at!=="string"||
        !Number.isFinite(Date.parse(value.checked_at))||
        Math.abs(Date.now()-Date.parse(value.checked_at))>60000||
        !exact(value.verification,["snapshot","relay","oauth","tools","git","onboarding","native_host"])||
        value.verification.snapshot!=="valid"||
        !["relay","oauth","tools","git"].every(k=>value.verification[k]==="not_probed")||
        value.verification.onboarding!=="disabled"||value.verification.native_host!=="disabled"||
        !Array.isArray(value.devices)||value.devices.length!==3)throw Error("Некорректный ответ источника.");
     for(let i=0;i<3;i++){
       const d=value.devices[i];
       if(!exact(d,["name","status","last_seen_age_seconds","command_execution"])||
          d.name!==names[i]||!allowedStates.has(d.status)||
          !Number.isSafeInteger(d.last_seen_age_seconds)||d.last_seen_age_seconds<0||
          d.command_execution!=="not_verified")throw Error("Некорректный ответ источника.");
     }
     const online=value.devices.filter(d=>d.status==="online").length;
     if(value.status!==(online===3?"online":online?"partial":"unavailable"))
       throw Error("Некорректный ответ источника.");
     nodes["source-result"].textContent="Источник: проверенный снимок "+value.snapshot_age_seconds+
       " с назад; устройств онлайн "+online+"/3. Relay, OAuth, команды и Git не проверялись.";
   }catch(error){
     const messages=["Требуется авторизация через GitHub.","Снимок недоступен или устарел.",
       "Некорректный ответ источника."];
     nodes["source-result"].textContent=messages.includes(error.message)?error.message:
       "Не удалось проверить снимок. Повторите запрос после восстановления связи.";
   }finally{clearTimeout(timeout);sourcePending=false;nodes["check-source"].disabled=false;}
 }

 // Generates text for an independently connected ChatGPT/Codex MCP client.
 // No browser-initiated device calls, fixed canonical projects and commands.
 function clientCheckRequest(){
   const p=projects.find(item=>item.id===selected)||projects[0];
   return [
     "Проверь подключение Hermes Commander к проекту "+p.name+".",
     "Используй только подключённый Hermes Agent MCP; ничего не изменяй.",
     "1. Вызови list_devices, затем list_workspaces и resolve_workspace для "+p.id+".",
     "2. Найди три разрешённых sandbox-устройства по именам из list_devices;",
     "   для каждого вызови list_directory и get_file_info для /workspace.",
     "3. На Windows sandbox проверь существующий каталог "+"/workspace/projects/"+p.id,
     "   через get_file_info и list_directory (depth=1).",
     "4. Покажи PASS/FAIL/NOT_VERIFIED отдельно по устройствам,",
     "   проверенный root, branch и только фактически проверенные Git-данные.",
     "   Не заявляй права записи или успешность команд на основании статуса online.",
     "5. Не открывай оригинальные папки Windows, приватный vault,",
     "   не запускай процессы, не редактируй файлы и не меняй права.",
     "   Если MCP недоступен, честно сообщи об ошибке и предложи",
     "   восстановить существующее подключение без переподключения устройства."
   ].join("\n");
 }
 async function copyClientCheck(){
   const value=clientCheckRequest();
   try{
     if(!navigator.clipboard?.writeText)throw Error("clipboard_unavailable");
     await navigator.clipboard.writeText(value);
     nodes["client-check-status"].textContent="Запрос скопирован. Вставьте его в ChatGPT или Codex с подключённым Hermes Agent.";
   }catch(_){
     nodes["client-check-status"].textContent="Копирование недоступно в браузере. Используйте подключённый Hermes Agent для проверки выбранного проекта.";
   }
 }

 const onboarding=Object.fromEntries(["open","close","cancel","form","entry","result","result-title",
   "step","url","error","preview","back","repository","device","root","result-note"].map(key=>
     [key,document.getElementById("brc-onboard-"+key)]));
 const dialog=document.getElementById("brc-onboard");
 function renderOnboardingDevice(){
   const status=observation&&verify(observation)?.devices[0].status;
   const text={online:"на связи",offline:"не на связи",paused:"приостановлено",stale:"данные устарели"}[status];
   onboarding.device.textContent=text?"Windows sandbox — "+text+" (по снимку)":"Windows sandbox — нет свежих данных";
 }
 const githubUrl=/^https:\/\/github\.com\/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)\/([a-z0-9_][a-z0-9_.-]{0,103})\/?$/i;
 let previewController=null;
 function resetOnboarding(){
   previewController?.abort();previewController=null;onboarding.form.reset();
   onboarding.entry.hidden=false;onboarding.result.hidden=true;onboarding.step.textContent="Шаг 1 из 2";
   onboarding.error.textContent="";onboarding.url.removeAttribute("aria-invalid");onboarding.preview.disabled=false;
 }
 onboarding.open.addEventListener("click",()=>{resetOnboarding();dialog.showModal();onboarding.url.focus();});
 onboarding.close.addEventListener("click",()=>dialog.close());
 onboarding.cancel.addEventListener("click",()=>dialog.close());
 dialog.addEventListener("close",()=>{resetOnboarding();onboarding.open.focus();});
 dialog.addEventListener("keydown",event=>{
   if(event.key!=="Tab")return;
   const focusable=[...dialog.querySelectorAll("button:not(:disabled),input:not(:disabled)")]
     .filter(element=>element.getClientRects().length);
   if(!focusable.length)return;
   const first=focusable[0],last=focusable[focusable.length-1];
   if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
   else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
 });
 onboarding.back.addEventListener("click",()=>{
   onboarding.result.hidden=true;onboarding.entry.hidden=false;onboarding.step.textContent="Шаг 1 из 2";
   onboarding.url.focus();
 });
 onboarding.url.addEventListener("input",()=>onboarding.url.removeAttribute("aria-invalid"));
 onboarding.form.addEventListener("submit",async event=>{
   event.preventDefault();
   if(previewController)return;
   const input=onboarding.url.value.trim(),match=githubUrl.exec(input);
   const repository=match?.[2].replace(/\.git$/i,"");
   if(!match || input.length>200 || !repository || repository.length>100 || repository.endsWith(".") || repository.includes("..")){
     onboarding.error.textContent="Введите HTTPS-ссылку GitHub с допустимым именем проекта.";
     onboarding.url.setAttribute("aria-invalid","true");
     onboarding.url.focus();return;
   }
   const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),8000);
   previewController=controller;onboarding.preview.disabled=true;onboarding.error.textContent="Проверяем адрес и публичный репозиторий…";
   try{
     const response=await fetch("/api/providers/hermes-brc/onboarding-preview",{
       method:"POST",credentials:"same-origin",cache:"no-store",signal:controller.signal,
       headers:{"Content-Type":"application/json","X-Hermes-Onboarding-Intent":"owner-interactive"},
       body:JSON.stringify({repository_url:input})
     });
     if(response.status===401||response.status===403)throw Error("auth");
     if(!response.ok)throw Error("unavailable");
     const value=await response.json(), name=repository.toLowerCase();
     if(!exact(value,["schema","status","repository","device","root","scope","catalog","remote","filesystem","can_connect"])||
       value.schema!==1||value.status!=="preview_only"||value.repository!=="https://github.com/"+match[1]+"/"+name+".git"||
       value.device!=="Windows sandbox"||value.root!=="/workspace/projects/"+name||value.scope!=="sandbox"||
       !["reserved","not_reserved"].includes(value.catalog)||
       (value.catalog==="reserved"?value.remote!=="not_checked":!["public_confirmed","unavailable"].includes(value.remote))||
       value.filesystem!=="not_checked"||value.can_connect!==false)throw Error("invalid");
     if(!dialog.open||previewController!==controller)return;
     onboarding.repository.textContent=value.repository;onboarding.root.textContent=value.root;renderOnboardingDevice();
     onboarding["result-note"].textContent=value.catalog==="reserved"?
       "Имя зарезервировано или уже есть во встроенном каталоге. Подключение заблокировано.":
       value.remote==="public_confirmed"?
       "Публичный репозиторий найден на GitHub; это имя отсутствует во встроенном каталоге.":
       "Не удалось подтвердить публичный репозиторий. Проверьте адрес или повторите позже.";
     onboarding.entry.hidden=true;onboarding.result.hidden=false;onboarding.step.textContent="Шаг 2 из 2";
     onboarding["result-title"].focus();
   }catch(error){
     if(!dialog.open||previewController!==controller)return;
     onboarding.error.textContent=error.message==="auth"?
       "Предпросмотр доступен после входа владельца через GitHub.":
       "Предпросмотр недоступен. Никаких изменений не выполнено.";
   }finally{
     clearTimeout(timeout);
     if(previewController===controller){previewController=null;onboarding.preview.disabled=false;}
   }
 });

 nodes["client-check"].addEventListener("click",copyClientCheck);
 nodes.refresh.addEventListener("click",refresh);
 nodes["check-source"].addEventListener("click",checkSource);
 document.addEventListener("visibilitychange",()=>{if(!document.hidden)void refresh();});
 window.setInterval(()=>{if(!document.hidden)void refresh();},60000);
 render();void refresh();
})();
