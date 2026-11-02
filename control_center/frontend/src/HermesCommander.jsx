import React,{useCallback,useEffect,useMemo,useRef,useState} from "react";
import {Activity,ArrowUpRight,Check,Clipboard,ExternalLink,FolderGit2,
  GitBranch,HardDrive,LockKeyhole,Monitor,RefreshCw,Search,Server,ShieldCheck,
  ShieldAlert,Workflow} from "lucide-react";
import {commanderDevices,commanderProjects,parseBrcObservation,
  parseBrcSourceCheck,projectSandboxRoot} from "./commander-model.js";
import "./commander.css";

// This is an Orbit 3.0 module, not a second standalone application.
// API requests are read-only and never access the desktop or MCP directly.
const projects=[
  ...commanderProjects.map(p=>({
    ...p,name:p.repo==="hermes"?"Hermes Agent":p.name,
    caption:p.repo==="hermes"?"Рабочее пространство Hermes":
      p.repo==="your-fitness-coach"?"Изолированный проект YFC":
      p.repo==="second-brain"?"Публичный sandbox; приватное хранилище закрыто":
      "Инструменты разработки в sandbox"
  }))
];
const errorText={
 not_loaded:"Нет проверенного снимка BRC.",
 auth:"Сессия Control Center не подтверждена. Войдите через GitHub и обновите страницу.",
 stale:"Нет свежего наблюдения BRC. Проверьте relay и обновление снимка.",
 invalid:"Источник вернул неподтверждённые данные. Статусы скрыты.",
 network:"Не удалось получить снимок BRC. Проверьте соединение и повторите запрос."
};
const labels={online:"ОНЛАЙН",offline:"ОФЛАЙН",paused:"ПРИОСТАНОВЛЕНО",stale:"УСТАРЕЛО"};
const stateLabel=value=>labels[value]||"НЕ ПРОВЕРЕНО";
const SOURCE_URL="/api/providers/hermes-brc/source-check";
const SNAPSHOT_URL="/api/providers/hermes-brc";
const issue="https://github.com/MikeMoore1337/hermes/issues/455";
const formatTime=value=>{
 const date=Date.parse(value||"");
 return Number.isFinite(date)?new Date(date).toLocaleString("ru-RU"):"Нет проверенного снимка";
};
function clientCheckRequest(project){
 return [
  "Проверь подключение Hermes Commander к проекту "+project.name+".",
  "Используй только подключённый Hermes Agent MCP; ничего не изменяй.",
  "1. Вызови list_devices, затем list_workspaces и resolve_workspace для "+project.repo+".",
  "2. Найди три разрешённых sandbox-устройства по именам из list_devices;",
  "   для каждого вызови list_directory и get_file_info для /workspace.",
  "3. На Windows sandbox проверь существующий каталог "+projectSandboxRoot(project),
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
function Status({status}){
 return <span className={"oc-state oc-state-"+(status||"unknown")}>
  <i aria-hidden="true"/>{stateLabel(status)}</span>;
}
function SectionHead({number,title,sub,children}){
 return <div className="oc-section-head">
  <div><span className="orbit-section-code">{number}</span>
   <h2>{title}</h2>{sub&&<p>{sub}</p>}</div>{children}
 </div>;
}
export default function HermesCommander(){
 const [selected,setSelected]=useState("hermes");
 const [query,setQuery]=useState("");
 const [observation,setObservation]=useState(null);
 const [fault,setFault]=useState("not_loaded");
 const [busy,setBusy]=useState(false);
 const [sourceBusy,setSourceBusy]=useState(false);
 const [sourceResult,setSourceResult]=useState("Проверка источника не выполнялась");
 const [clientStatus,setClientStatus]=useState("Выберите проект для проверки в своём MCP-клиенте.");
 const [copied,setCopied]=useState("");
 const [refreshEpoch,setRefreshEpoch]=useState(0);
 const [now,setNow]=useState(Date.now());
 const codeRef=useRef(null);
 const current=projects.find(p=>p.repo===selected)||projects[0];
 const shown=useMemo(()=>projects.filter(p=>
   (p.name+" "+p.repo+" "+p.branch).toLocaleLowerCase("ru")
    .includes(query.trim().toLocaleLowerCase("ru"))),[query]);
 const refresh=useCallback(()=>setRefreshEpoch(n=>n+1),[]);

 useEffect(()=>{
  const tick=()=>{setNow(Date.now());if(!document.hidden)refresh();};
  const timer=setInterval(tick,60000);
  const visible=()=>{if(!document.hidden)tick();};
  document.addEventListener("visibilitychange",visible);
  return()=>{clearInterval(timer);document.removeEventListener("visibilitychange",visible);};
 },[refresh]);
 useEffect(()=>{
  let active=true;
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),8000);
  setBusy(true);
  setSourceResult("Проверка источника не выполнялась");
  (async()=>{
   try{
    const response=await fetch(SNAPSHOT_URL,{
      credentials:"same-origin",cache:"no-store",signal:controller.signal
    });
    if(response.status===401)throw Error("auth");
    if(response.status===503)throw Error("stale");
    if(!response.ok)throw Error("network");
    let data;
    try{data=await response.json();}catch(_){throw Error("invalid");}
    const verified=parseBrcObservation(data);
    if(!verified)throw Error("invalid");
    if(active){setObservation(verified);setFault("");setNow(Date.now());}
   }catch(error){
    if(active){setObservation(null);
      setFault(Object.hasOwn(errorText,error.message)?error.message:"network");}
   }finally{clearTimeout(timeout);if(active)setBusy(false);}
  })();
  return()=>{active=false;clearTimeout(timeout);controller.abort();};
 },[refreshEpoch]);

 const live=observation&&now-Date.parse(observation.observed_at)<=300000?observation:null;
 const state=live?.status;
 const online=live?.devices.filter(d=>d.status==="online").length;
 const reachable=live?.workspaces.filter(w=>w.state==="reachable_not_git_verified").length;
 const deviceState=live?.devices[0]?.status;
 const selectedState=live?deviceState:undefined;
 const diagnostic=!live?"Диагностика: "+(errorText[fault]||errorText.stale):
    state==="online"?"Снимок свежий, 3 устройства на связи. Доступность инструментов и Git не проверены.":
    state==="partial"?"Свежий снимок: часть устройств недоступна. Проверьте соединение через Hermes MCP.":
    "Свежий снимок: устройства недоступны. Проверьте состояние relay и агентов.";

 const checkSource=async()=>{
  if(sourceBusy)return;
  setSourceBusy(true);
  setSourceResult("Проверяется сохранённый снимок. Команды на устройства не выполняются.");
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),8000);
  try{
   const response=await fetch(SOURCE_URL,{
    credentials:"same-origin",cache:"no-store",signal:controller.signal
   });
   if(response.status===401)throw Error("Требуется авторизация через GitHub.");
   if(response.status===503)throw Error("Снимок недоступен или устарел.");
   if(!response.ok)throw Error("Проверка источника не выполнена.");
   let value;
   try{value=await response.json();}catch(_){throw Error("Некорректный ответ источника.");}
   const checked=parseBrcSourceCheck(value);
   if(!checked)throw Error("Некорректный ответ источника.");
   const number=checked.devices.filter(d=>d.status==="online").length;
   setSourceResult("Источник: проверенный снимок "+checked.snapshot_age_seconds+
    " с назад; устройств онлайн "+number+"/3. Relay, OAuth, команды и Git не проверялись.");
  }catch(error){
   const messages=["Требуется авторизация через GitHub.","Снимок недоступен или устарел.",
    "Некорректный ответ источника."];
   setSourceResult(messages.includes(error.message)?error.message:
    "Не удалось проверить снимок. Повторите запрос после восстановления связи.");
  }finally{clearTimeout(timeout);setSourceBusy(false);}
 };
 const copyPath=async()=>{
  try{
   if(!navigator.clipboard?.writeText)throw Error("clipboard_unavailable");
   await navigator.clipboard.writeText(projectSandboxRoot(current));
   setCopied("Скопировано");
  }catch(_){
   if(codeRef.current){
    const selection=window.getSelection(),range=document.createRange();
    selection?.removeAllRanges();range.selectNodeContents(codeRef.current);selection?.addRange(range);
   }
   setCopied("Путь выделен");
  }
 };
 const copyClientCheck=async()=>{
  try{
   if(!navigator.clipboard?.writeText)throw Error("clipboard_unavailable");
   await navigator.clipboard.writeText(clientCheckRequest(current));
   setClientStatus("Запрос скопирован. Вставьте его в ChatGPT или Codex с подключённым Hermes Agent.");
  }catch(_){
   setClientStatus("Копирование недоступно в браузере. Используйте подключённый Hermes Agent для проверки выбранного проекта.");
  }
 };

 return <section className="oc-page" aria-labelledby="brc-title">
  <header className="oc-intro">
   <div><span className="orbit-section-code">HERMES COMMANDER / WORKSPACE CONTROL</span>
    <h1 id="brc-title">Рабочие пространства</h1>
    <p>Выберите проект и проверьте его доступность в изолированной среде.
      Выполнение команд и доступ к Windows не подразумеваются.</p>
   </div>
   <div className="oc-intro-symbol" aria-hidden="true">
    <img src="/orbit-brand.svg" width="72" height="72" alt=""/>
    <div><strong>HERMES / BRC</strong><span>НАБЛЮДЕНИЕ · ТОЛЬКО ЧТЕНИЕ</span></div>
   </div>
  </header>
  <div className="oc-summary" aria-label="Сводка Hermes BRC">
   <div><span>СОСТОЯНИЕ ИСТОЧНИКА</span><strong id="brc-health">
     {state==="online"?"Hermes BRC · подключён":
      state==="partial"?"Hermes BRC · частичное подключение":"Hermes BRC · статус недоступен"}</strong>
     <small id="brc-time">{live?formatTime(live.observed_at):"Нет проверенного снимка"}</small></div>
   <div><span>УСТРОЙСТВА НА СВЯЗИ</span><strong id="brc-device-count">{live?online+"/3":"—"}</strong>
    <small>Присутствие не подтверждает работу инструментов</small></div>
   <div><span>ПРОЕКТЫ В SANDBOX</span><strong id="brc-project-count">{live?reachable+"/4":"—"}</strong>
    <small>Git и полномочия не проверены</small></div>
   <div><span>РЕЖИМ ДОСТУПА</span><strong className="oc-readonly">READ / ONLY</strong>
    <small>Запуск команд через браузер недоступен</small></div>
  </div>
  <div className="oc-actions">
   <div><span className={"oc-health-led "+(state||"unknown")} aria-hidden="true"/>
    <span>{live?"Получены проверенные метаданные BRC":"Подтверждённого состояния BRC нет"}</span></div>
   <div><button id="brc-refresh" type="button" className="oc-action" onClick={refresh} disabled={busy}>
     <RefreshCw size={15} className={busy?"spin":""} aria-hidden="true"/>{busy?"Обновление…":"Обновить снимок"}</button>
    <button id="brc-check-source" type="button" className="oc-action" onClick={checkSource} disabled={sourceBusy}>
     <ShieldCheck size={15} aria-hidden="true"/>{sourceBusy?"Проверка…":"Проверить источник"}</button>
   </div>
  </div>
  {!live&&<div id="brc-error" className="oc-error" role="alert">
    <ShieldAlert size={19} aria-hidden="true"/>{errorText[fault]||errorText.stale}
  </div>}
  <div className="oc-workgrid">
   <section className="oc-panel oc-project-panel" aria-labelledby="oc-project-title">
    <SectionHead number="01 / КОНТЕКСТ" title="Проекты" sub="Четыре разрешённых sandbox-каталога. Переключение не выдаёт прав."/>
    <label className="oc-search"><Search size={17} aria-hidden="true"/>
      <span className="sr-only">Поиск проекта</span>
      <input type="search" value={query} onChange={e=>setQuery(e.target.value)}
       placeholder="Найти проект…" autoComplete="off"/></label>
    <div id="brc-projects" className="oc-projects" role="group" aria-label="Рабочие пространства">
     {shown.map(p=><button type="button" key={p.repo} data-project={p.repo}
      aria-pressed={p.repo===selected} className={"oc-project"+(p.repo===selected?" selected":"")}
      onClick={()=>{setSelected(p.repo);setCopied("");setClientStatus("Выберите проект для проверки в своём MCP-клиенте.");}}>
      <span className="oc-project-mark"><FolderGit2 size={20} aria-hidden="true"/></span>
      <span><strong>{p.name}</strong><small>{p.branch} · Git не проверен</small></span>
      <ArrowUpRight size={14} aria-hidden="true"/></button>)}
     {!shown.length&&<p className="oc-empty">Проекты по запросу не найдены.</p>}
    </div>
    <div className="oc-panel-foot"><GitBranch size={16} aria-hidden="true"/>
     Известный путь не подтверждает Git HEAD, чистоту репозитория или право записи.</div>
   </section>
   <section className="oc-panel oc-context-panel" aria-labelledby="brc-selected-name">
    <div className="oc-context-head"><div><span className="orbit-section-code">02 / ВЫБРАННЫЙ КОНТЕКСТ</span>
      <h2 id="brc-selected-name">{current.name}</h2><p>{current.caption}</p></div>
      <span id="brc-selected-state" className={"oc-state oc-state-"+(selectedState||"unknown")}>{stateLabel(selectedState)}</span>
    </div>
    <div className="oc-path-title"><FolderGit2 size={18} aria-hidden="true"/> РАЗРЕШЁННЫЙ ПУТЬ В SANDBOX</div>
    <div className="oc-path"><code id="brc-path" ref={codeRef}>{projectSandboxRoot(current)}</code>
     <button id="brc-copy" type="button" onClick={copyPath} aria-label="Скопировать путь sandbox">
       {copied==="Скопировано"?<Check size={18}/>:<Clipboard size={18}/>}
       <span>{copied||"Копировать"}</span></button></div>
    <div className="oc-context-facts brc-facts">
     <div><span>ИЗОЛИРОВАННАЯ СРЕДА</span><strong>Windows sandbox</strong></div>
     <div><span>ВЕТКА (КОНТРАКТ)</span><strong id="brc-branch">{current.branch}</strong></div>
     <div><span>GIT HEAD / CLEAN</span><strong className="oc-unverified">Не проверено</strong></div>
     <div><span>ВЫПОЛНЕНИЕ КОМАНД</span><strong className="oc-unverified">Не подтверждено</strong></div>
    </div>
    <div className="oc-check-guide">
     <div><Workflow size={21} aria-hidden="true"/><div><strong>Безопасный маршрут проверки</strong>
      <p>Подготовьте запрос для подключённого ChatGPT/Codex. Он ничего не запускает из браузера и не открывает Windows-хост.</p></div></div>
     <button id="brc-client-check" type="button" className="oc-primary" onClick={copyClientCheck}>
       <Clipboard size={16} aria-hidden="true"/> Скопировать запрос проверки</button>
     <p id="brc-client-check-status" role="status" aria-live="polite">{clientStatus}</p>
    </div>
   </section>
  </div>
  <div className="oc-bottomgrid">
   <section className="oc-panel" aria-labelledby="oc-device-title">
    <SectionHead number="03 / ПРИСУТСТВИЕ" title="Устройства">
      <span id="brc-devices-label" className="oc-section-info">{live?online+" ONLINE":"Нет данных"}</span>
    </SectionHead>
    <ul id="brc-devices" className="oc-devices" aria-label="Статусы устройств">
     {!live?<li className="oc-empty">Свежие данные устройств недоступны</li>:
      live.devices.map((d,i)=>{
       const Icon=i===0?Monitor:Server;
       const age=d.last_seen_age_seconds+Math.max(0,Math.floor((now-Date.parse(live.observed_at))/1000));
       return <li key={d.name}><span className="oc-device-icon"><Icon size={18} aria-hidden="true"/></span>
        <div><strong>{d.name}</strong><small>Последний сигнал: ~{age} с назад (по снимку)</small></div>
        <Status status={d.status}/></li>;
      })}
    </ul>
   </section>
   <section className="oc-panel oc-access-panel" aria-labelledby="oc-access-title">
    <SectionHead number="04 / ГРАНИЦЫ" title="Полномочия"/>
    <div className="oc-access-list">
     <div><span><Activity size={16} aria-hidden="true"/> Чтение статусов</span><strong id="brc-read-access">{live?"Разрешено":"Не проверено"}</strong></div>
     <div><span><LockKeyhole size={16} aria-hidden="true"/> Выполнение команд</span><strong className="oc-unverified">Не проверено</strong></div>
     <div><span><HardDrive size={16} aria-hidden="true"/> Оригинальный Windows</span><strong className="oc-denied">Закрыт</strong></div>
     <div><span><ShieldCheck size={16} aria-hidden="true"/> Новые проекты</span><strong className="oc-unverified">Не допущено</strong></div>
    </div>
    <p id="brc-diagnostic" className="oc-diagnostic" role="status">{diagnostic}</p>
    <p id="brc-source-result" className="oc-diagnostic" role="status">{sourceResult}</p>
   </section>
  </div>
  <footer className="oc-footer">
   <span>Online не подтверждает выполнение команд или права на файловую систему.</span>
   <div><a href={issue} target="_blank" rel="noopener noreferrer">Контракт BRC <ExternalLink size={14}/></a>
    <a href="/desktop-commander-archive">Архив Desktop Commander <ArrowUpRight size={14}/></a></div>
  </footer>
 </section>;
}
