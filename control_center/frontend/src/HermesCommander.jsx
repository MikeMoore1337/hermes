import React,{useCallback,useEffect,useMemo,useState} from "react";
import {ArrowLeft,AlertTriangle,Check,ChevronRight,Clipboard,ExternalLink,
 FolderGit2,GitBranch,HardDrive,LockKeyhole,Monitor,RefreshCw,Search,
 Server,ShieldCheck,Workflow} from "lucide-react";
import {commanderProjects,commanderDevices,parseBrcObservation,
 projectExpectedOrigin,projectSandboxRoot} from "./commander-model.js";
import "./commander.css";

const tabs=[["overview","Обзор"],["git","Git"],["windows","Windows"]];
const issue="https://github.com/MikeMoore1337/hermes/issues/455";
function State({status}){
 const label={online:"В сети",offline:"Не в сети",paused:"Приостановлено",stale:"Снимок устарел"};
 return <span className={"hc-status hc-status-"+(status||"unknown")}>
  <i aria-hidden="true"/>{label[status]||"Не проверено"}</span>;
}
function Pair({label,children,warn}){
 return <div className="hc-pair"><dt>{label}</dt><dd className={warn?"hc-warn":""}>{children}</dd></div>;
}
export default function HermesCommander({onBack}){
 const [selected,setSelected]=useState("hermes"),[tab,setTab]=useState("overview");
 const [query,setQuery]=useState(""),[observation,setObservation]=useState(null);
 const [fault,setFault]=useState("Снимок BRC пока не подключён.");
 const [busy,setBusy]=useState(false),[copied,setCopied]=useState("");
 const project=commanderProjects.find(p=>p.id===selected)||commanderProjects[1];
 const visible=useMemo(()=>commanderProjects.filter(p=>
   (p.name+" "+p.short+" "+p.repo).toLowerCase().includes(query.trim().toLowerCase())),[query]);
 const reload=useCallback(async(signal)=>{
   setBusy(true);
   try{
     const res=await fetch("/api/providers/hermes-brc",{cache:"no-store",credentials:"same-origin",signal});
     if(!res.ok)throw Error("Снимок недоступен (HTTP "+res.status+").");
     const data=parseBrcObservation(await res.json());
     if(!data)throw Error("Снимок устарел или не соответствует контракту.");
     setObservation(data);setFault("");
   }catch(e){
     if(e.name!=="AbortError"){setObservation(null);setFault(e.message||"Снимок не получен.");}
   }finally{if(!signal?.aborted)setBusy(false);}
 },[]);
 useEffect(()=>{const ctrl=new AbortController();void reload(ctrl.signal);return()=>ctrl.abort();},[reload]);
 const choose=id=>{setSelected(id);setTab("overview");setCopied("");};
 const copy=async(value,key)=>{
   try{await navigator.clipboard.writeText(value);setCopied(key);}
   catch{setCopied("error");}
 };
 const state=name=>observation?.devices?.find(d=>d.name===name)?.status;
 return <div className="hc-root">
  <a href="#hc-main" className="hc-skip">Перейти к выбранному проекту</a>
  <header className="hc-header">
   <div className="hc-brand"><img src="/brand.webp" alt="Hermes"/><span><strong>Hermes Commander</strong><small>CONTROL CENTER / WORKSPACES</small></span></div>
   <div className="hc-crumb">Control Center <ChevronRight size={14}/> <b>Рабочие пространства</b></div>
   <div className="hc-header-actions"><span className="hc-read"><LockKeyhole size={13}/> ТОЛЬКО ЧТЕНИЕ</span>
    <button type="button" onClick={onBack} className="hc-back"><ArrowLeft size={17}/> К панели</button>
   </div>
  </header>
  <div className="hc-layout">
   <aside className="hc-sidebar" aria-label="Проекты и устройства">
    <div className="hc-side-title"><span className="hc-overline">HERMES BRC</span><h2>Проекты <small>04</small></h2></div>
    <label className="hc-search"><Search size={16}/><span className="hc-sr">Поиск проекта</span>
     <input type="search" placeholder="Найти проект…" value={query} onChange={e=>setQuery(e.target.value)} autoComplete="off"/></label>
    <nav className="hc-projects" aria-label="Выбор проекта">
     {visible.map(p=><button key={p.id} type="button" className={"hc-project"+(selected===p.id?" hc-selected":"")}
      aria-current={selected===p.id?"page":undefined} onClick={()=>choose(p.id)}>
      <span className="hc-project-icon"><FolderGit2 size={20}/></span>
      <span className="hc-project-text"><b>{p.name}</b><small><GitBranch size={12}/>{p.branch} · sandbox</small>
       <em>Windows: путь указан, доступ не выдан</em></span></button>)}
     {!visible.length&&<p className="hc-empty">Ничего не найдено</p>}
    </nav>
    <div className="hc-devices">
     <div className="hc-devices-title">Устройства <span>03</span></div>
     <ul>{commanderDevices.map((name,i)=>{
      const Icon=i===0?Monitor:Server;
      return <li key={name}><Icon size={17}/><span>{i===0?"Windows sandbox":i===1?"Hermes VPS sandbox":"YFC VPS sandbox"}</span><State status={state(name)}/></li>;
     })}</ul>
     <p>Online означает присутствие устройства, а не подтверждённое выполнение команды или доступ к Windows.</p>
    </div>
   </aside>
   <main id="hc-main" className="hc-main" tabIndex={-1}>
    <span className="hc-overline hc-blue">РАБОЧАЯ СРЕДА / {project.short.toUpperCase()}</span>
    <div className="hc-heading"><div><h1>{project.name}</h1>
     <p>Один проект, два разных контура доступа. Права на Windows не наследуются.</p></div>
     <button type="button" className="hc-primary" onClick={()=>setTab("git")}><GitBranch size={16}/> Контракт Git <ChevronRight size={16}/></button>
    </div>
    <div className="hc-flags"><span><FolderGit2 size={14}/>{project.repo}</span>
     <span><GitBranch size={14}/>{project.branch} (контракт)</span>
     <span className="hc-flag-warn"><LockKeyhole size={14}/> Windows host: доступ не выдан</span></div>
    <section className="hc-map" aria-labelledby="hc-map-title">
     <div className="hc-map-heading"><div><span className="hc-overline">КОНТУР ДОСТУПА / WORKSPACE MAPPING</span>
      <h2 id="hc-map-title">Где находятся файлы</h2><p>Sandbox-клон и оригинальная Windows-папка — независимые пространства.</p></div>
      <small>02 КОНТУРА</small></div>
     <div className="hc-contexts">
      <article className="hc-context">
       <div className="hc-context-head"><strong><FolderGit2 size={19}/> Sandbox-копия</strong><State status={state(commanderDevices[0])}/></div>
       <small className="hc-field-label">РАБОЧИЙ КАТАЛОГ BRC</small>
       <div className="hc-path"><code>{projectSandboxRoot(project)}</code>
        <button type="button" aria-label="Скопировать путь sandbox" onClick={()=>copy(projectSandboxRoot(project),"sandbox")} title="Скопировать путь">{copied==="sandbox"?<Check size={16}/>:<Clipboard size={16}/>}</button></div>
       <p>Каталог изолированного агента. Перед записью нужны проверка Git и права на операцию.</p>
       <footer>Git статус <strong>Не проверен в текущем сеансе</strong></footer>
      </article>
      <article className="hc-context hc-host">
       <div className="hc-context-head"><strong><HardDrive size={19}/> Оригинал Windows</strong><span className="hc-host-label">НЕ ПОДКЛЮЧЁН</span></div>
       <small className="hc-field-label">УКАЗАННАЯ ПАПКА ВЛАДЕЛЬЦА</small>
       <div className="hc-path"><code>{project.windowsPath}</code>
        <button type="button" aria-label="Скопировать путь Windows" title="Скопировать путь" onClick={()=>copy(project.windowsPath,"windows")}>{copied==="windows"?<Check size={16}/>:<Clipboard size={16}/>}</button></div>
       {project.parentWorkspace&&<p className="hc-parent">Родительский workspace: <code>{project.parentWorkspace}</code></p>}
       <p>Путь известен, но не проверен на устройстве и не предоставляет доступ к Windows.</p>
       <footer>Права <strong>Чтение, запись и исполнение не разрешены</strong></footer>
      </article>
     </div>
    </section>
    <div className="hc-below">
     <section className="hc-details" aria-label="Сведения о проекте">
      <div className="hc-tabs" role="tablist" aria-label="Подробности выбранного проекта">
       {tabs.map(([key,label])=><button key={key} type="button" role="tab" id={"hc-tab-"+key}
        aria-selected={tab===key} aria-controls="hc-tabpanel" tabIndex={tab===key?0:-1} onClick={()=>setTab(key)}>{label}</button>)}
      </div>
      <div className="hc-tabpanel" role="tabpanel" id="hc-tabpanel" aria-labelledby={"hc-tab-"+tab} tabIndex={0}>
       <dl>
       {tab==="overview"&&<>
        <Pair label="Origin (ожидаемый)"><code>{projectExpectedOrigin(project)}</code></Pair>
        <Pair label="Устройство">Windows sandbox · Hermes MCP</Pair>
        <Pair label="Git статус" warn>NOT VERIFIED · Online ≠ разрешение на запись</Pair>
        <Pair label="Хост-доступ" warn>Не включён · отдельное разрешение</Pair>
       </>}
       {tab==="git"&&<>
        <Pair label="Репозиторий"><code>{project.repo}</code></Pair>
        <Pair label="Ветка (контракт)"><code>{project.branch}</code></Pair>
        <Pair label="HEAD / clean tree" warn>NOT VERIFIED · нужен read-only Git-check</Pair>
        <Pair label="Защита">Не менять проект до проверки origin, ветки и статуса.</Pair>
       </>}
       {tab==="windows"&&<>
        <Pair label="Исходная папка"><code>{project.windowsPath}</code></Pair>
        {project.parentWorkspace&&<Pair label="Родительский каталог"><code>{project.parentWorkspace}</code></Pair>}
        <Pair label="Разрешения" warn>Доступ пока не предоставлен.</Pair>
        <Pair label="Ограничения">Приватный vault, другие каталоги и весь диск D: не включены.</Pair>
       </>}
       </dl>
      </div>
     </section>
     <aside className="hc-guide"><span className="hc-overline">БЕЗОПАСНЫЙ МАРШРУТ</span>
      <h2>От выбора проекта до работы</h2>
      <ol><li><b>1</b><span>Найти каталог через <code>resolve_workspace</code></span></li>
       <li><b>2</b><span>Проверить origin, ветку и рабочее дерево</span></li>
       <li><b>3</b><span>Работать только в утверждённом sandbox</span></li></ol>
      <p><ShieldCheck size={16}/> Исходные папки Windows требуют отдельного OS-допуска.</p>
      <a href={issue} target="_blank" rel="noopener noreferrer">Задача #455 <ExternalLink size={14}/></a>
     </aside>
    </div>
    <section className="hc-observe" aria-label="Состояние Hermes BRC"><div>
      <span className="hc-overline">НАБЛЮДЕНИЕ / ТОЛЬКО ЧТЕНИЕ</span>
      <p>{observation?("Снимок от "+new Date(observation.observed_at).toLocaleString("ru-RU")+
      ". Исполнение команд не проверено."):fault}</p></div>
      <button type="button" disabled={busy} onClick={()=>void reload()}><RefreshCw size={16}/> Обновить снимок</button>
    </section>
    {copied==="error"&&<p className="hc-error" role="status">Буфер обмена недоступен. Выделите путь вручную.</p>}
    <p className="hc-notice"><AlertTriangle size={15}/> Git, хост-права и выполнение команд не моделируются по статусу подключения.</p>
   </main>
  </div>
  <nav className="hc-mobilebar" aria-label="Мобильная навигация Commander">
   <button type="button" onClick={()=>document.querySelector(".hc-projects")?.scrollIntoView({block:"nearest"})}><FolderGit2 size={19}/> Проекты</button>
   <button type="button" onClick={()=>document.querySelector(".hc-devices")?.scrollIntoView({block:"nearest"})}><Server size={19}/> Устройства</button>
   <button type="button" onClick={()=>document.querySelector(".hc-observe")?.scrollIntoView({block:"nearest"})}><Workflow size={19}/> Диагностика</button>
  </nav>
 </div>;
}
