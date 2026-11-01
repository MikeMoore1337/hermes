import React,{useCallback,useEffect,useMemo,useState} from "react";
import {createRoot} from "react-dom/client";
import {ShieldCheck,LockKeyhole,Activity,RefreshCw,Search,Github,ArrowRight,
  AlertTriangle,Radio,Server,Clock3,Database,ExternalLink,ChevronsRight,ChevronDown,
  CircleHelp,ShieldAlert,Eye,Signal,Check,LogIn,ArrowUpRight,
  LayoutDashboard,Inbox,Layers3,BookOpenText,FilePenLine,Bot,Gauge,Menu,X,ChevronRight} from "lucide-react";
import {groups,statuses,validSnapshot,counts,filterServices} from "./health.js";
import "./style.css";
import {registerPwa} from "./register-pwa.js";
import CodexPanel from "./CodexPanel.jsx";
import OperatorInbox from "./OperatorInbox.jsx";
import YfcArticles from "./YfcArticles.jsx";
import OrbitLogin from "./OrbitLogin.jsx";
import OrbitOverview from "./OrbitOverview.jsx";
import "./orbit-operator.css";

const ISSUE33="https://github.com/MikeMoore1337/hermes/issues/33";
const ISSUE163="https://github.com/MikeMoore1337/hermes/issues/163";
const UI_VERSION="0.3.0";
const nav=["all","inbox","articles","commander","ops","research","qa","agent","codex"];
const navName=key=>key==="commander"?"Hermes Commander":key==="articles"?"Статьи YFC":groups[key].name;
const icons={news:Radio,ops:Activity,alerts:Signal,qa:ShieldCheck,
  research:Search,network:ShieldCheck,agent_bounded:Activity,agent:LockKeyhole};
const formatTime=t=>{const d=new Date(t);return Number.isFinite(d.getTime())?d.toLocaleString("ru-RU",{day:"2-digit",month:"long",hour:"2-digit",minute:"2-digit"}):"нет данных";};

function Brand({large=false}){
 return <div className={"brand"+(large?" brand-large":"")}>
  <img src="/orbit-brand.svg" alt="Фирменная крылатая H - Hermes"/>
  <span className="brand-text"><strong>HERMES</strong><small>COMMAND CENTER</small></span>
 </div>;
}
function InfoBadge({children,tone=""}){return <span className={"badge "+tone}>{children}</span>;}
function State({value}){const p=statuses[value]||statuses.unknown;return <span className={"state state-"+p.tone}><i aria-hidden="true"/>{p.label}</span>;}
const navIcons={all:LayoutDashboard,inbox:Inbox,articles:FilePenLine,commander:Layers3,ops:Activity,research:BookOpenText,qa:ShieldCheck,agent:Bot,codex:Gauge};
function Nav({view,onView,mode}){
 return <nav className="nav-list" aria-label="Разделы управления">
 {nav.filter(key=>key!=="articles"||mode==="github").map((key,i)=>{
  const Icon=navIcons[key]||LayoutDashboard;
  return <button key={key} type="button" className={"nav-link"+(view===key?" is-active":"")} aria-current={view===key?"page":undefined}
   onClick={()=>key==="commander"?window.location.assign("/hermes-brc"):onView(key)}>
   <span className="nav-number" aria-hidden="true">{String(i+1).padStart(2,"0")}</span>
   <span className="orbit-nav-icon"><Icon size={18} strokeWidth={1.65} aria-hidden="true"/></span><span>{navName(key)}</span>
  </button>;
 })}
 </nav>;
}
function Header({view,authMode,onLogout,onMenu,menuOpen}){
 return <header className="orbit-topbar">
   <button type="button" className="orbit-topbar-menu" onClick={onMenu} aria-expanded={menuOpen} aria-label={menuOpen?"Закрыть меню разделов":"Открыть меню разделов"}>
    {menuOpen?<X size={20}/>:<Menu size={20}/>}
   </button>
   <div className="orbit-topbar-breadcrumb"><span>HERMES</span><ChevronRight size={15}/><span>COMMAND CENTER</span><ChevronRight size={15}/><strong>{navName(view)}</strong></div>
   <div className="orbit-topbar-tools">
    <InfoBadge tone="outline"><LockKeyhole size={13} aria-hidden="true"/> {view==="articles"?"Публикация вручную":"Только чтение"}</InfoBadge>
    {authMode==="github"&&<button type="button" className="owner-button" onClick={onLogout}><LogIn size={15} aria-hidden="true"/> Выйти</button>}
   </div>
 </header>;
}
function StatTile({title,value,sub,icon:Icon,tone=""}){
 return <div className={"stat-tile "+tone}>
  <span className="tile-title">{title}</span>
  <div className="tile-content"><strong>{value}</strong><Icon size={27} strokeWidth={1.45} aria-hidden="true"/></div>
  <small>{sub}</small>
 </div>;
}
function Empty({error}){
 return <div className="empty"><ShieldAlert size={30} strokeWidth={1.4} aria-hidden="true"/>
 <h3>{error?"Снимок недоступен":"Загрузка данных"}</h3>
 <p>{error||"Запрашиваем безопасный снимок состояния systemd."}</p>
 </div>;
}
function Registry({snapshot,view,search,setSearch,filter,setFilter}){
 const services=snapshot?.services||[];
 const shown=filterServices(services,view,search,filter);
 return <section className="registry-panel" aria-label="Реестр служб">
  <div className="panel-head registry-head">
   <div><span className="eyebrow">СЛУЖБЫ И КОМПОНЕНТЫ / SYSTEMD</span>
    <h2>{view==="all"?"Реестр служб":groups[view].name}</h2>
    <p>Статусы системных единиц, без прав управления.</p></div>
   <InfoBadge>{services.length} объектов</InfoBadge>
  </div>
  <div className="registry-toolbar">
   <label className="search-field"><Search size={16} aria-hidden="true"/><span className="sr-only">Поиск по службам</span>
    <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Поиск по службам…" autoComplete="off"/></label>
   <label className="status-filter"><span className="sr-only">Фильтр по состоянию</span>
    <select value={filter} onChange={e=>setFilter(e.target.value)}>
     <option value="all">Все статусы</option>{Object.entries(statuses).map(([id,s])=><option key={id} value={id}>{s.label}</option>)}
    </select><ChevronDown size={14} aria-hidden="true"/></label>
  </div>
  <div className="table-scroll"><table className="service-table"><caption className="sr-only">Реестр системных служб и компонентов</caption><thead><tr>
   <th scope="col">Служба / единица</th><th scope="col">Состояние</th>
   <th scope="col">Режим</th><th scope="col">Источник</th>
   </tr></thead><tbody>
   {shown.map(s=>{const Icon=icons[s.id]||Server;return <tr key={s.id} className={s.id==="agent"?"restricted":""}>
    <td><div className="service-cell"><span className="service-icon"><Icon size={17} strokeWidth={1.55}/></span>
     <span className="service-label"><strong>{s.name}</strong><small>{s.unit}</small></span></div></td>
    <td><State value={s.state}/></td><td><span className="read-label">READ</span></td>
    <td><span className="unit-type">{s.kind==="schedule"?"systemd.timer":s.kind==="restricted"?"политика доступа":"systemd.service"}</span></td>
   </tr>})}
   {!shown.length&&<tr><td colSpan={4} className="no-results">{snapshot?"По текущим условиям служб не найдено.":"Нет проверенного снимка."}</td></tr>}
  </tbody></table></div>
  <p className="registry-disclaimer">Активный таймер означает, что он запущен в systemd, но не доказывает успешность последнего задания.</p>
 </section>;
}
function ResearchPanel({research}){
 const reports=research?.curated_reports||[];
 const packets=research?.items||[];
 const availability=research?.availability||"UNAVAILABLE";
 return <section className="registry-panel research-panel" aria-label="Исследования Research Scout">
  <div className="panel-head"><div><span className="eyebrow">H-03 / RESEARCH SCOUT</span>
   <h2>Научные исследования</h2>
   <p>Первоисточники, статус проверок и осторожные обзоры без автопубликации.</p></div>
   <InfoBadge tone="muted">Только чтение</InfoBadge></div>
  <div className="science-overview">
   <div><small>ПОСЛЕДНИЙ СБОР</small><strong>{availability==="AVAILABLE"?(research.status||"UNKNOWN"):"Нет данных"}</strong>
    <span>{research?.observed_at?formatTime(research.observed_at):"Пакет недоступен"}</span></div>
   <div><small>КАНДИДАТЫ</small><strong>{availability==="AVAILABLE"?packets.length:"—"}</strong>
    <span>Метаданные Europe PMC / Crossref</span></div>
   <div><small>РУЧНАЯ НАУЧНАЯ ОЦЕНКА</small><strong>Не завершена</strong>
    <span>Нет подтверждения эксперта</span></div>
  </div>
  <h3 className="science-title">Текущие публикации</h3>
  <p className="science-hint">Отсутствующий DOI в поисковой записи не доказывает, что его нет у статьи. HOLD никогда не означает «проверено».</p>
  {availability==="AVAILABLE"&&packets.length?<div className="science-list">
   {packets.map((item,i)=><div key={item.identifier+"-"+i} className="science-item">
    <div><strong>{item.title}</strong><small>PMID/PMCID {item.identifier} · {item.publication_date||"Дата неизвестна"} · {item.doi||"DOI не получен"}</small></div>
    <div><span className="science-status">{item.status}</span><small>{item.article_notice_state}</small></div>
    <a href={item.source_url} target="_blank" rel="noopener noreferrer" aria-label={"Источник "+item.identifier}><ExternalLink size={17}/></a>
   </div>)}
  </div>:<p className="science-hint">Актуальный локальный пакет недоступен либо новых кандидатов нет.</p>}
  <h3 className="science-title">Разобранные первоисточники</h3>
  <p className="science-hint">Четыре разбора по проверенным публичным рефератам. Это не экспертиза полного текста, не доказательство эффективности и не рекомендации.</p>
  <div className="science-cards">{reports.map(r=><details className="science-card" key={r.pmid}>
   <summary><div><strong>{r.title}</strong><small>{r.journal} · {r.publication_date} · PMID {r.pmid}</small></div>
    <span className="science-status">{r.status==="HOLD"?"HOLD / исправление":"Ручная проверка"}</span><ChevronDown size={17}/></summary>
   <div className="science-detail">
    <p><b>Вопрос:</b> {r.question}</p><p><b>Дизайн:</b> {r.design}</p>
    <p><b>Выборка:</b> {r.sample_size}</p><p><b>Сравнение:</b> {r.comparison}</p>
    <p><b>Главный результат:</b> {r.finding}</p>
    <p><b>Подтверждено публичным рефератом:</b> {r.confirmed}</p>
    <p><b>Не доказано:</b> {r.unconfirmed}</p><p><b>Ограничения:</b> {r.limits}</p>
    <p><b>Практический смысл:</b> {r.application}</p>
    <p><b>Размер эффекта:</b> {r.effect_size}; <b>статистическая неопределённость:</b> {r.statistical_uncertainty}</p>
    <p><b>Исправления:</b> {r.correction_status}</p>
    <p><b>Научная проверка:</b> {r.review_status}; проверено по реферату {r.checked_at}; полный текст не рецензирован.</p>
    <div className="science-links"><a href={r.url} target="_blank" rel="noopener noreferrer">PubMed <ExternalLink size={13}/></a>
     <a href={"https://doi.org/"+r.doi} target="_blank" rel="noopener noreferrer">DOI <ExternalLink size={13}/></a>
     {r.correction_url&&<a href={r.correction_url} target="_blank" rel="noopener noreferrer">Исправление издателя <ExternalLink size={13}/></a>}</div>
    <details><summary className="science-evidence">Подтверждающие факты F1-F8</summary>
     {r.evidence.map(e=><p key={e.id}><b>{e.id}</b>: {e.abstract_paraphrase} <a href={e.url} target="_blank" rel="noopener noreferrer">Источник ↗</a></p>)}
    </details>
   </div>
  </details>)}</div>
 </section>;
}
function SignalPanel({snapshot,error}){
 const problems=(snapshot?.services||[]).filter(s=>["failed","unknown","unexpected_active"].includes(s.state));
 return <aside className="side-stack">
  <section className="right-panel">
   <div className="side-heading"><span className="eyebrow">СИГНАЛЫ И КОНТЕКСТ</span><InfoBadge tone="muted">Из snapshot</InfoBadge></div>
   <div className="signal-list">
    <div className="signal-item"><span className="timeline-point blue"/><div>
     <small>СИСТЕМНЫЙ СНИМОК</small><strong>{snapshot?"Данные получены":"Данные недоступны"}</strong>
     <p>{snapshot?formatTime(snapshot.generated_at):"Нет подтверждённого состояния служб."}</p></div></div>
    {problems.map(s=><div className="signal-item" key={s.id}><span className="timeline-point amber"/><div>
     <small>ТРЕБУЕТ ПРОВЕРКИ</small><strong>{s.name}</strong><p>{statuses[s.state]?.label||"Нет данных"}</p>
    </div></div>)}
    <div className="signal-item"><span className="timeline-point amber"/><div>
     <small>ПОЛИТИКА ДОПУСКА</small><strong>H-01 Ops AI / полный агент</strong><p>{snapshot?.agent_policy||"Нет данных о политике AI Agent."}</p></div></div>
   </div>
   <p className="signal-disclaimer">История инцидентов и доставки уведомлений пока не подключена. События не моделируются.</p>
  </section>
  <section className="right-panel security-panel">
   <div className="side-heading"><span className="eyebrow">ПОЛИТИКА БЕЗОПАСНОСТИ</span><ShieldCheck size={19} aria-hidden="true"/></div>
   <div className="policy-state"><LockKeyhole size={27} aria-hidden="true"/><div><strong>Полный AI Agent не допущен</strong>
    <p>Ограниченный H-01 разрешён отдельно. Активный таймер не доказывает успешность анализа (#33).</p></div></div>
   <dl className="permission-list"><div><dt>Чтение снимка</dt><dd>Разрешено</dd></div><div><dt>Запуск служб</dt><dd className="denied">Запрещён</dd></div>
    <div><dt>Изменение конфигурации</dt><dd className="denied">Недоступно</dd></div><div><dt>Доступ к секретам</dt><dd className="denied">Закрыт</dd></div></dl>
   <a href={ISSUE33} target="_blank" rel="noopener noreferrer" className="policy-link">Условия допуска <ArrowUpRight size={14}/></a>
  </section>
 </aside>;
}
function OperatorApp({authMode,onLogout}){
 const [view,setView]=useState("all");
 const [menuOpen,setMenuOpen]=useState(false);
 const [snapshot,setSnapshot]=useState(null),[error,setError]=useState(""),[busy,setBusy]=useState(false);
 const [search,setSearch]=useState(""),[filter,setFilter]=useState("all");
 const reload=useCallback(async()=>{
  setBusy(true);
  try{
   const res=await fetch("/api/overview",{cache:"no-store",credentials:"same-origin"});
   if(!res.ok)throw new Error("Не удалось получить снимок ("+res.status+").");
   const body=await res.json();
   if(!validSnapshot(body))throw new Error("Снимок устарел или не соответствует безопасному формату.");
   setSnapshot(body);setError("");
  }catch(e){setSnapshot(null);setError(e.message||"Ошибка чтения API.");}
  finally{setBusy(false);}
 },[]);
 useEffect(()=>{
  let live=true,controller=new AbortController();
  const load=async()=>{
   try{const res=await fetch("/api/overview",{cache:"no-store",credentials:"same-origin",signal:controller.signal});
    if(!res.ok)throw Error("Снимок недоступен (HTTP "+res.status+").");
    const data=await res.json();if(!validSnapshot(data))throw Error("Получен устаревший или недостоверный снимок.");
    if(live){setSnapshot(data);setError("");}
   }catch(e){if(live){setSnapshot(null);setError(e.message||"API недоступен.");}}
  };
  load();const id=setInterval(()=>{if(!document.hidden)load();},60000);
  return()=>{live=false;controller.abort();clearInterval(id);};
 },[]);
 const stats=counts(snapshot?.services||[]);
 const now=snapshot?formatTime(snapshot.generated_at):"Нет данных";

 useEffect(()=>{
  if(!menuOpen)return;
  const onEscape=event=>{if(event.key==="Escape"){setMenuOpen(false);document.querySelector(".orbit-topbar-menu")?.focus();}};
  window.addEventListener("keydown",onEscape);
  return ()=>window.removeEventListener("keydown",onEscape);
 },[menuOpen]);
 const onView=key=>{
  setView(key);setMenuOpen(false);
  if(menuOpen)requestAnimationFrame(()=>document.getElementById("main-content")?.focus());
 };
 return <div className="shell theme-orbit">
  <a href="#main-content" className="skip-link">Перейти к основному содержимому</a>
  <div className="orbit-app-layout">
   <aside className={"orbit-rail"+(menuOpen?" is-open":"")} aria-label="Разделы и рабочее пространство">
    <div className="orbit-rail-brand"><Brand/></div>
    <div className="orbit-rail-label"><span>РАБОЧАЯ ПАНЕЛЬ</span><span>01-09</span></div>
    <div className="atlas-section-nav">
     <Nav view={view} mode={authMode} onView={onView}/>
     <div className="orbit-side-refresh">
      <button className="refresh-button" type="button" onClick={reload} disabled={busy}><RefreshCw size={16} className={busy?"spin":""}/> Обновить снимок</button>
     </div>
    </div>
    <div className="orbit-rail-bottom"><span>РАБОЧЕЕ ПРОСТРАНСТВО</span>
     <div className="orbit-workspace-pill"><img src="/orbit-brand.svg" width="38" height="38" alt=""/><div><strong>Hermes</strong><small>Изолированный контур</small></div></div>
     <div className="orbit-rail-foot"><i aria-hidden="true"/> {snapshot?"Снимок получен":"Состояние не проверено"}</div>
    </div>
   </aside>
   <button type="button" aria-label="Закрыть меню" className={"orbit-rail-backdrop"+(menuOpen?" is-open":"")} onClick={()=>setMenuOpen(false)} tabIndex={menuOpen?0:-1}/>
   <div className="orbit-content">
    <Header view={view} authMode={authMode} onLogout={onLogout} onMenu={()=>setMenuOpen(v=>!v)} menuOpen={menuOpen}/>
    <main id="main-content" className="orbit-main" tabIndex={-1}>
     {view==="all"?<><OrbitOverview snapshot={snapshot} error={error} onView={onView} onRefresh={reload} busy={busy} Registry={Registry}
      registryProps={{snapshot,view,search,setSearch,filter,setFilter}}/><section className="orbit-compact-codex" aria-label="Сводка лимитов Codex"><CodexPanel compact/></section></>:
      <div className="orbit-module-shell">
       <h1 className="sr-only">{navName(view)}</h1>
       {view==="articles"?<YfcArticles/>:view==="inbox"?<OperatorInbox/>:
       <>
        {error&&<div className="inline-error" role="alert"><AlertTriangle size={17}/>{error}</div>}
        <div className="operator-grid">
         <div className="center-area">
          {view==="codex"?<CodexPanel/>:<>
           {view==="research"&&<ResearchPanel research={snapshot?.research}/>}
           <Registry snapshot={snapshot} view={view} search={search} setSearch={setSearch} filter={filter} setFilter={setFilter}/>
          </>}
          {view!=="codex"&&<section className="context-panel"><div><span className="eyebrow">ИСТОЧНИК</span><strong>systemd · защищённый снимок</strong>
            <p>Разрешённый список {snapshot?.services?.length??"—"} компонентов, без журналов и токенов.</p></div>
           <div><span className="eyebrow">РЕЖИМ</span><strong>Только чтение</strong><p>Данные обновляются раз в минуту.</p></div>
           <a href={ISSUE163} target="_blank" rel="noopener noreferrer">Задача разработки <ExternalLink size={14}/></a></section>}
         </div>
         <SignalPanel snapshot={snapshot} error={error}/>
        </div>
       </>}
      </div>}
    </main>
    <footer className="footer">HERMES COMMAND CENTER <span>·</span> Состояние systemd, не результат выполнения заданий <span>·</span> <a href={ISSUE33} target="_blank" rel="noopener noreferrer">Политика доступа</a></footer>
   </div>
   <nav className="orbit-app-mobilebar" aria-label="Мобильная навигация">
    {[["all","Обзор",LayoutDashboard],["inbox","Входящие",Inbox],["research","Исследования",BookOpenText],["qa","QA / CI",ShieldCheck]].map(([id,label,Icon])=>
     <button key={id} type="button" aria-current={view===id?"page":undefined} onClick={()=>onView(id)}><Icon size={19} aria-hidden="true"/>{label}</button>)}
    <button type="button" aria-expanded={menuOpen} onClick={()=>setMenuOpen(v=>!v)}><Menu size={19} aria-hidden="true"/>Ещё</button>
   </nav>
  </div>
 </div>;
}

function LoginPreview({onBack,active=false,unavailable=false}){
 return <OrbitLogin onBack={onBack} active={active} unavailable={unavailable}/>;
}
function serverAuthBootstrap(){
 const root=document.getElementById("root");
 const mode=root?.dataset.authMode;
 const authenticated=root?.dataset.authenticated;
 if(!["proxy","github"].includes(mode)||!["true","false"].includes(authenticated))return null;
 return {mode,authenticated:authenticated==="true"};
}
function App(){
 const preview=new URLSearchParams(location.search).get("preview")==="login";
 const [auth,setAuth]=useState(serverAuthBootstrap);
 useEffect(()=>{
  if(serverAuthBootstrap())return;
  let active=true;
  fetch("/api/auth/session",{cache:"no-store",credentials:"same-origin"})
   .then(async response=>{
     if(!response.ok)throw new Error("auth unavailable");
     const body=await response.json();
     if(!["proxy","github"].includes(body.mode)||typeof body.authenticated!=="boolean"){
       throw new Error("bad auth response");
     }
     return body;
   })
   .then(result=>{if(active)setAuth(result);})
   .catch(()=>{if(active)setAuth({mode:"unavailable",authenticated:false});});
  return ()=>{active=false;};
 },[]);
 const logout=useCallback(async()=>{
  try{
   const result=await fetch("/auth/logout",{method:"POST",credentials:"same-origin",
     cache:"no-store",headers:{"Content-Type":"text/plain"}});
   if(result.status===204)window.location.replace("/");
  }catch(_){/* remain on protected screen; expiry will deny future APIs */}
 },[]);
 if(!auth)return <div className="auth-wait" role="status">Проверка доступа к Hermes Control Center…</div>;
 if(auth.mode==="unavailable")return <LoginPreview unavailable/>;
 if(auth.mode==="github"&&!auth.authenticated)return <LoginPreview active/>;
 if(preview)return <LoginPreview onBack={()=>window.location.assign("/")}/>;
 return <OperatorApp authMode={auth.mode} onLogout={logout}/>;
}
createRoot(document.getElementById("root")).render(<App/>);
void registerPwa();
