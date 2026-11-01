import React,{useCallback,useEffect,useMemo,useState} from "react";
import {createRoot} from "react-dom/client";
import {ShieldCheck,LockKeyhole,Activity,RefreshCw,Search,Github,ArrowRight,
  AlertTriangle,Radio,Server,Clock3,Database,ExternalLink,ChevronsRight,ChevronDown,
  CircleHelp,ShieldAlert,Eye,Signal,Check,LogIn,ArrowUpRight} from "lucide-react";
import {groups,statuses,validSnapshot,counts,filterServices} from "./health.js";
import "./style.css";
import {registerPwa} from "./register-pwa.js";
import CodexPanel from "./CodexPanel.jsx";
import OperatorInbox from "./OperatorInbox.jsx";
import YfcArticles from "./YfcArticles.jsx";
import OrbitLogin from "./OrbitLogin.jsx";

const ISSUE33="https://github.com/MikeMoore1337/hermes/issues/33";
const ISSUE163="https://github.com/MikeMoore1337/hermes/issues/163";
const UI_VERSION="0.2.0";
const nav=["all","inbox","articles","commander","ops","research","qa","agent","codex"];
const navName=key=>key==="commander"?"Hermes Commander":key==="articles"?"Статьи YFC":groups[key].name;
const icons={news:Radio,ops:Activity,alerts:Signal,qa:ShieldCheck,
  research:Search,network:ShieldCheck,agent_bounded:Activity,agent:LockKeyhole};
const formatTime=t=>{const d=new Date(t);return Number.isFinite(d.getTime())?d.toLocaleString("ru-RU",{day:"2-digit",month:"long",hour:"2-digit",minute:"2-digit"}):"нет данных";};

function Brand({large=false}){
 return <div className={"brand"+(large?" brand-large":"")}>
  <img src="/brand.webp" alt="Крылатая H — фирменный знак Hermes Agent"/>
  <span className="brand-text"><strong>HERMES</strong><small>CONTROL CENTER</small></span>
 </div>;
}
function InfoBadge({children,tone=""}){return <span className={"badge "+tone}>{children}</span>;}
function State({value}){const p=statuses[value]||statuses.unknown;return <span className={"state state-"+p.tone}><i aria-hidden="true"/>{p.label}</span>;}
function Nav({view,onView,mode}){
 return <nav className="nav-list" aria-label="Разделы управления">
 {nav.filter(key=>key!=="articles"||mode==="github").map((key,i)=><button key={key} type="button" className={"nav-link"+(view===key?" is-active":"")} aria-current={view===key?"page":undefined} onClick={()=>key==="commander"?window.location.assign("/hermes-brc"):onView(key)}>
   <span className="nav-number">{String(i+1).padStart(2,"0")}</span><span>{navName(key)}</span>
 </button>)}
 </nav>;
}
function Header({view,setView,authMode,onLogout}){
 return <header className="site-header atlas-header">
   <Brand/>
   <div className="brand-divider" aria-hidden="true"/>
   <span className="header-subtitle">Центр наблюдения и управления <small>AI · АВТОМАТИЗАЦИЯ · КОНТРОЛЬ · БЕЗОПАСНОСТЬ</small></span>
   <div className="atlas-nav" role="navigation" aria-label="Основные разделы">
     {["all","inbox","articles","ops","research","qa","commander"].filter(k=>k!=="articles"||authMode==="github").map(k=><button key={k} type="button" className={view===k?"selected":""} aria-current={view===k?"page":undefined} onClick={()=>k==="commander"?window.location.assign("/hermes-brc"):setView(k)}>{navName(k)}</button>)}
   </div>
   <div className="header-tools">
    <InfoBadge tone="outline"><LockKeyhole size={13}/> {view==="articles"?"Публикация только вручную":"Только чтение"}</InfoBadge>
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
 return <div className="shell theme-atlas">
  <a href="#main-content" className="skip-link">Перейти к основному содержимому</a>
  <Header view={view} setView={setView} authMode={authMode} onLogout={onLogout}/>
  <div className="body-layout">
   <main id="main-content" tabIndex={-1} className="dashboard-main">
    {view!=="inbox"&&view!=="articles"&&<><section className="atlas-hero"><div className="eyebrow">ОПЕРАЦИОННЫЙ КОНТУР H-15</div>
       <h1>Система. Под наблюдением.</h1><p>Инвентаризация, контроль состояния и изоляция компонентов.
       <br/>Только проверенные данные systemd.</p>
       <div className="hero-meta">HERMES CONTROL CENTER / H-15 <span>РЕЖИМ: ТОЛЬКО ЧТЕНИЕ</span></div>
    </section>
    <section className="stats-bar" aria-label="Показатели">
     <StatTile title="АКТИВНЫЕ ЕДИНИЦЫ" value={snapshot?stats.active+" / "+stats.total:"—"} sub="Активные системные единицы" icon={Server}/>
     <StatTile title="ТРЕБУЮТ ВНИМАНИЯ" value={snapshot?String(stats.attention).padStart(2,"0"):"—"} sub="Сбой или неизвестное состояние" icon={AlertTriangle} tone="warn"/>
     <StatTile title="ПОСЛЕДНИЙ СНИМОК" value={snapshot?"Получен":"Нет данных"} sub={now} icon={Database}/>
     <StatTile title="РЕЖИМ ДОСТУПА" value="Только чтение" sub="Команды управления отключены" icon={LockKeyhole}/>
    </section>
    </>}
    <div className="atlas-section-nav"><Nav view={view} mode={authMode} onView={setView}/>{view!=="articles"&&<button className="refresh-button" onClick={reload} disabled={busy}><RefreshCw size={15} className={busy?"spin":""}/> Обновить</button>}</div>
    {view!=="inbox"&&view!=="articles"&&error&&<div className="inline-error" role="alert"><AlertTriangle size={17}/>{error}</div>}
    {view==="articles"?<YfcArticles/>:view==="inbox"?<OperatorInbox/>:<div className="operator-grid">
     <div className="center-area">{view==="codex"?<CodexPanel/>:<>{view==="research"&&<ResearchPanel research={snapshot?.research}/>}<Registry snapshot={snapshot} view={view} search={search} setSearch={setSearch} filter={filter} setFilter={setFilter}/>{view==="all"&&<CodexPanel compact/>}</>}
      {view!=="codex"&&<section className="context-panel"><div><span className="eyebrow">ИСТОЧНИК</span><strong>systemd · защищённый снимок</strong><p>Разрешённый список {snapshot?.services?.length||"—"} компонентов, без приватных журналов и токенов.</p></div>
       <div><span className="eyebrow">РЕЖИМ</span><strong>Read-only</strong><p>Обновление интерфейса раз в минуту.</p></div>
       <a href={ISSUE163} target="_blank" rel="noopener noreferrer">Задача разработки <ExternalLink size={14}/></a></section>}
     </div>
     <SignalPanel snapshot={snapshot} error={error}/>
    </div>}
   </main>
  </div>
  <footer className="footer">HERMES CONTROL CENTER <span>•</span> Сведения о systemd, не о результатах задач <span>•</span> <a href={ISSUE33} target="_blank" rel="noopener noreferrer">Политика допуска</a></footer>
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
