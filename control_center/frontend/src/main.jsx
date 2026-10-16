import React,{useCallback,useEffect,useMemo,useState} from "react";
import {createRoot} from "react-dom/client";
import {ShieldCheck,LockKeyhole,Activity,RefreshCw,Search,Github,ArrowRight,
  AlertTriangle,Radio,Server,Clock3,Database,ExternalLink,ChevronsRight,ChevronDown,
  CircleHelp,ShieldAlert,Eye,Signal,Check,LogIn,ArrowUpRight} from "lucide-react";
import {groups,statuses,validSnapshot,counts,filterServices} from "./health.js";
import "./style.css";
import {registerPwa} from "./register-pwa.js";

const ISSUE33="https://github.com/MikeMoore1337/hermes/issues/33";
const ISSUE163="https://github.com/MikeMoore1337/hermes/issues/163";
const UI_VERSION="0.2.0";
const nav=["all","ops","research","qa","agent"];
const icons={news:Radio,ops:Activity,alerts:Signal,qa:ShieldCheck,
  research:Search,network:ShieldCheck,agent:LockKeyhole};
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
 {nav.map((key,i)=><button key={key} type="button" className={"nav-link"+(view===key?" is-active":"")} aria-current={view===key?"page":undefined} onClick={()=>onView(key)}>
   <span className="nav-number">{String(i+1).padStart(2,"0")}</span><span>{groups[key].name}</span>
 </button>)}
 </nav>;
}
function Header({view,setView,authMode,onLogout}){
 return <header className="site-header atlas-header">
   <Brand/>
   <div className="brand-divider" aria-hidden="true"/>
   <span className="header-subtitle">Центр наблюдения и управления <small>AI · АВТОМАТИЗАЦИЯ · КОНТРОЛЬ · БЕЗОПАСНОСТЬ</small></span>
   <div className="atlas-nav" role="navigation" aria-label="Основные разделы">
     {nav.slice(0,4).map(k=><button key={k} className={view===k?"selected":""} onClick={()=>setView(k)}>{groups[k].name}</button>)}
   </div>
   <div className="header-tools">
    <InfoBadge tone="outline"><LockKeyhole size={13}/> Только чтение</InfoBadge>
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
  <div className="table-scroll"><table className="service-table"><thead><tr>
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
     <small>ПОЛИТИКА ДОПУСКА</small><strong>Resident AI Agent: NO-GO</strong><p>Постоянный агент не разрешён к запуску.</p></div></div>
   </div>
   <p className="signal-disclaimer">История инцидентов и доставки уведомлений пока не подключена. События не моделируются.</p>
  </section>
  <section className="right-panel security-panel">
   <div className="side-heading"><span className="eyebrow">ПОЛИТИКА БЕЗОПАСНОСТИ</span><ShieldCheck size={19} aria-hidden="true"/></div>
   <div className="policy-state"><LockKeyhole size={27} aria-hidden="true"/><div><strong>Resident AI Agent заблокирован</strong>
    <p>До прохождения обязательных проверок безопасности (#33).</p></div></div>
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
  <Header view={view} setView={setView} authMode={authMode} onLogout={onLogout}/>
  <div className="body-layout">
   <main className="dashboard-main">
    <section className="atlas-hero"><div className="eyebrow">ОПЕРАЦИОННЫЙ КОНТУР H-15</div>
       <h1>Система. Под наблюдением.</h1><p>Инвентаризация, контроль состояния и изоляция компонентов.
       <br/>Только проверенные данные systemd.</p>
       <div className="hero-meta">HERMES CONTROL CENTER / H-15 <span>РЕЖИМ: ТОЛЬКО ЧТЕНИЕ</span></div>
    </section>
    <section className="stats-bar" aria-label="Показатели">
     <StatTile title="АКТИВНЫЕ СЛУЖБЫ" value={snapshot?stats.active+" / "+stats.total:"—"} sub="Активные системные единицы" icon={Server}/>
     <StatTile title="ТРЕБУЮТ ВНИМАНИЯ" value={snapshot?String(stats.attention).padStart(2,"0"):"—"} sub="Сбой или неизвестное состояние" icon={AlertTriangle} tone="warn"/>
     <StatTile title="ПОСЛЕДНИЙ СНИМОК" value={snapshot?"Получен":"Нет данных"} sub={now} icon={Database}/>
     <StatTile title="РЕЖИМ ДОСТУПА" value="Только чтение" sub="Команды управления отключены" icon={LockKeyhole}/>
    </section>
    <div className="atlas-section-nav"><Nav view={view} onView={setView}/><button className="refresh-button" onClick={reload} disabled={busy}><RefreshCw size={15} className={busy?"spin":""}/> Обновить</button></div>
    {error&&<div className="inline-error" role="alert"><AlertTriangle size={17}/>{error}</div>}
    <div className="operator-grid">
     <div className="center-area"><Registry snapshot={snapshot} view={view} search={search} setSearch={setSearch} filter={filter} setFilter={setFilter}/>
      <section className="context-panel"><div><span className="eyebrow">ИСТОЧНИК</span><strong>systemd · защищённый снимок</strong><p>Разрешённый список 7 компонентов, без приватных журналов и токенов.</p></div>
       <div><span className="eyebrow">РЕЖИМ</span><strong>Read-only</strong><p>Обновление интерфейса раз в минуту.</p></div>
       <a href={ISSUE163} target="_blank" rel="noopener noreferrer">Задача разработки <ExternalLink size={14}/></a></section>
     </div>
     <SignalPanel snapshot={snapshot} error={error}/>
    </div>
   </main>
  </div>
  <footer className="footer">HERMES CONTROL CENTER <span>•</span> Сведения о systemd, не о результатах задач <span>•</span> <a href={ISSUE33} target="_blank" rel="noopener noreferrer">Политика допуска</a></footer>
 </div>;
}
function LoginPreview({onBack,active=false,unavailable=false}){
 return <div className="login-root">
  <header className="login-header"><Brand/><span>ОПЕРАЦИОННЫЙ КОНТУР H-15</span></header>
  <main className="login-content">
   <section className="login-story">
    <img src="/brand.webp" alt="Эмблема Hermes Agent: крылатая H" className="login-hero-mark"/>
    <p className="login-overline">H E R M E S &nbsp; / &nbsp; C O N T R O L &nbsp; C E N T E R</p>
    <h1>Безопасный доступ<br/>к мониторингу и управлению.</h1>
    <p>Единая система контроля, наблюдения и защиты.<br/>Для владельца. Конфиденциально.</p>
    <blockquote>«Наблюдение, контроль, уверенность.»</blockquote>
   </section>
   <section className="login-form" aria-label={active?"Вход через GitHub":"Предпросмотр экрана входа"}>
    <InfoBadge tone="outline">{active?"GITHUB OAUTH · ТОЛЬКО ВЛАДЕЛЕЦ":unavailable?"ВХОД НЕДОСТУПЕН":"ПРЕДПРОСМОТР · OAuth не включён"}</InfoBadge>
    <h2>Вход в систему</h2><p className="login-form-subtitle">Для доступа к Hermes Control Center потребуется подтверждение владельца через GitHub.</p>
    {active?<a className="github-action" href="/auth/github/start"><Github size={24}/> Войти через GitHub <ArrowRight size={19}/></a>:<button type="button" className="github-action" disabled><Github size={24}/> Войти через GitHub <ArrowRight size={19}/></button>}
    <p className="login-notice">{active?"Доступ предоставляется только разрешённому GitHub ID. Никаких прав записи.":unavailable?"Проверка состояния авторизации не удалась. Доступ закрыт.":"Авторизация пока не подключена. Действующая панель защищена Basic Auth."}</p>
    <div className="login-features"><span><LockKeyhole size={20}/> Только владелец</span><span><ShieldCheck size={20}/> Защищённый сеанс</span><span><Eye size={20}/> Только чтение</span></div>
    <div className="login-policy"><LockKeyhole size={22}/><div><strong>Resident AI Agent: NO-GO</strong><p>Запуск не разрешён до прохождения проверки безопасности.</p></div></div>
    {!active&&!unavailable&&<button className="back-dashboard" type="button" onClick={onBack}>← Вернуться к предварительному просмотру дашборда</button>}
   </section>
  </main>
  <footer className="login-footer">HERMES CONTROL CENTER · Только для владельца <a target="_blank" rel="noopener noreferrer" href={ISSUE33}>Политика доступа ↗</a></footer>
 </div>;
}
function App(){
 const preview=new URLSearchParams(location.search).get("preview")==="login";
 const [auth,setAuth]=useState(null);
 useEffect(()=>{
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
   if(result.status===204)setAuth({mode:"github",authenticated:false});
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
