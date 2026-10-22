import React,{useCallback,useEffect,useMemo,useState} from "react";
import {AlertCircle,AlertTriangle,Ban,CheckCircle2,ChevronRight,Clock3,
  Database,ExternalLink,Inbox,RefreshCw,Search,ShieldCheck,Signal} from "lucide-react";
import "./operator-inbox.css";

const filters=[
 {id:"all",label:"Все"},
 {id:"failure",label:"Сбой"},
 {id:"needs_review",label:"Проверить"},
 {id:"blocked",label:"Заблокировано"},
 {id:"in_progress",label:"Выполняется"}
];
const coverageLabels={
 SUPPORTED:"Подтверждён",PARTIAL:"Частично",STALE:"Устарел",NOT_AVAILABLE:"Нет данных"
};
const groupLabels={failure:"Сбой",needs_review:"Нужна проверка",blocked:"Заблокировано",in_progress:"Выполняется"};
const safeEvidence=new Set(["/api/overview","/api/codex/tasks"]);
const timeString=(v)=>{if(!v)return "Время не подтверждено";const t=Date.parse(v);
 return Number.isFinite(t)?new Date(t).toLocaleString("ru-RU",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}):"Время не подтверждено";};
function validInbox(data){
 return !!data&&data.schema===1&&data.mode==="read_only"&&data.actions_enabled===false&&
  data.completeness==="PARTIAL"&&Array.isArray(data.events)&&data.events.length<=24&&
  data.summary&&typeof data.summary.total==="number"&&
  data.sources&&typeof data.sources==="object"&&
  Object.values(data.sources).every(s=>s&&coverageLabels[s.status]&&typeof s.label==="string")&&
  data.events.every(e=>e&&typeof e.event_id==="string"&&typeof e.title==="string"&&
    typeof e.detail==="string"&&typeof e.action_hint==="string"&&
    ["critical","warning","info"].includes(e.severity)&&
    groupLabels[e.category]&&typeof e.status==="string"&&
    (e.evidence_link===null||safeEvidence.has(e.evidence_link)));
}
function Metric({name,value,subtitle,tone="normal",Icon}){
 return <div className={"oi-metric oi-metric-"+tone}>
  <div className="oi-metric-label"><span>{name}</span><Icon size={19} aria-hidden="true"/></div>
  <strong>{value}</strong><small>{subtitle}</small>
 </div>;
}
function InboxPanel({event}){
 if(!event)return <div className="oi-detail-empty"><Signal size={22} aria-hidden="true"/><p>Выберите событие, чтобы изучить основание и подсказку.</p></div>;
 return <section className="oi-detail" aria-label="Подробности выбранного события">
  <span className="oi-overline">СВЕДЕНИЯ ОБ ОБНАРУЖЕНИИ</span>
  <h3>{event.title}</h3>
  <span className={"oi-state oi-state-"+event.severity}>{groupLabels[event.category]}</span>
  <p>{event.detail}</p>
  <dl>
   <div><dt>Источник</dt><dd>{event.source}</dd></div>
   <div><dt>Зафиксировано</dt><dd>{timeString(event.observed_at)}</dd></div>
   <div><dt>Последняя проверка</dt><dd>{timeString(event.last_verified_at)}</dd></div>
   <div><dt>Область доступа</dt><dd>Только владелец · чтение</dd></div>
  </dl>
  <div className="oi-action-hint"><strong>Что проверить</strong><p>{event.action_hint}</p></div>
  {event.evidence_link&&<a className="oi-evidence" href={event.evidence_link} target="_blank" rel="noopener noreferrer">
    Открыть исходные сведения <ExternalLink size={15} aria-hidden="true"/></a>}
  <div className="oi-readonly"><ShieldCheck size={15} aria-hidden="true"/> Просмотр ничего не запускает</div>
 </section>;
}
export default function OperatorInbox(){
 const [response,setResponse]=useState(null);
 const [phase,setPhase]=useState("loading");
 const [filter,setFilter]=useState("all");
 const [query,setQuery]=useState("");
 const [selected,setSelected]=useState(null);
 const [nonce,setNonce]=useState(0);
 const reload=useCallback(()=>setNonce(v=>v+1),[]);
 useEffect(()=>{
  const controller=new AbortController();let alive=true;
  async function load(){
   if(!alive)return;
   setPhase("loading");
   try{
    const res=await fetch("/api/operator/inbox",{credentials:"same-origin",cache:"no-store",signal:controller.signal});
    if(!res.ok)throw Error("Сведения Operator Inbox недоступны.");
    const result=await res.json();
    if(!validInbox(result))throw Error("Некорректный или неполный ответ Operator Inbox.");
    if(alive){setResponse(result);setPhase("ready");}
   }catch(e){if(alive&&!controller.signal.aborted){setResponse(null);setPhase("error");}}
  }
  load();
  const interval=setInterval(()=>{if(!document.hidden)load();},60000);
  return()=>{alive=false;controller.abort();clearInterval(interval);};
 },[nonce]);
 const events=response?.events||[];
 const shown=useMemo(()=>events.filter(e=>
  (filter==="all"||e.category===filter)&&
  (!query.trim()||[e.title,e.detail,e.source].join(" ").toLocaleLowerCase("ru")
      .includes(query.trim().toLocaleLowerCase("ru")))
 ),[events,filter,query]);
 const current=shown.find(e=>e.event_id===selected)||shown[0]||null;
 const coverage=Object.entries(response?.sources||{});
 const hasMissing=coverage.some(([,v])=>v.status!=="SUPPORTED");
 return <section className="oi-root" aria-label="Operator Inbox">
  <header className="oi-header">
   <div><span className="oi-overline">HERMES / ОПЕРАТОРСКОЕ ВНИМАНИЕ / #468</span>
    <h1><Inbox size={28} aria-hidden="true"/> Operator Inbox</h1>
    <p>Очередь подтверждённых сигналов и неполных проверок. Все действия — только чтение.</p>
   </div>
   <button type="button" className="oi-refresh" onClick={reload} disabled={phase==="loading"}>
    <RefreshCw size={16} aria-hidden="true"/> Обновить</button>
  </header>
  {phase==="loading"&&<div className="oi-placeholder" role="status">
    <Clock3 size={21} aria-hidden="true"/><strong>Получение сведений…</strong>
    <p>Обновляем только доступные источники. Предыдущее состояние не считается подтверждённым.</p></div>}
  {phase==="error"&&<div className="oi-placeholder oi-error" role="alert">
    <AlertCircle size={23} aria-hidden="true"/><strong>Не удалось загрузить очередь</strong>
    <p>Нет подтверждённой сводки. Повторите чтение; автоматических действий не было.</p>
    <button type="button" onClick={reload}>Повторить проверку</button></div>}
  {phase==="ready"&&<>
   <div className="oi-metrics" role="region" aria-label="Общая сводка">
    <Metric name="ВСЕГО СИГНАЛОВ" value={response.summary.total} subtitle="В доступных источниках" Icon={Inbox}/>
    <Metric name="КРИТИЧЕСКИЕ" value={response.summary.critical} subtitle="Требуют приоритетной проверки" tone="danger" Icon={AlertTriangle}/>
    <Metric name="ПРОВЕРИТЬ" value={response.summary.review} subtitle="Нет подтверждения нормы" tone="warn" Icon={Clock3}/>
    <Metric name="ИСТОЧНИКИ" value={response.summary.available_sources+" / "+response.summary.source_count}
      subtitle="Поддерживаются полностью или частично" tone="blue" Icon={Database}/>
   </div>
   {hasMissing&&<div className="oi-notice" role="status"><AlertCircle size={16} aria-hidden="true"/>
    Не все источники подключены или актуальны. Нулевая очередь не гарантирует отсутствие неисправностей.</div>}
   <div className="oi-body">
    <div className="oi-queue">
     <div className="oi-queue-head"><div><span className="oi-overline">РАБОЧАЯ ОЧЕРЕДЬ</span><h2>События и проверки</h2></div>
      <span className="oi-queue-count">{shown.length} из {events.length}</span></div>
     <div className="oi-filters" role="group" aria-label="Категории событий">
      {filters.map(f=><button key={f.id} type="button" aria-pressed={filter===f.id}
       className={filter===f.id?"is-active":""} onClick={()=>{setFilter(f.id);setSelected(null);}}>{f.label}</button>)}
     </div>
     <label className="oi-search"><Search size={16} aria-hidden="true"/>
      <span className="sr-only">Поиск событий</span>
      <input aria-label="Поиск событий" value={query} onChange={e=>{setQuery(e.target.value);setSelected(null);}} placeholder="Название или источник"/></label>
     {shown.length===0?<div className="oi-queue-empty" role="status">
       <CheckCircle2 size={29} aria-hidden="true"/>
       <strong>{events.length===0?"Нет подтверждённых сигналов":"Нет событий по фильтру"}</strong>
       <p>{events.length===0?"Охват неполный: проверьте доступность источников справа.":"Измените фильтр или поиск, чтобы увидеть другие записи."}</p>
      </div>:<div className="oi-list">
      {shown.map(e=><button type="button" key={e.event_id} className={"oi-row oi-row-"+e.severity+(current?.event_id===e.event_id?" is-selected":"")}
        aria-pressed={current?.event_id===e.event_id} onClick={()=>setSelected(e.event_id)}>
       <span className="oi-row-mark" aria-hidden="true">{e.severity==="critical"?<AlertCircle size={18}/>:e.category==="blocked"?<Ban size={18}/>:<AlertTriangle size={18}/>}</span>
       <span className="oi-row-copy"><span className="oi-row-status">{groupLabels[e.category]} · {e.source}</span>
        <strong>{e.title}</strong><small>{e.detail}</small></span>
       <span className="oi-row-time">{timeString(e.observed_at)}</span><ChevronRight size={16} aria-hidden="true"/>
      </button>)}
      </div>}
     <p className="oi-disclaimer">Данные не равны подтверждению успешной работы агентов. Сигналы дедуплицированы по источнику и идентификатору.</p>
    </div>
    <aside className="oi-aside" aria-label="Источники и сведения">
     <section className="oi-sources" aria-label="Доступность источников">
      <span className="oi-overline">ПОЛНОТА НАБЛЮДЕНИЯ</span><h2>Источники данных</h2>
      <ul>{coverage.map(([id,s])=><li key={id}>
        <div><strong>{s.label}</strong><small>{s.details}</small></div>
        <span className={"oi-source-status oi-source-"+s.status.toLowerCase()}>{coverageLabels[s.status]}</span>
      </li>)}</ul>
     </section>
     <InboxPanel event={current}/>
    </aside>
   </div>
  </>}
 </section>;
}
