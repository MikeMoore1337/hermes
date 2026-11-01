import React,{useState} from "react";
import {ArrowUpRight,ChevronRight,LockKeyhole,Pause,Play,ShieldCheck,Activity,Search,GitBranch} from "lucide-react";
import {statuses,counts} from "./health.js";
import "./orbit-operator.css";

const topology=[
 {id:"news",label:"Новости YFC",kind:"ИСТОЧНИКИ",position:"one",scope:"Мониторинг расписания",destination:"ops"},
 {id:"ops",label:"Ops Watch",kind:"НАБЛЮДЕНИЕ",position:"two",scope:"Состояние наблюдателя",destination:"ops"},
 {id:"qa",label:"QA Advisor",kind:"КАЧЕСТВО",position:"three",scope:"Проверки и отчёты",destination:"qa"},
 {id:"research",label:"Research Scout",kind:"ИССЛЕДОВАНИЯ",position:"four",scope:"Научные источники",destination:"research"},
 {id:"agent",label:"Полный AI Agent",kind:"ПОЛИТИКА",position:"five",scope:"Ограничения доступа",destination:"agent"}
];
const actionable=new Set(["failed","unknown","unexpected_active"]);
const stateLabel=value=>statuses[value]?.label||"Нет данных";
const tone=value=>statuses[value]?.tone||"unknown";
function ClockLabel({value}) {
 const d=Date.parse(value||"");
 return <time dateTime={value||undefined}>{Number.isFinite(d)?new Date(d).toLocaleString("ru-RU",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"}):"Нет данных"}</time>;
}
function WireMap({flowing}) {
 return <svg className={"orbit-graph-wires"+(flowing?" is-flowing":"")} viewBox="0 0 1000 450" preserveAspectRatio="none" aria-hidden="true">
  <path className="orbit-wire" d="M274 124C355 124 319 194 395 194M274 338C354 338 324 263 395 263M608 194C690 194 665 126 736 126M608 223H736M608 263C688 263 662 337 736 337"/>
  <path className="orbit-wire-glow" d="M274 124C355 124 319 194 395 194M274 338C354 338 324 263 395 263M608 194C690 194 665 126 736 126M608 223H736M608 263C688 263 662 337 736 337"/>
 </svg>;
}
function Node({value,service,selected,onSelect}) {
 const id=value.id;
 const displayState=service?.state;
 return <button type="button" className={"orbit-topology-node node-"+value.position+(selected?" is-selected":"")} onClick={()=>onSelect(id)} aria-pressed={selected}>
  <span className="orbit-node-category">{value.kind}<span>{value.position==="one"?"01":value.position==="two"?"02":value.position==="three"?"03":value.position==="four"?"04":"05"}</span></span>
  <span className="orbit-node-title">{value.label}<ChevronRight size={15} aria-hidden="true"/></span>
  <span className={"orbit-node-status tone-"+tone(displayState)}><i aria-hidden="true"/>{service?stateLabel(displayState):"Нет подтверждённого снимка"}</span>
 </button>;
}
function CoreNode({selected,onSelect}){
 return <button type="button" className={"orbit-core-node"+(selected?" is-selected":"")} onClick={()=>onSelect("core")} aria-label="Центральная схема Hermes, не исполняющий агент" aria-pressed={selected}>
  <span className="orbit-core-corner lt"/><span className="orbit-core-corner rt"/><span className="orbit-core-corner lb"/><span className="orbit-core-corner rb"/>
  <span className="orbit-core-pre">H / 00 · VISUAL ROUTER</span>
  <img src="/orbit-brand.svg" alt="" width="102" height="102" aria-hidden="true"/>
  <span className="orbit-core-heading">HERMES <b>CORE</b></span>
  <span className="orbit-core-context">СХЕМА НАБЛЮДЕНИЯ / НЕ АГЕНТ</span>
 </button>;
}
export default function OrbitOverview({snapshot,error,onView,onRefresh,busy,Registry,registryProps}){
 const [selected,setSelected]=useState("core");
 const [moving,setMoving]=useState(true);
 const services=snapshot?.services||[];
 const stats=counts(services);
 const find=id=>services.find(s=>s.id===id);
 const selectedMeta=topology.find(x=>x.id===selected);
 const selectedService=selectedMeta?find(selectedMeta.id):null;
 const attention=services.filter(s=>actionable.has(s.state));
 const statusInfo=selected==="core"?
   {title:"Hermes Core",text:"Схематическое представление наблюдаемых источников. Реальный агент и выполнение команд здесь не включаются.",state:"Не является телеметрией"}:
   {title:selectedMeta.label,
    text:selectedService?selectedService.name+" · "+selectedService.unit+" · "+stateLabel(selectedService.state)+". Источник: защищённый снимок systemd.": "Для этого узла нет подтверждённых данных в текущем снимке.",
    state:selectedService?stateLabel(selectedService.state):"Не проверено"};
 return <div className="orbit-overview">
  <section className="orbit-page-intro">
   <div className="orbit-intro-copy">
    <span className="orbit-intro-kicker"><i aria-hidden="true"/> HERMES / СИСТЕМНЫЙ ОБЗОР</span>
    <h1>Вся система.<span>В одном поле зрения.</span></h1>
    <p>Состояние компонентов и сигналы, требующие внимания. Данные берутся из разрешённого снимка, без запуска команд.</p>
   </div>
   <div className="orbit-intro-identity">
    <img src="/orbit-brand.svg" alt="" width="68" height="68"/><div><span>ORBIT / 3.0</span><strong>COMMAND<br/>INTELLIGENCE</strong><small>Hermes Control Center</small></div>
   </div>
  </section>
  <section className="orbit-stats" aria-label="Общие показатели">
   <div><span>ИСТОЧНИК ДАННЫХ</span><strong>{snapshot?"SYSTEMD SNAPSHOT":"НЕТ ДАННЫХ"}</strong><small>{snapshot?<ClockLabel value={snapshot.generated_at}/>:error||"Снимок не получен"}</small></div>
   <div><span>АКТИВНЫЕ ЕДИНИЦЫ</span><strong>{snapshot?String(stats.active).padStart(2,"0"):"—"}<small> / {snapshot?stats.total:"—"}</small></strong><small>Активные службы и таймеры</small></div>
   <div className={attention.length?"has-attention":""}><span>ТРЕБУЮТ ПРОВЕРКИ</span><strong>{snapshot?String(stats.attention).padStart(2,"0"):"—"}</strong><small>Сбой / неизвестное состояние</small></div>
   <div><span>РЕЖИМ ДОСТУПА</span><strong className="orbit-readonly">READ <small>/ ONLY</small></strong><small>Команды управления недоступны</small></div>
  </section>
  {error&&<div className="orbit-alert" role="alert">{error}</div>}
  <div className="orbit-main-grid">
   <section className="orbit-topology" aria-labelledby="orbit-topology-title">
    <div className="orbit-panel-head">
     <div><span className="orbit-section-code">01 / СИСТЕМНАЯ СХЕМА</span><h2 id="orbit-topology-title">Архитектура потоков</h2><p>Выберите узел, чтобы посмотреть подтверждённое состояние.</p></div>
     <div className="orbit-panel-controls">
      <button type="button" className="orbit-small-button" onClick={()=>setMoving(x=>!x)} aria-pressed={!moving}>
       {moving?<Pause size={14} aria-hidden="true"/>:<Play size={14} aria-hidden="true"/>}{moving?"Остановить":"Включить"}
      </button>
     </div>
    </div>
    <div className={"orbit-graph"+(moving?"":" motion-paused")}>
      <span className="orbit-graph-label one">ИСТОЧНИКИ / INGEST</span>
      <span className="orbit-graph-label two">HERMES / СХЕМА</span>
      <span className="orbit-graph-label three">СЛУЖБЫ / STATUS</span>
      <WireMap flowing={moving}/>
      {topology.map(t=><Node key={t.id} value={t} service={find(t.id)} selected={selected===t.id} onSelect={setSelected}/>)}
      <CoreNode selected={selected==="core"} onSelect={setSelected}/>
      <span className="orbit-graph-watermark">TOPOLOGY / VERIFIED STATES ONLY</span>
    </div>
    <div className="orbit-graph-detail">
     <div className="orbit-detail-symbol"><img src="/orbit-brand.svg" width="28" height="28" alt=""/></div>
     <div><span>ВЫБРАННЫЙ УЗЕЛ / {statusInfo.state}</span><strong>{statusInfo.title}</strong><p>{statusInfo.text}</p></div>
     {selectedMeta&&<button type="button" onClick={()=>onView(selectedMeta.destination)} aria-label={"Открыть раздел "+selectedMeta.destination}><ArrowUpRight size={18}/></button>}
    </div>
   </section>
   <aside className="orbit-attention" aria-labelledby="orbit-attention-title">
    <div className="orbit-attention-head"><span className="orbit-section-code">02 / ОЧЕРЕДЬ ВНИМАНИЯ</span>
     <h2 id="orbit-attention-title">Требует решения <span>{snapshot?String(attention.length).padStart(2,"0"):"—"}</span></h2>
    </div>
    <div className="orbit-attention-items">
     {!snapshot?<p className="orbit-empty-state">Нет проверенного снимка. Состояния служб не определены.</p>:
      !attention.length?<p className="orbit-empty-state">По текущему снимку нет служб в состояниях «Сбой», «Нет данных» или «Запущен без допуска».</p>:
      attention.slice(0,5).map((s,i)=><button key={s.id} className="orbit-attention-item" type="button" onClick={()=>onView(s.id==="qa"?"qa":s.id==="research"?"research":s.id.startsWith("agent")?"agent":"ops")}>
      <div className="orbit-attention-meta"><span>{String(i+1).padStart(2,"0")} / {s.unit}</span><span>{stateLabel(s.state)}</span></div>
      <strong>{s.name}</strong><p>Снимок systemd: {stateLabel(s.state)}. Проверить детали в разделе.</p>
      <span className="orbit-attention-link">Открыть детали <ArrowUpRight size={14} aria-hidden="true"/></span>
      </button>)
     }
    </div>
    <p className="orbit-attention-note"><LockKeyhole size={15}/> История инцидентов и действия по управлению здесь не моделируются.</p>
    <button type="button" className="orbit-attention-cta" onClick={()=>onView("inbox")}>Открыть входящие <ArrowUpRight size={15}/></button>
   </aside>
  </div>
  <section className="orbit-registry-section">
   <div className="orbit-module-head"><div><span className="orbit-section-code">03 / СЛУЖБЫ И КОМПОНЕНТЫ</span><h2>Состояние контуров</h2></div>
    <button type="button" className="orbit-small-button" onClick={onRefresh} disabled={busy}><Activity size={16} aria-hidden="true"/>{busy?"Обновление…":"Обновить снимок"}</button></div>
   {Registry&&<Registry {...registryProps}/>}
   <p className="orbit-data-footnote"><ShieldCheck size={15} aria-hidden="true"/> Активный таймер не доказывает успешность последнего задания. Отсутствующие данные не заменяются демонстрацией.</p>
  </section>
 </div>;
}
