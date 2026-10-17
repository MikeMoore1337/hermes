import React,{useCallback,useEffect,useMemo,useState} from "react";
import {Activity,AlertTriangle,Clock3,RefreshCw,ChevronDown} from "lucide-react";
import "./codex-usage.css";

const states={
 available:["Доступен","good"],low:["Квота заканчивается","warn"],
 limited:["Часть квот исчерпана","warn"],exhausted:["Квота исчерпана","bad"],
 stale:["Данные устарели","warn"],auth_required:["Нужен вход в Codex","warn"],
 unavailable:["Сервис недоступен","warn"],not_configured:["Не подключён","muted"],
 unknown:["Нет данных о квоте","muted"]
};
const formatMoment=v=>{
 if(typeof v!=="number"||!Number.isFinite(v)||v<0)return "Не указано";
 const d=new Date(v*1000);
 return Number.isFinite(d.getTime())?d.toLocaleString("ru-RU",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}):"Не указано";
};
const formatObserved=v=>{
 if(typeof v!=="string")return "Нет данных";
 const d=new Date(v);
 return Number.isFinite(d.getTime())?d.toLocaleString("ru-RU",{hour:"2-digit",minute:"2-digit",day:"2-digit",month:"2-digit"}):"Нет данных";
};
const bucketName=m=>{
 if(m===300)return "5 часов";
 if(m===10080)return "7 дней";
 if(!Number.isInteger(m)||m<1)return "Окно не указано";
 if(m%1440===0)return (m/1440)+" дн.";
 if(m%60===0)return (m/60)+" ч";
 return m+" мин";
};
export const validCodex=d=>Boolean(d&&d.schema===1&&d.source==="codex-app-server"
 &&typeof d.status==="string"&&Object.hasOwn(states,d.status)
 &&Array.isArray(d.limits)&&d.limits.length<=24);
const statusLabels={available:"Доступен",low:"Низкий остаток",limited:"Ограничен",
 exhausted:"Исчерпан",auth_required:"Требуется вход",stale:"Устарел",unavailable:"Недоступен",unknown:"Неизвестно"};
const decisionLabels={ALLOW:"Запуск допустим",DEFER:"Новые задания отложены",UNKNOWN:"Нет подтверждения доступности"};
export const historyPoints=data=>(Array.isArray(data?.samples)?data.samples:[]).map(item=>{
 const time=new Date(item.observed_at).getTime();
 if(!Number.isFinite(time))return null;
 const windows=Array.isArray(item.limits)?item.limits.flatMap(group=>Array.isArray(group.windows)?group.windows:[]):[];
 const remain=windows.map(w=>w.remaining_percent).filter(v=>typeof v==="number"&&Number.isFinite(v)&&v>=0&&v<=100);
 return {time,status:item.status,remaining:remain.length?Math.min(...remain):null};
}).filter(Boolean);
function HistoryChart({history,days}){
 const points=useMemo(()=>historyPoints(history),[history]);
 const start=Date.now()-days*86400000,end=Date.now();
 const width=640,height=152,left=34,right=12,top=8,bottom=28;
 const plotW=width-left-right,plotH=height-top-bottom;
 const project=p=>[left+Math.max(0,Math.min(1,(p.time-start)/(end-start)))*plotW,
  top+(100-p.remaining)*plotH/100];
 const runs=[];let current=[];
 points.forEach(p=>{
  if(p.remaining===null||p.status==="unavailable"||p.status==="auth_required"||p.status==="unknown"){
   if(current.length)runs.push(current);current=[];return;
  }
  if(current.length&&p.time-current[current.length-1].time>3600000){runs.push(current);current=[];}
  current.push(p);
 });
 if(current.length)runs.push(current);
 return <div className="codex-chart-wrap" role="img" aria-label={"История минимального остатка квоты за "+days+" дней, точек: "+points.length}>
  <svg viewBox={"0 0 "+width+" "+height} className="codex-history-chart" aria-hidden="true">
   {[0,20,50,100].map(v=><g key={v}><line x1={left} x2={width-right} y1={top+(100-v)*plotH/100} y2={top+(100-v)*plotH/100} className="codex-chart-grid"/>
    <text x={left-8} y={top+(100-v)*plotH/100+4} textAnchor="end" className="codex-chart-text">{v}%</text></g>)}
   {runs.map((run,i)=>run.length>1?
    <polyline key={i} fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round"
     points={run.map(p=>project(p).join(",")).join(" ")}/>:
    <circle key={i} cx={project(run[0])[0]} cy={project(run[0])[1]} r="2.8" fill="currentColor"/>)}
   <text x={left} y={height-5} className="codex-chart-text">{days===1?"24 часа назад":days+" дн. назад"}</text>
   <text x={width-right} y={height-5} textAnchor="end" className="codex-chart-text">Сейчас</text>
  </svg>
 </div>;
}
function WindowMeter({bucket,muted=false,threshold=20}){
 const r=bucket.remaining_percent;
 if(typeof r!=="number"||r<0||r>100)return null;
 return <div className={"codex-meter"+(muted?" is-muted":"")}>
  <div className="codex-meter-label"><strong>{bucketName(bucket.duration_minutes)}</strong><span>{r}% осталось</span></div>
  <div className="codex-track" role="progressbar" aria-label={"Осталось в окне "+bucketName(bucket.duration_minutes)} aria-valuemin={0} aria-valuemax={100} aria-valuenow={r}>
   <div className={"codex-track-fill"+(r<=threshold?" is-low":"")} style={{width:r+"%"}}/>
  </div>
  <small><Clock3 size={13}/> {bucket.resets_at==null?"Время обновления неизвестно":"Обновление "+formatMoment(bucket.resets_at)}</small>
 </div>;
}
export default function CodexPanel({compact=false}){
 const [snapshot,setSnapshot]=useState(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [expanded,setExpanded]=useState(!compact);
 const [days,setDays]=useState(7);
 const [threshold,setThreshold]=useState(()=>{
  try {const n=Number(window.localStorage.getItem("hermes.codex.warningPercent"));
   return Number.isInteger(n)&&n>=0&&n<=50?n:20;}catch(_){return 20;}
 });
 const [history,setHistory]=useState(null);
 const [historyError,setHistoryError]=useState("");
 const [policy,setPolicy]=useState(null);
 const [revision,setRevision]=useState(0);
 const refresh=useCallback(async()=>{
  setLoading(true);
  try{
   const res=await fetch("/api/providers/codex",{cache:"no-store",credentials:"same-origin"});
   if(!res.ok)throw Error("HTTP "+res.status);
   const data=await res.json();
   if(!validCodex(data))throw Error("Некорректный формат");
   setSnapshot(data);setError("");setRevision(n=>n+1);
  }catch(_){setSnapshot(null);setError("Не удалось прочитать состояние Codex.");}
  finally{setLoading(false);}
 },[]);
 useEffect(()=>{
  refresh();
  const id=setInterval(()=>{if(!document.hidden)refresh();},60000);
  return()=>clearInterval(id);
 },[refresh]);
 useEffect(()=>{
  let alive=true;
  fetch("/api/providers/codex/history?days="+days,{cache:"no-store",credentials:"same-origin"})
   .then(res=>{if(!res.ok)throw Error();return res.json();})
   .then(data=>{if(alive){setHistory(data);setHistoryError("");}})
   .catch(()=>{if(alive){setHistory(null);setHistoryError("История временно недоступна.");}});
  return()=>{alive=false;};
 },[days,revision]);
 useEffect(()=>{
  let alive=true;
  fetch("/api/providers/codex/policy?threshold="+threshold,{cache:"no-store",credentials:"same-origin"})
   .then(res=>{if(!res.ok)throw Error();return res.json();})
   .then(data=>{if(alive)setPolicy(data);})
   .catch(()=>{if(alive)setPolicy(null);});
  return()=>{alive=false;};
 },[threshold,revision]);
 const updateThreshold=event=>{
  const next=Number(event.target.value);
  if(!Number.isInteger(next)||next<0||next>50)return;
  setThreshold(next);
  try{window.localStorage.setItem("hermes.codex.warningPercent",String(next));}catch(_){}
 };
 const status=error?"unavailable":snapshot?.status||"unknown";
 const [label,tone]=states[status];
 const limits=snapshot?.limits||[];
 return <section className={"codex-panel"+(compact?" codex-compact":"")} aria-label="Лимиты Codex">
  <div className="codex-panel-head">
   <div className="codex-panel-title"><Activity size={19} strokeWidth={1.6} aria-hidden="true"/>
    <div><span className="eyebrow">CODEX / USAGE</span><h2>Лимиты Codex</h2></div>
   </div>
   <span className={"codex-chip codex-chip-"+tone}>{label}</span>
  </div>
  <div className="codex-panel-meta"><span>Последняя проверка: {formatObserved(snapshot?.observed_at)}</span>
   <button type="button" onClick={refresh} disabled={loading} className="codex-reload" aria-label="Обновить отображение лимитов Codex">
    <RefreshCw size={15} className={loading?"spin":""}/> Обновить
   </button></div>
  {compact&&<button className="codex-disclose" type="button" onClick={()=>setExpanded(x=>!x)}
   aria-expanded={expanded}>{expanded?"Скрыть подробности":"Показать подробности"}
   <ChevronDown size={16} className={expanded?"is-up":""}/></button>}
  {expanded&&<div className="codex-content">
   {status==="not_configured"&&<p className="codex-message">Монитор Codex на сервере пока не подключён. После авторизации на VPS здесь появятся реальные данные.</p>}
   {status==="auth_required"&&<p className="codex-message">Нужна авторизация ChatGPT для Codex CLI на VPS.</p>}
   {status==="unavailable"&&<p className="codex-message" role="status">{error||"Нет соединения с Codex. Доступная квота неизвестна."}</p>}
   {status==="unknown"&&<p className="codex-message">Провайдер не вернул применимых окон квоты.</p>}
   {status==="stale"&&<p className="codex-message" role="status">Последний опрос устарел. Показатели ниже только для справки.</p>}
   {status==="exhausted"&&<p className="codex-message codex-message-warning">Лимит исчерпан по данным последнего опроса.</p>}
   {limits.length>0&&<div className="codex-limits">{limits.map((limit,i)=><div className="codex-group" key={limit.limit_id||i}>
    <div className="codex-group-title"><strong>{limit.limit_id==="codex"?"Codex":(limit.limit_id||"Дополнительная квота").replace(/[^a-zA-Z0-9_.-]/g,"").slice(0,50)}</strong>
    {limit.status==="exhausted"&&<span><AlertTriangle size={13}/> Исчерпан</span>}</div>
    <div className="codex-meter-grid">{limit.windows.map((w,j)=><WindowMeter key={j} bucket={w} muted={status==="stale"} threshold={threshold}/>)}</div>
   </div>)}</div>}
   <div className="codex-history">
    <div className="codex-history-head"><div><strong>История квот</strong><small>Минимальный остаток среди доступных окон</small></div>
     <div className="codex-periods" aria-label="Период истории">
      {[1,7,30].map(n=><button key={n} type="button" className={days===n?"is-active":""}
       onClick={()=>setDays(n)} aria-pressed={days===n}>{n===1?"24 ч":n+" дн."}</button>)}
     </div>
    </div>
    {historyError?<p className="codex-message" role="status">{historyError}</p>:
     history?.samples?.length?<HistoryChart history={history} days={days}/>:
     <p className="codex-message">История пока пуста. Она накапливается после опросов VPS.</p>}
    {history?.last_successful_at&&<small className="codex-last-success">Последний подтверждённый опрос: {formatObserved(history.last_successful_at)}</small>}
    {history?.transitions?.length>0&&<details className="codex-transitions"><summary>История событий ({history.transitions.length})</summary>
     <ul>{history.transitions.slice(0,10).map((e,i)=><li key={e.observed_at+"-"+i}>
      <time>{formatObserved(e.observed_at)}</time><span>{statusLabels[e.previous]||"Нет данных"} → {statusLabels[e.current]||"Нет данных"}</span>
     </li>)}</ul></details>}
   </div>
   <div className="codex-settings">
    <div><label htmlFor="codex-warning-threshold">Порог предупреждения · {threshold}% остатка</label>
     <small>Локальная оценка доступности. Не изменяет серверный порог Ops Watch.</small></div>
    <input id="codex-warning-threshold" type="range" min="0" max="50" step="5" value={threshold} onChange={updateThreshold}/>
    <p className="codex-policy-status">Проверка новых задач: <strong>{decisionLabels[policy?.decision]||"Нет ответа сервера"}</strong></p>
   </div>
   <p className="codex-disclaimer">Источник: официальный Codex App Server на VPS. Кнопка «Обновить» читает последний серверный снимок, не вызывает OpenAI. Проценты не гарантируют успешного запуска задачи.</p>
  </div>}
 </section>;
}
