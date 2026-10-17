import React,{useCallback,useEffect,useState} from "react";
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
function WindowMeter({bucket,muted=false}){
 const r=bucket.remaining_percent;
 if(typeof r!=="number"||r<0||r>100)return null;
 return <div className={"codex-meter"+(muted?" is-muted":"")}>
  <div className="codex-meter-label"><strong>{bucketName(bucket.duration_minutes)}</strong><span>{r}% осталось</span></div>
  <div className="codex-track" role="progressbar" aria-label={"Осталось в окне "+bucketName(bucket.duration_minutes)} aria-valuemin={0} aria-valuemax={100} aria-valuenow={r}>
   <div className={"codex-track-fill"+(r<=20?" is-low":"")} style={{width:r+"%"}}/>
  </div>
  <small><Clock3 size={13}/> {bucket.resets_at==null?"Время обновления неизвестно":"Обновление "+formatMoment(bucket.resets_at)}</small>
 </div>;
}
export default function CodexPanel({compact=false}){
 const [snapshot,setSnapshot]=useState(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [expanded,setExpanded]=useState(!compact);
 const refresh=useCallback(async()=>{
  setLoading(true);
  try{
   const res=await fetch("/api/providers/codex",{cache:"no-store",credentials:"same-origin"});
   if(!res.ok)throw Error("HTTP "+res.status);
   const data=await res.json();
   if(!validCodex(data))throw Error("Некорректный формат");
   setSnapshot(data);setError("");
  }catch(_){setSnapshot(null);setError("Не удалось прочитать состояние Codex.");}
  finally{setLoading(false);}
 },[]);
 useEffect(()=>{
  refresh();
  const id=setInterval(()=>{if(!document.hidden)refresh();},60000);
  return()=>clearInterval(id);
 },[refresh]);
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
    <div className="codex-meter-grid">{limit.windows.map((w,j)=><WindowMeter key={j} bucket={w} muted={status==="stale"}/>)}</div>
   </div>)}</div>}
   <p className="codex-disclaimer">Источник: официальный Codex App Server на VPS. Кнопка «Обновить» читает последний серверный снимок, не вызывает OpenAI. Проценты не гарантируют успешного запуска задачи.</p>
  </div>}
 </section>;
}
