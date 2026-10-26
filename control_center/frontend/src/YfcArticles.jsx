import React,{useCallback,useEffect,useRef,useState} from "react";
import {AlertTriangle,BookOpen,CheckCircle2,ExternalLink,FileText,
  LockKeyhole,RefreshCw,ShieldCheck,X} from "lucide-react";
import "./yfc-articles.css";

const ID=/^[0-9a-f]{32}$/;
const HASH=/^[0-9a-f]{64}$/;
const statuses=new Set(["draft","review","update_required"]);
const safeSourceUrl=(url)=>{
 try{
  const value=new URL(url);
  if(value.protocol!=="https:"||value.username||value.password)return null;
  return value.href;
 }catch{return null;}
};
const validRow=(row)=>row&&typeof row==="object"&&ID.test(row.article_id)&&
 statuses.has(row.article_status)&&HASH.test(row.content_hash)&&
 Number.isInteger(row.content_version)&&row.content_version>0&&typeof row.title==="string";
const validDetail=(article,row)=>{
 if(!article||!row||!validRow(article)||article.article_id!==row.article_id||
   article.content_hash!==row.content_hash||article.content_version!==row.content_version)return false;
 return typeof article.lead==="string"&&article.lead.trim().length>0&&
  typeof article.description==="string"&&Array.isArray(article.body_sections)&&
  article.body_sections.length>=2&&article.body_sections.length<=24&&
  article.body_sections.every(s=>s&&typeof s.heading==="string"&&s.heading.trim()&&
   Array.isArray(s.paragraphs)&&s.paragraphs.length>0&&
   s.paragraphs.every(p=>typeof p==="string"&&p.trim()))&&
  Array.isArray(article.claims)&&article.claims.length>0&&
  Array.isArray(article.sources)&&article.sources.length>0&&
  Array.isArray(article.claim_source_matrix)&&article.claim_source_matrix.length>0&&
  Array.isArray(article.review_blockers);
};
const blocked=(article)=>article.claim_source_matrix.some(x=>
 !x||x.review_status==="blocked"||x.support_level==="does_not_support");
async function editorialRequest(action,payload,signal){
 const res=await fetch("/api/yfc/editorial/"+action,{
  method:"POST",credentials:"same-origin",cache:"no-store",signal,
  headers:{"Content-Type":"application/json","X-Hermes-Editorial-Intent":"owner-interactive"},
  body:JSON.stringify(payload)
 });
 let value={};
 try{value=await res.json();}catch{/* request cannot be treated as success */}
 if(!res.ok)throw Error(value.error||"yfc_request_unavailable");
 return value;
}
const errors={
 authentication_required:"Сессия Hermes завершена. Войдите снова.",
 owner_oauth_required:"Публикация доступна только после входа владельца через GitHub.",
 owner_origin_denied:"Защита запроса не пройдена. Обновите страницу.",
 yfc_root_auth_required:"Root-токен YFC недействителен или срок его действия истёк.",
 yfc_article_revision_conflict:"Черновик изменился. Обновите очередь и перечитайте статью.",
 yfc_article_not_publishable:"Этот черновик нельзя публиковать. Проверьте его статус и источники.",
 yfc_draft_response_invalid:"Получен неполный черновик. Публикация запрещена.",
 owner_confirmation_required:"Необходимо явное подтверждение владельца.",
 editorial_rate_limited:"Слишком много запросов. Повторите действие позже."
};
const friendly=(e)=>errors[e?.message]||"Не удалось выполнить запрос к YFC. Повторите проверку.";

export default function YfcArticles(){
 const [token,setToken]=useState("");
 const [rows,setRows]=useState([]);
 const [selected,setSelected]=useState(null);
 const [article,setArticle]=useState(null);
 const [phase,setPhase]=useState("locked");
 const [detailPhase,setDetailPhase]=useState("idle");
 const [error,setError]=useState("");
 const [reading,setReading]=useState(false);
 const [confirm,setConfirm]=useState(false);
 const [ack,setAck]=useState(false);
 const [publishing,setPublishing]=useState(false);
 const [receipt,setReceipt]=useState(null);
 const confirmRef=useRef(null);
 const requestRef=useRef(null);
 const detailRef=useRef(null);
 const list=useCallback(async(rawToken)=>{
  requestRef.current?.abort();
  const ctrl=new AbortController();requestRef.current=ctrl;
  setPhase("loading");setError("");setRows([]);setArticle(null);setSelected(null);
  setDetailPhase("idle");setConfirm(false);setAck(false);setReading(false);setReceipt(null);
  try{
   const data=await editorialRequest("list",{root_token:rawToken,limit:25,offset:0},ctrl.signal);
   if(!Array.isArray(data)||data.length>25||!data.every(validRow))throw Error("yfc_draft_response_invalid");
   if(!ctrl.signal.aborted){setRows(data);setPhase("ready");}
  }catch(e){
   if(!ctrl.signal.aborted){setPhase("error");setError(friendly(e));
    if(e.message==="yfc_root_auth_required")setToken("");}
  }
 },[]);
 useEffect(()=>()=>{requestRef.current?.abort();detailRef.current?.abort();},[]);
 useEffect(()=>{
  detailRef.current?.abort();
  setArticle(null);setConfirm(false);setAck(false);setDetailPhase("idle");setReading(false);
  if(!selected||!token)return;
  const row=rows.find(x=>x.article_id===selected);
  if(!row)return;
  const ctrl=new AbortController();detailRef.current=ctrl;setDetailPhase("loading");
  (async()=>{
   try{
    const data=await editorialRequest("detail",{root_token:token,article_id:selected},ctrl.signal);
    if(!validDetail(data,row))throw Error("yfc_draft_response_invalid");
    if(!ctrl.signal.aborted){setArticle(data);setDetailPhase("ready");}
   }catch(e){
    if(!ctrl.signal.aborted){setDetailPhase("error");setError(friendly(e));
     if(e.message==="yfc_root_auth_required")setToken("");}
   }
  })();
  return()=>ctrl.abort();
 },[selected,rows,token]);
 useEffect(()=>{
  if(!confirm)return;
  confirmRef.current?.focus();
  const escape=e=>{if(e.key==="Escape"){setConfirm(false);setAck(false);}};
  window.addEventListener("keydown",escape);
  return()=>window.removeEventListener("keydown",escape);
 },[confirm]);
 const currentRow=rows.find(r=>r.article_id===selected);
 const exact=detailPhase==="ready"&&validDetail(article,currentRow);
 const canPublish=exact&&!blocked(article)&&!publishing;
 const disconnected=()=>{
  requestRef.current?.abort();detailRef.current?.abort();setToken("");
  setRows([]);setSelected(null);setArticle(null);setPhase("locked");
  setDetailPhase("idle");setConfirm(false);setReceipt(null);setError("");
 };
 const publish=async()=>{
  if(!canPublish||!ack||!confirm||!token)return;
  setPublishing(true);setError("");
  try{
   const receipt=await editorialRequest("publish",{
    root_token:token,article_id:article.article_id,
    content_hash:article.content_hash,content_version:article.content_version,
    owner_confirmed:true
   });
   if(receipt.article_id!==article.article_id||receipt.content_version!==article.content_version||
      receipt.article_status!=="published"||receipt.editorial_decision!=="root_owner_publication"||
      receipt.scientific_verification!=="not_attested"||
      !safeSourceUrl(receipt.canonical_url))throw Error("yfc_publication_receipt_invalid");
   setReceipt(receipt);setArticle(null);setSelected(null);setRows([]);
   setPhase("locked");setDetailPhase("idle");setToken("");setConfirm(false);setAck(false);setReading(false);
  }catch(e){setConfirm(false);setAck(false);setArticle(null);setDetailPhase("error");
   setError(friendly(e));}
  finally{setPublishing(false);}
 };
 return <section className="ye-root" aria-label="Редакция статей YFC">
  <header className="ye-header">
   <div><span className="ye-overline">HERMES / CONTENT STUDIO / I4</span>
    <h1><BookOpen size={25} aria-hidden="true"/> Статьи YFC</h1>
    <p>Hermes готовит черновики. Решение о публикации принимаете только вы.</p>
   </div>
   <span className="ye-manual"><ShieldCheck size={17}/> Только ручная публикация</span>
  </header>
  {receipt&&<div className="ye-receipt" role="status">
   <CheckCircle2 size={22}/><div><strong>Публикация подтверждена YFC</strong>
    <p>Версия {receipt.content_version}. Научная аттестация: не заявлена.</p>
    <a href={receipt.canonical_url} target="_blank" rel="noopener noreferrer">Открыть статью <ExternalLink size={14}/></a>
   </div></div>}
  <section className="ye-login" aria-label="Авторизация Root YFC">
   <div><strong><LockKeyhole size={17}/> Независимая Root-проверка YFC</strong>
    <p>Вход через GitHub в Hermes не заменяет Root-авторизацию YFC. Введите временный токен из действующей Root-сессии YFC. Он используется только в памяти вкладки и не сохраняется.</p></div>
   <form onSubmit={e=>{e.preventDefault();if(token.trim())void list(token.trim());}}>
    <label htmlFor="ye-token">Временный Root-токен YFC</label>
    <div className="ye-login-controls"><input id="ye-token" type="password" autoComplete="off"
     spellCheck={false} value={token} onChange={e=>setToken(e.target.value)}
     placeholder="Введите токен без отображения" aria-label="Временный токен YFC Root"/>
     <button type="submit" disabled={!token.trim()||phase==="loading"}>
      <RefreshCw size={15}/> {phase==="ready"?"Обновить":"Загрузить черновики"}</button>
     {token&&<button type="button" className="ye-ghost" onClick={disconnected}>Отключить</button>}
    </div>
   </form>
  </section>
  {error&&<div className="ye-error" role="alert"><AlertTriangle size={18}/>{error}</div>}
  {phase==="loading"&&<div className="ye-empty" role="status">Загружаем приватную очередь YFC…</div>}
  {phase==="ready"&&<div className={"ye-layout"+(reading?" ye-reading":"")}>
    <aside className="ye-queue" aria-label="Черновики">
     <div className="ye-queue-top"><h2>На проверку</h2><span>{rows.length}</span></div>
     {rows.length===0?<p className="ye-empty">На первой странице нет ожидающих публикации материалов.</p>:
     rows.map(row=><button type="button" key={row.article_id}
       className={"ye-queue-item"+(selected===row.article_id?" ye-selected":"")}
       aria-pressed={selected===row.article_id} onClick={()=>setSelected(row.article_id)}>
       <span className="ye-queue-status">{row.article_status==="draft"?"Черновик":"На проверке"}</span>
       <strong>{row.title}</strong><small>Версия {row.content_version} · источники {row.source_count}</small>
     </button>)}
    </aside>
    <div className="ye-content">
     {detailPhase==="loading"&&<div className="ye-empty" role="status">Получение точной редакции…</div>}
     {detailPhase==="error"&&<div className="ye-empty" role="alert">Черновик не подтверждён. Обновите очередь и выберите материал заново.</div>}
     {detailPhase==="idle"&&<div className="ye-empty"><FileText size={27}/> Выберите черновик для чтения полного текста и проверки источников.</div>}
     {exact&&<article className="ye-paper">
       <div className="ye-paper-tools"><span className="ye-queue-status">Не опубликовано</span>
        <button type="button" onClick={()=>setReading(v=>!v)} aria-pressed={reading}>
         {reading?"Вернуть очередь":"Режим чтения"}</button></div>
       <h2>{article.title}</h2><p className="ye-description">{article.description}</p>
       <p className="ye-lead">{article.lead}</p>
       {article.body_sections.map((section,i)=><section className="ye-section" key={i}>
        <h3>{section.heading}</h3>{section.paragraphs.map((paragraph,j)=><p key={j}>{paragraph}</p>)}
       </section>)}
       <section className="ye-evidence" aria-label="Научные доказательства">
        <h3>Научные тезисы и источники</h3>
        <p>Проверяйте тезисы отдельно от текста: статус pending не означает независимую научную верификацию.</p>
        {article.claims.map((claim,i)=><div className="ye-claim" key={claim.claim_id||i}>
         <strong>{claim.claim_text}</strong>
         <ul>{article.claim_source_matrix.filter(x=>x.claim_id===claim.claim_id).map((item,j)=>
          <li key={j}>Источник: {item.source_id} · Поддержка: {item.support_level} · Рецензия: {item.review_status}</li>)}</ul>
        </div>)}
        <h4>Первоисточники</h4><ol>{article.sources.map((source,i)=><li key={source.source_id||i}>
         {safeSourceUrl(source.url)?<a href={safeSourceUrl(source.url)} target="_blank" rel="noopener noreferrer">{source.title} <ExternalLink size={13}/></a>:<span>{source.title} (ссылка недоступна)</span>}
         {source.limitations&&<p>{source.limitations}</p>}
        </li>)}</ol>
       </section>
       <section className="ye-meta" aria-label="Редакция и ограничения">
        <h3>Проверки перед публикацией</h3>
        <p>Доказательства: {article.evidence_level}. Риск: {article.risk_level}. Рецензент: {article.domain_reviewer?.name||"не указан"}.</p>
        {article.review_blockers.length>0&&<ul>{article.review_blockers.map((b,i)=><li key={i}>{b}</li>)}</ul>}
        <dl><dt>Версия</dt><dd>{article.content_version}</dd>
         <dt>SHA-256 точной редакции</dt><dd className="ye-hash">{article.content_hash}</dd>
         <dt>Провайдер</dt><dd>{article.provider} · {article.model}</dd></dl>
       </section>
       {blocked(article)&&<div className="ye-error"><AlertTriangle size={18}/>Есть явно заблокированные или неподтверждённые источником тезисы — публикация недоступна.</div>}
       <div className="ye-paper-actions"><button type="button" disabled={!canPublish}
        onClick={()=>{setAck(false);setConfirm(true);}}>Проверил статью · перейти к публикации</button>
        <span>Никаких автоматических публикаций</span></div>
      </article>}
    </div>
  </div>}
  {confirm&&exact&&<div className="ye-modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget&&!publishing){setConfirm(false);setAck(false);}}}>
   <div className="ye-modal" role="dialog" aria-modal="true" aria-labelledby="ye-confirm-title">
    <button className="ye-close" type="button" ref={confirmRef} onClick={()=>{setConfirm(false);setAck(false);}} disabled={publishing} aria-label="Отменить публикацию"><X size={19}/></button>
    <span className="ye-overline">ПОСЛЕДНЕЕ ПОДТВЕРЖДЕНИЕ ВЛАДЕЛЬЦА</span>
    <h2 id="ye-confirm-title">Опубликовать именно эту редакцию?</h2>
    <strong>{article.title}</strong>
    <p>Версия {article.content_version} · SHA-256 <code className="ye-hash">{article.content_hash}</code></p>
    <p>YFC повторно сверит хеш и версию. Если черновик изменился, публикация будет отклонена.</p>
    <label className="ye-ack"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>
      Я прочитал полный текст и ограничения, понимаю, что независимая научная аттестация не заявлена.</label>
    <div className="ye-modal-actions"><button type="button" onClick={()=>{setConfirm(false);setAck(false);}} disabled={publishing}>Отмена</button>
      <button type="button" className="ye-publish" disabled={!ack||publishing||!canPublish}
       onClick={()=>void publish()}>{publishing?"Подтверждаем в YFC…":"Опубликовать в YFC"}</button></div>
   </div>
  </div>}
 </section>;
}
