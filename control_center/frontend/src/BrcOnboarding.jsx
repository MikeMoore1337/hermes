import React,{useEffect,useRef,useState} from "react";

const githubUrl=/^https:\/\/github\.com\/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)\/([a-z0-9_][a-z0-9_.-]{0,103})\/?$/i;
const exact=(value,keys)=>value!==null&&typeof value==="object"&&!Array.isArray(value)&&
 Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));

export default function BrcOnboarding({deviceStatus}){
 const dialog=useRef(null), opener=useRef(null), input=useRef(null), heading=useRef(null), request=useRef(null);
 const [url,setUrl]=useState(""),[invalid,setInvalid]=useState(false),[error,setError]=useState("");
 const [busy,setBusy]=useState(false),[result,setResult]=useState(null);
 useEffect(()=>()=>{request.current?.abort();request.current=null;},[]);
 useEffect(()=>{if(result)heading.current?.focus();},[result]);
 const reset=()=>{request.current?.abort();request.current=null;setUrl("");setInvalid(false);setError("");setBusy(false);setResult(null);};
 const open=()=>{reset();dialog.current.showModal();requestAnimationFrame(()=>input.current?.focus());};
 const close=()=>dialog.current.close();
 const onClose=()=>{reset();opener.current?.focus();};
 const onKeyDown=event=>{
  if(event.key!=="Tab")return;
  const items=[...dialog.current.querySelectorAll("button:not(:disabled),input:not(:disabled)")].filter(item=>item.getClientRects().length);
  if(!items.length)return;
  if(event.shiftKey&&document.activeElement===items[0]){event.preventDefault();items.at(-1).focus();}
  else if(!event.shiftKey&&document.activeElement===items.at(-1)){event.preventDefault();items[0].focus();}
 };
 const submit=async event=>{
  event.preventDefault();if(request.current)return;
  const value=url.trim(),match=githubUrl.exec(value),repo=match?.[2].replace(/\.git$/i,"");
  if(!match||value.length>200||!repo||repo.length>100||repo.endsWith(".")||repo.includes("..")){
   setError("Введите HTTPS-ссылку GitHub с допустимым именем проекта.");setInvalid(true);input.current?.focus();return;
  }
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),8000);
  request.current=controller;setBusy(true);setError("Проверяем адрес и публичный репозиторий…");
  try{
   const response=await fetch("/api/providers/hermes-brc/onboarding-preview",{
    method:"POST",credentials:"same-origin",cache:"no-store",signal:controller.signal,
    headers:{"Content-Type":"application/json","X-Hermes-Onboarding-Intent":"owner-interactive"},
    body:JSON.stringify({repository_url:value})
   });
   if(response.status===401||response.status===403)throw Error("auth");
   if(!response.ok)throw Error("unavailable");
   const data=await response.json(),name=repo.toLowerCase();
   if(!exact(data,["schema","status","repository","device","root","scope","catalog","remote","filesystem","can_connect"])||
    data.schema!==1||data.status!=="preview_only"||data.repository!=="https://github.com/"+match[1]+"/"+name+".git"||
    data.device!=="Windows sandbox"||data.root!=="/workspace/projects/"+name||data.scope!=="sandbox"||
    !["reserved","not_reserved"].includes(data.catalog)||
    (data.catalog==="reserved"?data.remote!=="not_checked":!["public_confirmed","unavailable"].includes(data.remote))||
    data.filesystem!=="not_checked"||data.can_connect!==false)throw Error("invalid");
   if(dialog.current?.open&&request.current===controller){setError("");setResult(data);}
  }catch(reason){
   if(dialog.current?.open&&request.current===controller)setError(reason.message==="auth"?
    "Предпросмотр доступен после входа владельца через GitHub.":"Предпросмотр недоступен. Никаких изменений не выполнено.");
  }finally{clearTimeout(timeout);if(request.current===controller){request.current=null;setBusy(false);}}
 };
 const state={online:"на связи",offline:"не на связи",paused:"приостановлено",stale:"данные устарели"}[deviceStatus];
 return <>
  <button ref={opener} id="brc-onboard-open" className="oc-action brc-onboard-open" type="button" onClick={open}>Подключить проект</button>
  <dialog ref={dialog} id="brc-onboard" className="brc-onboard" aria-labelledby="brc-onboard-title"
   aria-describedby="brc-onboard-help" onClose={onClose} onKeyDown={onKeyDown}>
   <div className="brc-onboard-header"><div><h2 id="brc-onboard-title">Подключить проект</h2>
    <p id="brc-onboard-step">Шаг {result?"2":"1"} из 2</p></div>
    <button id="brc-onboard-close" type="button" aria-label="Закрыть" onClick={close}>×</button></div>
   <form id="brc-onboard-form" noValidate onSubmit={submit}>
    <div id="brc-onboard-entry" hidden={Boolean(result)}>
     <div className="brc-onboard-label">Источник</div>
     <div className="brc-onboard-sources">
      <div className="brc-onboard-source selected"><strong>Git-репозиторий в sandbox</strong><small>Изолированная рабочая копия</small></div>
      <div className="brc-onboard-source" aria-disabled="true"><strong>Папка Windows</strong><small>Требуется отдельное разрешение</small></div>
     </div>
     <label className="brc-onboard-label" htmlFor="brc-onboard-url">Ссылка на репозиторий</label>
     <input ref={input} id="brc-onboard-url" name="repository_url" type="url" maxLength={200}
      placeholder="https://github.com/owner/repository" autoComplete="off" aria-describedby="brc-onboard-help brc-onboard-error"
      aria-invalid={invalid?"true":undefined} required value={url} onChange={event=>{setUrl(event.target.value);setInvalid(false);}}/>
     <p id="brc-onboard-help" className="brc-onboard-help">Проверяем формат, встроенный каталог и публичный доступ к GitHub. Папка на устройстве пока не проверяется.</p>
     <p id="brc-onboard-error" className="brc-onboard-error" role="status" aria-live="polite">{error}</p>
     <div className="brc-onboard-actions"><button id="brc-onboard-cancel" type="button" onClick={close}>Отмена</button>
      <button id="brc-onboard-preview" className="primary" type="submit" disabled={busy}>Проверить</button></div>
    </div>
    <div id="brc-onboard-result" hidden={!result}>
     <h3 ref={heading} id="brc-onboard-result-title" tabIndex={-1}>Проверьте подключение</h3>
     <dl className="brc-onboard-summary">
      <div><dt>Репозиторий</dt><dd id="brc-onboard-repository">{result?.repository}</dd></div>
      <div><dt>Устройство</dt><dd id="brc-onboard-device">{state?"Windows sandbox — "+state+" (по снимку)":"Windows sandbox — нет свежих данных"}</dd></div>
      <div><dt>Каталог</dt><dd id="brc-onboard-root">{result?.root}</dd></div>
      <div><dt>Доступ</dt><dd>Только sandbox</dd></div>
     </dl>
     <p id="brc-onboard-result-note" className="brc-onboard-help" role="status">{result?.catalog==="reserved"?
      "Имя зарезервировано или уже есть во встроенном каталоге. Подключение заблокировано.":
      result?.remote==="public_confirmed"?"Публичный репозиторий найден на GitHub; это имя отсутствует во встроенном каталоге.":
      "Не удалось подтвердить публичный репозиторий. Проверьте адрес или повторите позже."}</p>
     <p className="brc-onboard-help">Оригинальные папки Windows не затрагиваются. Подключение пока недоступно: инструменты и конфликты файлов не проверены.</p>
     <div className="brc-onboard-actions"><button id="brc-onboard-back" type="button" onClick={()=>{setResult(null);requestAnimationFrame(()=>input.current?.focus());}}>Назад</button>
      <button className="primary" type="button" disabled>Подключить</button></div>
    </div>
   </form>
  </dialog>
 </>;
}
