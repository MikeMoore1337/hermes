import React, {useState} from "react";
import {ArrowRight, ArrowUpRight, Github, LayoutDashboard, LockKeyhole, Pause,
  Play, ShieldCheck} from "lucide-react";
import "./orbit-login.css";

/** Visual-only gateway. The server alone owns authentication and authorization. */
const phases=[
  {id:"identity",number:"01",title:"Идентификация",name:"GitHub",
   detail:"GitHub используется для начала авторизации. Пароль аккаунта не вводится в Hermes."},
  {id:"policy",number:"02",title:"Проверка доступа",name:"Политика доступа",
   detail:"Сервер проверяет разрешения и состояние сессии. Эта схема не сообщает результат проверки."},
  {id:"workspace",number:"03",title:"Рабочее пространство",name:"Command Center",
   detail:"Доступ открывается только после серверной проверки. Набор доступных действий зависит от разрешений."}
];

function Mark({className=""}){
 return <img className={className} src="/orbit-brand.svg" alt="Фирменная эмблема Hermes - крылатая H"/>;
}
function Step({id,number,name,caption,selected,onClick,Icon}){
 return <button type="button" onClick={onClick} aria-pressed={selected}
   className={"orbit-route-node orbit-node-"+id+(selected?" is-current":"")}>
   <span className="orbit-node-label">{caption}<small>{number}</small></span>
   <span className="orbit-node-name"><Icon className="orbit-route-icon" size={22} strokeWidth={2.2} aria-hidden="true"/>{name}</span>
   <span className="orbit-node-state"><span aria-hidden="true"/> {id==="identity"?"Поставщик входа":id==="policy"?"Проверка на сервере":"После разрешения"}</span>
 </button>;
}
export default function OrbitLogin({active=false,unavailable=false,onBack,themeControl=null}){
 const [selected,setSelected]=useState("identity");
 const [playing,setPlaying]=useState(true);
 const phase=phases.find(p=>p.id===selected)||phases[0];
 const notActive=!active||unavailable;
 return <div className={"orbit-auth"+(playing?"":" orbit-motion-off")}>
  <a className="orbit-auth-skip" href="#orbit-auth-form">Перейти к форме входа</a>
  <header className="orbit-auth-header">
   <div className="orbit-auth-brand"><Mark/><div><strong>HERMES</strong><span>COMMAND CENTER</span></div></div>
   <div className="orbit-auth-header-actions">
    {themeControl}
   </div>
  </header>
  <main className="orbit-auth-layout">
   <div className="orbit-auth-left">
    <div className="orbit-auth-intro">
      <h1>Все системы.<span>Один центр решений.</span></h1>
      <p>Единая точка доступа к проектам, сигналам и инструментам Hermes. Сначала подтверждение личности - затем рабочее пространство.</p>
    </div>
    <section className="orbit-auth-route" aria-labelledby="orbit-route-title">
      <div className="orbit-route-header"><h2 id="orbit-route-title"><span>01 /</span> Маршрут доступа</h2>
       <button type="button" className="orbit-motion-control" onClick={()=>setPlaying(v=>!v)} aria-pressed={!playing}>
        {playing?<Pause size={14} aria-hidden="true"/>:<Play size={14} aria-hidden="true"/>}
        {playing?"Приостановить":"Воспроизвести"}
       </button>
      </div>
      <div className={"orbit-route-stage orbit-selected-"+selected}>
       <svg className="orbit-route-lines" viewBox="0 0 740 350" preserveAspectRatio="none" aria-hidden="true">
        <path className="orbit-line-base" d="M0 173H255M445 173H492L545 90H740M445 190H488L550 282H740"/>
        <path className="orbit-line-signal" d="M0 173H255M445 173H492L545 90H740M445 190H488L550 282H740"/>
        <circle cx="255" cy="173" r="4"/><circle cx="545" cy="90" r="4"/><circle cx="550" cy="282" r="4"/>
       </svg>
       <Step id="identity" number="01" name="GitHub" Icon={Github} caption="ID PROVIDER" selected={selected==="identity"} onClick={()=>setSelected("identity")}/>
       <div className="orbit-auth-core" aria-label="Hermes Core - визуальная схема, не состояние реального агента">
        <div className="orbit-core-symbol"><img src="/orbit-brand.svg" alt="" width="86" height="86" aria-hidden="true"/></div>
        <strong>HERMES <span>CORE</span></strong>
       </div>
       <Step id="policy" number="02" name="Политика доступа" Icon={ShieldCheck} caption="AUTHORIZATION" selected={selected==="policy"} onClick={()=>setSelected("policy")}/>
       <Step id="workspace" number="03" name="Command Center" Icon={LayoutDashboard} caption="WORKSPACE" selected={selected==="workspace"} onClick={()=>setSelected("workspace")}/>
      </div>
      <div className="orbit-route-caption" aria-live="polite">
        <span className="orbit-phase-number">{phase.number}<small> / 03</small></span>
        <div><strong>{phase.title} <span>/ {phase.name}</span></strong><p>{phase.detail}</p></div>
        <div className="orbit-phase-selector" role="group" aria-label="Этап маршрута">
         {phases.map(p=><button key={p.id} type="button" aria-label={"Этап "+p.number+": "+p.title} aria-pressed={p.id===selected} onClick={()=>setSelected(p.id)}>{p.number}</button>)}
        </div>
      </div>
    </section>
   </div>
   <aside className="orbit-auth-right">
    <div className="orbit-access-form" id="orbit-auth-form" tabIndex={-1}>
     <div className="orbit-access-content">
      <div className="orbit-access-emblem"><img src="/orbit-brand.svg" alt="" width="60" height="60" aria-hidden="true"/></div>
      <h2 className="orbit-access-label">Вход в систему</h2>
      <h3>Добро пожаловать<br/>в Hermes.</h3>
      <p className="orbit-access-lead">Войдите через GitHub, чтобы получить доступ к разрешённым функциям Command Center.</p>
      {active&&!unavailable
       ?<a className="orbit-github-cta" href="/auth/github/start" aria-label="Войти через GitHub">
         <Github size={23} aria-hidden="true"/> Продолжить через GitHub <ArrowRight size={19} aria-hidden="true"/></a>
       :<button type="button" className="orbit-github-cta" disabled aria-label="Войти через GitHub">
         <Github size={23} aria-hidden="true"/> Продолжить через GitHub <ArrowRight size={19} aria-hidden="true"/></button>}
      <p className="orbit-login-notice" role={unavailable?"alert":undefined}>
       <LockKeyhole size={14} aria-hidden="true"/>
       {unavailable?"Проверка состояния авторизации не удалась. Доступ закрыт."
        :notActive?"OAuth не включён. Предпросмотр интерфейса защищён существующей авторизацией."
        :"Доступ предоставляется только разрешённому GitHub ID. Права записи не выдаются."}
      </p>
      <div className="orbit-access-steps">
       <div className="orbit-access-steps-head"><span>ПОСЛЕ ВХОДА</span><span>01 → 03</span></div>
       <div><Github className="orbit-step-icon" size={21} strokeWidth={2.2} aria-hidden="true"/><span><strong>Идентификация</strong><small>Подтверждение через GitHub</small></span><b>01</b></div>
       <div><ShieldCheck className="orbit-step-icon" size={21} strokeWidth={2.2} aria-hidden="true"/><span><strong>Проверка доступа</strong><small>Разрешения и сессия на сервере</small></span><b>02</b></div>
       <div><LayoutDashboard className="orbit-step-icon" size={21} strokeWidth={2.2} aria-hidden="true"/><span><strong>Рабочее пространство</strong><small>Только в пределах разрешений</small></span><b>03</b></div>
      </div>
      {onBack&&!active&&!unavailable&&<button className="orbit-preview-link" type="button" onClick={onBack}>
       Открыть демонстрацию панели <ArrowUpRight size={16} aria-hidden="true"/>
      </button>}
     </div>
    </div>
   </aside>
  </main>
 </div>;
}
