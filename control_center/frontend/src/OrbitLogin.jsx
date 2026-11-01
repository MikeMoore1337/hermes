import React, {useState} from "react";
import {ArrowRight, ArrowUpRight, Check, Cpu, Github, LockKeyhole, Pause,
  Play, ShieldCheck, Workflow} from "lucide-react";
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
 return <img className={className} src="/brand.webp" alt="Фирменная эмблема Hermes - крылатая H"/>;
}
function Step({id,number,name,caption,selected,onClick,Icon}){
 return <button type="button" onClick={onClick} aria-pressed={selected}
   className={"orbit-route-node orbit-node-"+id+(selected?" is-current":"")}>
   <span className="orbit-node-label">{caption}<small>{number}</small></span>
   <span className="orbit-node-name"><Icon size={18} aria-hidden="true"/>{name}</span>
   <span className="orbit-node-state"><span aria-hidden="true"/> {id==="identity"?"Поставщик входа":id==="policy"?"Проверка на сервере":"После разрешения"}</span>
 </button>;
}
export default function OrbitLogin({active=false,unavailable=false,onBack}){
 const [selected,setSelected]=useState("identity");
 const [playing,setPlaying]=useState(true);
 const phase=phases.find(p=>p.id===selected)||phases[0];
 const notActive=!active||unavailable;
 return <div className={"orbit-auth"+(playing?"":" orbit-motion-off")}>
  <a className="orbit-auth-skip" href="#orbit-auth-form">Перейти к форме входа</a>
  <header className="orbit-auth-header">
   <div className="orbit-auth-brand"><Mark/><div><strong>HERMES</strong><span>COMMAND CENTER</span></div></div>
   <div className="orbit-auth-header-meta"><span>ORBIT / 2.0</span><i aria-hidden="true"/><span><LockKeyhole size={14} aria-hidden="true"/> ПРИВАТНЫЙ ДОСТУП</span></div>
  </header>
  <main className="orbit-auth-layout">
   <div className="orbit-auth-left">
    <div className="orbit-auth-intro">
      <div className="orbit-auth-marker"><span className="orbit-auth-wave" aria-hidden="true"><i/><i/><i/></span> HERMES / ТОЧКА ВХОДА <small>№ 001</small></div>
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
       <div className="orbit-stage-coord">GATEWAY / ACCESS ROUTE / V2.0</div>
       <div className="orbit-stage-outline" aria-hidden="true"/>
       <svg className="orbit-route-lines" viewBox="0 0 740 350" preserveAspectRatio="none" aria-hidden="true">
        <path className="orbit-line-base" d="M0 173H255M445 173H492L545 90H740M445 190H488L550 282H740"/>
        <path className="orbit-line-signal" d="M0 173H255M445 173H492L545 90H740M445 190H488L550 282H740"/>
        <circle cx="255" cy="173" r="4"/><circle cx="545" cy="90" r="4"/><circle cx="550" cy="282" r="4"/>
       </svg>
       <Step id="identity" number="01" name="GitHub" Icon={Github} caption="ID PROVIDER" selected={selected==="identity"} onClick={()=>setSelected("identity")}/>
       <div className="orbit-auth-core" aria-label="Hermes Core - визуальная схема, не состояние реального агента">
        <div className="orbit-core-top">H / SECURITY GATE</div>
        <div className="orbit-core-symbol"><span>H</span><i/></div>
        <strong>HERMES <span>CORE</span></strong><small>ACCESS ROUTER</small>
       </div>
       <Step id="policy" number="02" name="Политика доступа" Icon={ShieldCheck} caption="AUTHORIZATION" selected={selected==="policy"} onClick={()=>setSelected("policy")}/>
       <Step id="workspace" number="03" name="Command Center" Icon={Cpu} caption="WORKSPACE" selected={selected==="workspace"} onClick={()=>setSelected("workspace")}/>
       <div className="orbit-stage-bottom">SYS 00:01 / SCHEMATIC / NO LIVE LINK</div>
      </div>
      <div className="orbit-route-caption" aria-live="polite">
        <span className="orbit-phase-number">{phase.number}<small> / 03</small></span>
        <div><strong>{phase.title} <span>/ {phase.name}</span></strong><p>{phase.detail}</p></div>
        <div className="orbit-phase-selector" role="group" aria-label="Этап маршрута">
         {phases.map(p=><button key={p.id} type="button" aria-label={"Этап "+p.number+": "+p.title} aria-pressed={p.id===selected} onClick={()=>setSelected(p.id)}>{p.number}</button>)}
        </div>
      </div>
    </section>
    <p className="orbit-auth-schematic-note"><span>СХЕМА ПРОЦЕССА</span><span>СОЕДИНЕНИЯ НЕ ЯВЛЯЮТСЯ ТЕЛЕМЕТРИЕЙ</span></p>
   </div>
   <aside className="orbit-auth-right">
    <div className="orbit-access-form" id="orbit-auth-form" tabIndex={-1}>
     <div className="orbit-access-top"><span>ACCESS / 001</span><span><LockKeyhole size={12} aria-hidden="true"/> OAUTH</span></div>
     <div className="orbit-access-content">
      <div className="orbit-access-emblem"><LockKeyhole size={29} aria-hidden="true"/></div>
      <p className="orbit-access-tag"><span/> ЗАЩИЩЁННЫЙ ВХОД</p>
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
       <div><Github size={17} aria-hidden="true"/><span><strong>Идентификация</strong><small>Подтверждение через GitHub</small></span><b>01</b></div>
       <div><ShieldCheck size={17} aria-hidden="true"/><span><strong>Проверка доступа</strong><small>Разрешения и сессия на сервере</small></span><b>02</b></div>
       <div><Workflow size={17} aria-hidden="true"/><span><strong>Рабочее пространство</strong><small>Только в пределах разрешений</small></span><b>03</b></div>
      </div>
      {onBack&&!active&&!unavailable&&<button className="orbit-preview-link" type="button" onClick={onBack}>
       Открыть демонстрацию панели <ArrowUpRight size={16} aria-hidden="true"/>
      </button>}
      <p className="orbit-access-security"><LockKeyhole size={16} aria-hidden="true"/> Доступ контролируется сервером. Схема маршрута не подтверждает наличие сессии или прав.</p>
     </div>
    </div>
    <p className="orbit-right-foot">HERMES SECURITY / AUTH GATEWAY <span>V 2.0</span></p>
   </aside>
  </main>
  <footer className="orbit-auth-footer"><span>HERMES COMMAND CENTER</span><span>ORBIT / AUTH EXPERIENCE</span><span><Check size={13} aria-hidden="true"/> ПРИВАТНАЯ ПАНЕЛЬ</span></footer>
 </div>;
}
