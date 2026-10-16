"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const labels = {active:"Работает",inactive:"Неактивен",failed:"Сбой",
    unknown:"Нет данных",blocked:"Не допущен",unexpected_active:"Запущен без допуска"};
  const pages = {
    all:["Обзор Hermes","Состояние агентов, автоматизаций и инфраструктуры из проверяемого снимка systemd."],
    ops:["Наблюдение и уведомления","Ops Watch, Telegram, новостной конвейер и сеть."],
    research:["Research Scout","Проверяем только расписание. Содержание исследований здесь не хранится."],
    qa:["QA и CI","Состояние наблюдателя CI без доступа к приватным журналам."],
    agent:["AI Agent","Запуск постоянного агента не разрешён до прохождения P0."]
  };
  const selected = {ops:["news","ops","alerts","network"],research:["research"],qa:["qa"],agent:["agent"]};
  let view = "all", snapshot = null;
  function div(cls,value,tag="div"){
    const el=document.createElement(tag);el.className=cls;
    if(value!==undefined)el.textContent=String(value);return el;
  }
  function draw(){
    $("view-title").textContent=pages[view][0];
    $("view-description").textContent=pages[view][1];
    $("breadcrumb").textContent=pages[view][0];
    for(const b of document.querySelectorAll("[data-view]")){
      b.classList.toggle("selected",b.dataset.view===view);
      if(b.dataset.view===view)b.setAttribute("aria-current","page");
      else b.removeAttribute("aria-current");
    }
    const list=$("service-list");list.replaceChildren();
    if(!snapshot){
      list.append(div("placeholder","Снимок состояния пока недоступен.","p"));
      ["working","attention","checked"].forEach(x=>$(x).textContent="-");
      $("count-chip").textContent="Нет данных";return;
    }
    const svcs=view==="all"?snapshot.services:snapshot.services.filter(s=>(selected[view]||[]).includes(s.id));
    $("working").textContent=snapshot.services.filter(x=>x.state==="active").length;
    $("attention").textContent=snapshot.services.filter(x=>["failed","unknown","unexpected_active"].includes(x.state)).length;
    $("checked").textContent=snapshot.services.length;
    $("count-chip").textContent=svcs.length+" компонентов";
    for(const svc of svcs){
      const row=div("service-item");
      const icon=div("service-symbol",svc.id==="agent"?"◎":"◈");icon.setAttribute("aria-hidden","true");
      const body=div("");body.append(div("service-name",svc.name),div("service-unit",svc.unit));
      row.append(icon,body,div("status "+(labels[svc.state]?svc.state:"unknown"),labels[svc.state]||labels.unknown));
      list.append(row);
    }
    if(!svcs.length)list.append(div("placeholder","Здесь пока нет компонентов.","p"));
  }
  async function refresh(){
    $("refresh").disabled=true;$("feedback").textContent="";
    try{
      const res=await fetch("/api/overview",{cache:"no-store",credentials:"same-origin"});
      if(!res.ok)throw Error("Unavailable");
      const data=await res.json();
      if(data.schema!==1||data.mode!=="read_only"||!Array.isArray(data.services))throw Error("Invalid snapshot");
      snapshot=data;
      const timestamp=Date.parse(data.generated_at);
      $("last-updated").textContent="Снимок: "+(Number.isFinite(timestamp)?new Date(timestamp).toLocaleString("ru-RU"):"неизвестно");
      if(!Number.isFinite(timestamp)||timestamp-Date.now()>120000||Date.now()-timestamp>180000)
        $("feedback").textContent="Внимание: снимок устарел или часы сервера не синхронизированы.";
    }catch(error){
      snapshot=null;$("last-updated").textContent="Данные недоступны";
      $("feedback").textContent="Нет проверенного снимка. Проверьте службу сбора состояния.";
    }finally{$("refresh").disabled=false;draw();}
  }
  document.querySelectorAll("[data-view]").forEach(b=>b.addEventListener("click",()=>{view=b.dataset.view;draw();}));
  $("refresh").addEventListener("click",refresh);
  setInterval(()=>{if(!document.hidden)refresh();},60000);
  refresh();
})();
