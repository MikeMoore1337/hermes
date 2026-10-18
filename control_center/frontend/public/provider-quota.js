/* #295: one independent read-only quota card per actually identified service. */
(() => {
  "use strict";
  const ids = ["cloudflare_workers_ai", "codex", "desktop_commander", "github_api"];
  const labels = {cloudflare_workers_ai: "Cloudflare Workers AI", codex: "Codex / ChatGPT",
    desktop_commander: "Desktop Commander", github_api: "GitHub API"};
  const stateText = {ok: "Доступно", low: "Квота на исходе",
    exhausted: "Квота исчерпана", throttled: "Ограничено",
    auth_required: "Нужна авторизация", stale: "Данные устарели",
    unknown: "Нет подтверждённых данных", not_connected: "Не подключено"};
  const noteText = {account_usage_unavailable: "10 000 Neurons в сутки - документированный предел Free. Фактическое потребление аккаунта неизвестно.",
    official_account_snapshot: "Показатели из официального локального снимка Codex. Запросы моделей не выполняются.",
    official_delayed_historical_usage: "Cloudflare публикует исторические Neurons с задержкой. Текущие использовано/остаток всё ещё неизвестны.",
    billing_auth_required: "Исторический учёт недоступен: токен Cloudflare не имеет подтверждённого Billing Read. Суточная квота AI отдельно.",
    billing_throttled: "Обращения к отчётности Cloudflare ограничены. Текущий остаток Neurons неизвестен.",
    provider_limit_exhausted: "Поставщик сообщил об исчерпании лимита.",
    some_windows_exhausted: "Часть независимых окон квоты недоступна.",
    reauthorization_required: "Требуется повторная авторизация аккаунта.",
    snapshot_stale: "Результаты устарели. Исторические значения не считаются доступной квотой.",
    remote_calls_blocked: "Облачные удалённые команды заблокированы даже при подключённых устройствах.",
    device_presence_not_execution_permission: "Подключение устройств не подтверждает право на удалённые команды.",
    per_token_rate_limit_not_collected: "GitHub имеет отдельные лимиты для каждого токена и типа API. Общий остаток не измерен.",
    per_token_rate_limit_collected: "Показаны только лимиты отдельного настроенного токена GitHub. Это не общий лимит аккаунта и не квота CI.",
    provider_throttled: "Поставщик ограничил запросы. Не считать эту ошибку исчерпанием всех лимитов.",
    usage_not_exposed: "Поставщик не предоставляет проверенную квоту этому источнику.",
    usage_unavailable: "Невозможно подтвердить текущую квоту.",
    not_configured: "Источник квот ещё не настроен."};
  let tab, section, grid, active = false, busy = false, data = null;
  function add(tag, cls, parent, value) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (value !== undefined) e.textContent = String(value);
    if (parent) parent.append(e);
    return e;
  }
  const percent = n => typeof n === "number" && Number.isFinite(n) && 0 <= n && n <= 100 ? n : null;
  const readable = n => typeof n === "number" && Number.isFinite(n) ?
    n.toLocaleString("ru-RU", {maximumFractionDigits: 2}) : "Нет данных";
  const time = s => {const t = Date.parse(s);return Number.isFinite(t) ?
    new Date(t).toLocaleString("ru-RU", {dateStyle:"short",timeStyle:"short"}) : "Нет данных";};
  function usage(root, w) {
    const box = add("div", "quota295-window", root);
    add("strong", "", box, w.label || w.metric || "Окно квоты");
    if (w.quota_limit !== null && w.quota_limit !== undefined)
      add("p", "", box, "Лимит: " + readable(w.quota_limit) + " " + w.unit);
    if (w.used !== null && w.used !== undefined && w.remaining !== null && w.remaining !== undefined)
      add("p","quota295-note",box,
        "Фактически использовано: " + readable(w.used) + " · Осталось: " +
        readable(w.remaining) + " " + w.unit);
    const remainder = w.remaining_percent;
    const used = w.used_percent;
    if (percent(remainder) !== null && percent(used) !== null) {
      const labels = add("div", "quota295-values", box);
      add("span", "", labels, "Использовано: " + readable(used) + "%");
      add("strong", "", labels, "Осталось: " + readable(remainder) + "%");
      const bar = add("div", "quota295-track", box);
      bar.setAttribute("role", "progressbar");bar.setAttribute("aria-label",w.label||"Окно квоты");
      bar.setAttribute("aria-valuemin","0");bar.setAttribute("aria-valuemax","100");
      bar.setAttribute("aria-valuenow",String(used));
      const fill = add("div", "quota295-fill", bar);
      fill.style.width = used + "%";
      if (used >= 95) fill.classList.add("quota295-critical");
      else if (used >= 80) fill.classList.add("quota295-warning");
    } else {
      add("p", "quota295-note", box, "Использовано: неизвестно · Осталось: неизвестно");
    }
    add("small", "quota295-note", box, "Сброс: " +
      (w.reset_at_utc ? time(w.reset_at_utc) : "Не подтверждён"));
    add("small", "quota295-note", box,
      "Источник расхода: " + (w.source_kind === "official_api" ? "официальный API" :
      w.source_kind === "local_meter" ? "отчёт поставщика через локальный сборщик" :
      "нет подтверждённых измерений"));
  }
  function draw(root, points) {
    root.replaceChildren();
    if (!points.length) {
      add("p", "quota295-note", root, "За этот период нет подтверждённых измерений.");
      return;
    }
    const samples = points.filter(x => percent(x.value) !== null && Number.isFinite(Date.parse(x.at)))
      .sort((a,b) => Date.parse(a.at) - Date.parse(b.at));
    if (!samples.length) return add("p", "quota295-note", root, "История квоты недоступна.");
    const sampled = samples.filter((_,i) => i % Math.max(1, Math.ceil(samples.length / 150)) === 0);
    if (sampled[sampled.length-1] !== samples[samples.length-1])
      sampled.push(samples[samples.length-1]);
    const svg = document.createElementNS("http://www.w3.org/2000/svg","svg");
    svg.setAttribute("viewBox","0 0 320 110");svg.setAttribute("role","img");
    svg.setAttribute("aria-label","Наблюдавшийся остаток квоты в процентах");
    const from=Date.parse(sampled[0].at),until=Date.parse(sampled[sampled.length-1].at);
    const path=document.createElementNS("http://www.w3.org/2000/svg","polyline");
    path.setAttribute("stroke","#76a5ed");path.setAttribute("stroke-width","2");path.setAttribute("fill","none");
    path.setAttribute("points",sampled.map(p => {
      const t=Date.parse(p.at);
      return (8+(until>from?(t-from)/(until-from):.5)*304).toFixed(1)+","+(100-.85*p.value).toFixed(1);
    }).join(" "));
    svg.append(path);
    if(sampled.length===1 || from===until){
      const dot=document.createElementNS("http://www.w3.org/2000/svg","circle");
      dot.setAttribute("cx","160");dot.setAttribute("cy",String(100-.85*sampled[0].value));
      dot.setAttribute("r","3");dot.setAttribute("fill","#76a5ed");svg.append(dot);
    }
    root.append(svg);
    add("small", "quota295-note", root,
      "Подтверждённых точек: "+samples.length+". Последняя: "+time(samples[samples.length-1].at));
  }
  async function history(id,days,target) {
    target.replaceChildren(add("p","quota295-note",null,"Загрузка истории…"));
    const path=id==="codex"?"/api/providers/codex/history?days=":
      "/api/providers/desktop-commander/history?days=";
    try {
      const r=await fetch(path+days,{cache:"no-store",credentials:"same-origin"});
      if(!r.ok)throw Error("history unavailable");
      const payload=await r.json();
      if(payload.schema!==1)throw Error("invalid schema");
      const raw=id==="codex"?(payload.samples||[]).map(item=>({
        at:item.observed_at,value:item.limits?.[0]?.windows?.[0]?.remaining_percent
      })):(payload.points||[]).map(item=>({at:item.at,value:item.remaining_percent}));
      draw(target,raw);
    } catch(_){
      target.replaceChildren(add("p","quota295-note",null,"История этого поставщика недоступна."));
    }
  }
  function card(root,service) {
    const article=add("article","quota295-card",root);
    article.setAttribute("data-provider",service.id);
    const header=add("div","quota295-card-head",article);
    const name=add("div","",header);
    add("span","eyebrow",name,"ПОДКЛЮЧЁННЫЕ СЕРВИСЫ / КВОТЫ");
    add("h3","",name,labels[service.id]);
    add("span","quota295-status quota295-"+service.status,header,
      stateText[service.status]||"Нет подтверждённых данных");
    add("p","quota295-note",article,noteText[service.notes]||"Нет подтверждённых измерений.");
    const windows=Array.isArray(service.windows)?service.windows:[];
    if(windows.length){
      const box=add("div","quota295-windows",article);
      for(const w of windows.slice(0,48))usage(box,w);
    } else add("p","quota295-empty",article,"Доступные квотные окна: нет данных");
    add("small","quota295-timestamp",article,
      "Последний замер: "+(service.observed_at?time(service.observed_at):"отсутствует"));
    const src=service.source_kind==="official_api"?"официальный API":
      service.source_kind==="local_meter"?"локальный отчёт поставщика":"источник расхода не подтверждён";
    add("small","quota295-note",article,"Достоверность: "+src);
    if(service.id==="cloudflare_workers_ai" && service.limit_documentation){
      const link=add("a","quota295-link",article,"Документация квот Cloudflare");
      link.href="https://developers.cloudflare.com/workers-ai/platform/pricing/";
      link.target="_blank";link.rel="noopener noreferrer";
    }
    if(service.id==="cloudflare_workers_ai"){
      const billing = Array.isArray(service.billing_history) ? service.billing_history : [];
      if(billing.length){
        const previous = billing[billing.length - 1];
        add("p","quota295-note",article,
          "Официальный учёт за завершённые сутки " + previous.day + ": " +
          readable(previous.neurons) + " Neurons. Данные обновляются с задержкой; это НЕ сегодняшнее потребление.");
        const detail=add("details","quota295-history",article);
        add("summary","",detail,"История официального учёта (с задержкой)");
        const chart=add("div","quota295-chart",detail);
        add("p","quota295-note",chart,"Опубликованные данные по завершённым UTC-суткам. Никаких прогнозов остатка.");
        for(const point of billing.slice(-30)){
          add("p","quota295-note",chart,point.day + ": " + readable(point.neurons) + " Neurons");
        }
      }else add("p","quota295-note",article,
          "Официальный исторический учёт пока недоступен (требуется отдельный доступ Billing Read).");
    }
    if(service.id==="codex"||service.id==="desktop_commander"){
      const details=add("details","quota295-history",article);
      add("summary","",details,"История собственной квоты");
      const period=add("select","",details);
      period.setAttribute("aria-label","Период истории "+labels[service.id]);
      for(const [day,title] of [["1","24 часа"],["7","7 дней"],["30","30 дней"]]){
        const option=add("option","",period,title);option.value=day;if(day==="7")option.selected=true;
      }
      const chart=add("div","quota295-chart",details);
      const refresh=()=>history(service.id,period.value,chart);
      details.addEventListener("toggle",()=>{if(details.open)refresh();});
      period.addEventListener("change",()=>{if(details.open)refresh();});
    }else if(service.id!=="cloudflare_workers_ai"){
      add("p","quota295-note",article,"История расхода ещё не подключена. Никаких расчётных точек.");
    }
  }
  function render(){
    if(!grid)return;
    grid.replaceChildren();
    if(!data||!Array.isArray(data.providers))
      return add("p","quota295-note",grid,"Реестр квот недоступен.");
    for(const id of ids){
      const item=data.providers.find(x=>x.id===id);
      card(grid,item||{id,status:"not_connected",windows:[],notes:"not_configured",observed_at:null});
    }
  }
  async function refresh(){
    if(!grid||busy)return;
    busy=true;
    try{
      const response=await fetch("/api/providers/registry",{cache:"no-store",credentials:"same-origin"});
      if(!response.ok)throw Error("endpoint");
      const payload=await response.json();
      if(payload.schema!==1||payload.read_only!==true)throw Error("contract");
      data=payload;
    }catch(_){data=null;}
    finally{busy=false;render();}
  }
  function hide(){
    active=false;document.documentElement.classList.remove("quota295-active");
    if(section)section.hidden=true;
    if(tab){tab.classList.remove("is-active");tab.removeAttribute("aria-current");}
  }
  function show(){
    active=true;document.documentElement.classList.add("quota295-active");
    section.hidden=false;tab.classList.add("is-active");tab.setAttribute("aria-current","page");
    refresh();
  }
  function mount(){
    const nav=document.querySelector(".atlas-section-nav .nav-list");
    const target=document.querySelector(".center-area");
    if(!nav||!target)return;
    if(!tab||!tab.isConnected){
      tab=add("button","nav-link quota295-nav",nav);tab.type="button";
      add("span","nav-number",tab,"09");add("span","",tab,"Квоты и инструменты");
      tab.onclick=show;
    }
    if(!section||!section.isConnected){
      section=add("section","quota295-panel",target);
      section.hidden=!active;section.setAttribute("aria-label","Квоты и инструменты Hermes");
      const head=add("div","quota295-head",section);
      const title=add("div","",head);
      add("span","eyebrow",title,"H-15 / #295");
      add("h2","",title,"Ресурсы AI и инструменты");
      add("p","quota295-note",title,
        "Каждому сервису - отдельная карточка. Неизвестное потребление не равно нулю.");
      const button=add("button","quota295-reload",head,"Обновить");button.type="button";button.onclick=refresh;
      grid=add("div","quota295-grid",section);
      render();
    }
  }
  document.addEventListener("click",event=>{
    if(active && event.target.closest(".nav-link:not(.quota295-nav),.atlas-nav button"))hide();
  },true);
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",mount,{once:true});
  else mount();
  new MutationObserver(mount).observe(document.body,{childList:true,subtree:true});
  window.setInterval(()=>{if(active&&!document.hidden)refresh();},60000);
})();
