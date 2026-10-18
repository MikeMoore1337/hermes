/* #272: additive read-only Atlas panel, no model requests or shared secrets. */
(() => {
"use strict";
let button, panel, data=null, period="7d", selectedProject="all", selectedModel="all", activity="tokens", active=false;
const fmt=x=>x==null?"Нет данных":Number(x).toLocaleString("ru-RU",{maximumFractionDigits:1});
const cash=x=>x==null?"Нет данных":"$"+Number(x).toLocaleString("ru-RU",{minimumFractionDigits:2,maximumFractionDigits:4});
const safe=x=>typeof x==="string"?x:"";
function el(tag,cls,parent,text){
 const e=document.createElement(tag);if(cls)e.className=cls;
 if(text!==undefined)e.textContent=String(text);if(parent)parent.append(e);return e;
}
function choices(root,values,current,fn){
 root.replaceChildren();
 for(const [value,label] of values){const o=el("option","",root,label);o.value=value;}
 root.value=current;root.onchange=e=>fn(e.target.value);
}
function metric(root,title,value,sub){
 const x=el("div","ai272-metric",root);
 el("small","",x,title);el("strong","",x,value);el("span","",x,sub);
}
function bar(root,name,value,max,extra){
 const r=el("div","ai272-row",root);
 el("span","",r,name);el("strong","",r,fmt(value));
 const track=el("div","ai272-track",r);
 const fill=el("div","ai272-fill",track);
 fill.style.width=String(max>0?Math.max(0,Math.min(100,100*value/max)):0)+"%";
 if(extra)el("small","",r,extra);
}
function draw(){
 if(!panel)return;
 const summary=panel.querySelector("[data-summary]");
 const chart=panel.querySelector("[data-chart]");
 const breakdown=panel.querySelector("[data-breakdown]");
 const source=panel.querySelector("[data-source]");
 [summary,chart,breakdown,source].forEach(x=>x.replaceChildren());
 if(!data){
  panel.querySelector("[data-status]").textContent="Нет данных";
  el("p","ai272-hint",summary,"Фактическая телеметрия Codex ещё не доступна. Демонстрационные значения не показываются.");
  return;
 }
 const t=data.tokens||{};
 panel.querySelector("[data-status]").textContent=({verified:"Подтверждено",partial:"Частично",unknown:"Неизвестно",estimated:"Оценка"})[data.quality]||"Нет данных";
 for(const [name,value,sub] of [
 ["Токенов",fmt(t.total),"Вход / выход / кеш"],
 ["Сессий",fmt(data.sessions),"Только обнаруженные"],
 ["Завершено циклов",fmt(data.completed_turns),"Не равно задачам Scheduler"],
 ["Активное время",data.duration_seconds==null?"Нет данных":fmt(Math.round(data.duration_seconds/60))+" мин","С перекрытием интервалов"],
 ["API-эквивалент",cash(data.api_equivalent_usd),"Расчёт по фиксированным тарифам"],
 ["Фактические списания","Нет данных","Нет проверенных данных подписки"]
 ])metric(summary,name,value,sub);
 const projects=(data.projects||[]).map(x=>x.name);
 const models=(data.models||[]).map(x=>x.name);
 if(!projects.includes(selectedProject))selectedProject="all";
 if(!models.includes(selectedModel))selectedModel="all";
 choices(panel.querySelector("[data-project]"),[["all","Все проекты"]].concat(projects.map(x=>[x,x])),selectedProject,v=>{selectedProject=v;draw();});
 choices(panel.querySelector("[data-model]"),[["all","Все модели"]].concat(models.map(x=>[x,x])),selectedModel,v=>{selectedModel=v;draw();});
 el("h3","",chart,activity==="tokens"?"Динамика токенов":"Наблюдаемая активность");
 if(activity==="tokens"){
  const items=data.daily||[];
  if(!items.length)el("p","ai272-hint",chart,"За этот период нет наблюдений.");
  const peak=Math.max(1,...items.map(x=>x.input+x.output));
  items.forEach(x=>bar(chart,x.date,x.input+x.output,peak,
   "Вход: "+fmt(x.input)+" · Выход: "+fmt(x.output)+" · Кеш: "+fmt(x.cached)));
 }else{
  if(Number.isSafeInteger(data.completed_turns)&&data.completed_turns>=0)
   bar(chart,"Завершённые циклы",data.completed_turns,Math.max(1,data.completed_turns));
  else el("p","ai272-hint",chart,"Число завершённых циклов неизвестно.");
  el("p","ai272-hint",chart,"Активность рассчитывается по завершённым интервалам. Отсутствие событий не считается простоем.");
 }
 if(selectedProject!=="all"||selectedModel!=="all")
  el("p","ai272-hint",chart,"Дневной график показывает весь период; фильтры действуют на распределения.");
 el("h3","",breakdown,"Модели и проекты");
 for(const [name,records,selected] of [["Модели",data.models||[],selectedModel],["Проекты",data.projects||[],selectedProject]]){
  const group=el("div","ai272-group",breakdown);el("h4","",group,name);
  const entries=records.filter(x=>selected==="all"||x.name===selected).slice(0,15);
  if(!entries.length)el("p","ai272-hint",group,"Атрибуция недоступна.");
  const peak=Math.max(1,...entries.map(x=>x.input+x.output));
  entries.forEach(x=>bar(group,x.name,x.input+x.output,peak));
 }
 el("p","ai272-hint",source,"Источник: "+safe(data.source)+" · последний сбор: "+
  (data.observed_at?new Date(data.observed_at).toLocaleString("ru-RU"):"неизвестно"));
 el("p","ai272-hint",source,"Качество: "+safe(data.quality)+" · тариф: "+safe(data.price_version)+
  " · покрытие: "+(data.pricing_coverage==null?"неизвестно":Math.round(data.pricing_coverage*100)+"%"));
 el("p","ai272-hint",source,"Повреждено/пропущено: "+fmt(data.invalid_events)+
  " · незавершённых файлов: "+fmt(data.incomplete_files)+
  " · привязка к задачам: unattributed");
}
async function refresh(){
 if(!panel)return;
 panel.setAttribute("aria-busy", "true");
 panel.querySelector("[data-status]").textContent="Обновление…";
 try{
  const res=await fetch("/api/analytics/codex?period="+period,{credentials:"same-origin",cache:"no-store"});
  if(!res.ok)throw Error("HTTP");
  const json=await res.json();
  if(json.schema!==1||json.source!=="codex-local-rollout-jsonl")throw Error("schema");
  data=json;draw();
 }catch(_){data=null;draw();panel.querySelector("[data-status]").textContent="Недоступно";}
 finally{panel.removeAttribute("aria-busy");}
}
function hide(){
 active=false;document.documentElement.classList.remove("ai272-active");
 if(button){button.classList.remove("is-active");button.removeAttribute("aria-current");}
 if(panel)panel.hidden=true;
}
function show(){
 active=true;document.documentElement.classList.add("ai272-active");
 button.classList.add("is-active");button.setAttribute("aria-current","page");
 panel.hidden=false;refresh();
}
function mount(){
 const nav=document.querySelector(".atlas-section-nav .nav-list");
 const target=document.querySelector(".center-area");
 if(!nav||!target)return;
 if(!button||!button.isConnected){
  button=el("button","nav-link ai272-nav",nav);
  button.type="button";button.setAttribute("aria-label","AI Usage Analytics");
  el("span","nav-number",button,"07");el("span","",button,"AI Usage Analytics");
  button.onclick=show;
 }
 if(!panel||!panel.isConnected){
  panel=el("section","ai272-panel",target);
  panel.setAttribute("aria-label","AI Usage Analytics");
  panel.hidden=!active;
  panel.innerHTML=[
   '<div class="ai272-head"><div><span class="eyebrow">H-15 / #272 / CODEX</span>',
   '<h2>AI Usage Analytics</h2><p>Фактическая активность моделей и ориентировочная стоимость</p></div>',
   '<span data-status class="ai272-status" role="status" aria-atomic="true">Нет данных</span></div>',
   '<div class="ai272-controls"><label>Период <select data-period></select></label>',
   '<label>Проект <select data-project></select></label>',
   '<label>Модель <select data-model></select></label>',
   '<label>Показатель <select data-activity></select></label>',
   '<button type="button" data-reload>Обновить</button></div>',
   '<div class="ai272-summary" data-summary></div>',
   '<div class="ai272-body"><div data-chart class="ai272-chart"></div>',
   '<div data-breakdown class="ai272-breakdown"></div></div>',
   '<div data-source class="ai272-source"></div>'
  ].join("");
  choices(panel.querySelector("[data-period]"),[["24h","24 ч"],["7d","7 дней"],["30d","30 дней"],["all","Всё время"]],period,v=>{period=v;refresh();});
  choices(panel.querySelector("[data-activity]"),[["tokens","Токены"],["cycles","Циклы"]],activity,v=>{activity=v;draw();});
  panel.querySelector("[data-reload]").onclick=refresh;
  draw();
 }
}
document.addEventListener("click",e=>{
 if(active&&e.target.closest(".nav-link:not(.ai272-nav),.atlas-nav button"))hide();
},true);
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",mount,{once:true});
else mount();
new MutationObserver(mount).observe(document.body,{subtree:true,childList:true});
})();
