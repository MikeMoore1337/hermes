export const statuses=Object.freeze({
active:{label:"Работает",tone:"good"},inactive:{label:"Неактивен",tone:"warn"},
failed:{label:"Сбой",tone:"bad"},unknown:{label:"Нет данных",tone:"unknown"},
blocked:{label:"Не допущен",tone:"warn"},unexpected_active:{label:"Запущен без допуска",tone:"bad"}
});
export const groups=Object.freeze({
all:{name:"Обзор",description:"Общее состояние инфраструктуры"},
ops:{name:"Наблюдение",description:"Ops Watch, отправитель и сетевая защита"},
research:{name:"Исследования",description:"Расписание Research Scout"},
qa:{name:"QA и CI",description:"Наблюдение за проверками качества"},
agent:{name:"AI Agent",description:"Ограниченный H-01 и полный AI Agent"},
codex:{name:"Лимиты AI",description:"Доступные квоты Codex"}});
export const groupUnits=Object.freeze({ops:["news","ops","alerts","network"],research:["research"],qa:["qa"],agent:["agent_bounded","agent"]});
export function validSnapshot(d,now=Date.now()){
 if(!d||d.schema!==1||d.mode!=="read_only"||!Array.isArray(d.services))return false;
 if(!d.services.every(s=>s&&typeof s.id==="string"&&typeof s.name==="string"&&typeof s.state==="string"&&typeof s.unit==="string"))return false;
 const date=Date.parse(d.generated_at);return Number.isFinite(date)&&date-now<=120000&&now-date<=180000;
}
export function counts(s){return {
active:s.filter(x=>x.state==="active").length,
attention:s.filter(x=>["failed","unknown","unexpected_active"].includes(x.state)).length,
blocked:s.filter(x=>x.state==="blocked").length,total:s.length};}
export function filterServices(s,view,q,status){
 const term=q.trim().toLocaleLowerCase("ru");
 return s.filter(x=>(view==="all"||(groupUnits[view]||[]).includes(x.id))&&(status==="all"||x.state===status)&&(!term||[x.name,x.unit,x.id].some(v=>v.toLocaleLowerCase("ru").includes(term))));}
