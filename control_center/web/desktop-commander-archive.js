/* On-demand legacy history only; never contacts remote Desktop Commander service. */
(()=>{"use strict";
const period=document.getElementById("period"),refresh=document.getElementById("refresh"),
 table=document.getElementById("observations"),message=document.getElementById("message");
const allowed=new Set(["monitored","exhausted","unknown","unavailable","auth_required"]);
function valid(data,days){
 if(!data||data.schema!==1||data.source!=="desktop_commander_remote_mcp"||
  data.days!==days||!["available","not_configured"].includes(data.status)||
  !Array.isArray(data.points)||data.points.length>500)return false;
 return data.points.every(p=>{
   const time=Date.parse(p?.at);
   return p && typeof p==="object" &&
    Object.keys(p).sort().join(",")==="at,offline,online,remaining_percent,status" &&
    Number.isFinite(time)&&allowed.has(p.status)&&
    (p.remaining_percent===null||(Number.isInteger(p.remaining_percent)&&p.remaining_percent>=0&&p.remaining_percent<=100))&&
    Number.isInteger(p.online)&&p.online>=0&&p.online<=16&&
    Number.isInteger(p.offline)&&p.offline>=0&&p.offline<=16;
 });
}
function el(tag,txt){const node=document.createElement(tag);node.textContent=txt;return node;}
async function load(){
 refresh.disabled=true;table.replaceChildren();message.textContent="Чтение архива…";
 try{
   const days=Number(period.value);
   if(![1,7,30].includes(days))throw Error("invalid period");
   const response=await fetch("/api/providers/desktop-commander/history?days="+days,
     {credentials:"same-origin",cache:"no-store"});
   if(!response.ok)throw Error("unavailable");
   const payload=await response.json();
   if(!valid(payload,days))throw Error("invalid archive");
   if(payload.points.length===0){message.textContent="История за выбранный период отсутствует.";return;}
   for(const p of payload.points.slice(-100).reverse()){
     const tr=document.createElement("tr");
     for(const text of [new Date(p.at).toLocaleString("ru-RU"),p.status,
       p.remaining_percent===null?"Не измерено":p.remaining_percent+"%",String(p.online),String(p.offline)])
        tr.append(el("td",text));
     table.append(tr);
   }
   message.textContent="Исторических наблюдений: "+payload.points.length+
     ". Показаны последние "+Math.min(100,payload.points.length)+".";
 }catch(_){table.replaceChildren();message.textContent="Архив недоступен. Данные не подменяются.";}
 finally{refresh.disabled=false;}
}
refresh.addEventListener("click",()=>void load());period.addEventListener("change",()=>void load());
void load();
})();