import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";

test.use({serviceWorkers:"block"});
const screenshots=resolve(".artifacts/468");
mkdirSync(screenshots,{recursive:true});

function inbox(events=[],sources=null){
 const available=sources||{
  systemd:{status:"SUPPORTED",label:"Службы и Ops Watch",details:"Снимок systemd"},
  scheduler:{status:"PARTIAL",label:"Планировщик задач",details:"Счётчики без квитанций"},
  brc:{status:"NOT_AVAILABLE",label:"Hermes BRC",details:"Нет подключённого источника"},
  delivery:{status:"NOT_AVAILABLE",label:"Подтверждение доставки",details:"Нет отдельной квитанции"},
  ops_incidents:{status:"NOT_AVAILABLE",label:"События Ops Watch",details:"Журнал недоступен"}
 };
 return {schema:1,mode:"read_only",actions_enabled:false,completeness:"PARTIAL",
  generated_at:new Date().toISOString(),events,sources:available,
  summary:{total:events.length,critical:events.filter(x=>x.severity==="critical").length,
   review:events.filter(x=>x.category==="needs_review").length,
   blocked:events.filter(x=>x.category==="blocked").length,
   available_sources:Object.values(available).filter(x=>["SUPPORTED","PARTIAL"].includes(x.status)).length,
   source_count:Object.keys(available).length},
  note:"Отсутствие событий не доказывает отсутствие неисправностей."};
}
const incidents=[
 {source:"systemd",event_id:"systemd:ops",status:"failure",category:"failure",
  severity:"critical",title:"Ops Watch",detail:"Наблюдаемое состояние: failed",
  observed_at:new Date().toISOString(),last_verified_at:new Date().toISOString(),
  action_hint:"Проверить состояние службы в реестре; запуск недоступен.",
  evidence_link:"/api/overview",scope:"owner_read_only"},
 {source:"scheduler",event_id:"scheduler:blocked",status:"blocked",category:"blocked",
  severity:"warning",title:"Заблокированные задания",detail:"Заданий: 2. Время отдельных задач не подтверждено.",
  observed_at:null,last_verified_at:null,action_hint:"Проверить причину блокировки в планировщике.",
  evidence_link:"/api/codex/tasks",scope:"owner_read_only"},
 {source:"systemd",event_id:"systemd:qa",status:"needs_review",category:"needs_review",
  severity:"warning",title:"QA Advisor",detail:"Наблюдаемое состояние: unknown",
  observed_at:new Date().toISOString(),last_verified_at:new Date().toISOString(),
  action_hint:"Проверить состояние службы в реестре.",
  evidence_link:"/api/overview",scope:"owner_read_only"}
];
async function safeSynthetic(page,response=inbox(incidents),status=200){
 const violations=[];
 await page.route("**/*",route=>{
  const req=route.request(),url=new URL(req.url());
  const local=url.hostname==="127.0.0.1"&&url.port==="9133";
  if(!local||url.pathname.startsWith("/auth/")){
   violations.push(local?"oauth":"external");return route.abort("blockedbyclient");
  }
  if(url.pathname==="/api/operator/inbox"){
   if(req.method()!=="GET"){violations.push("mutation");return route.abort("blockedbyclient");}
   return route.fulfill({status,contentType:"application/json",
                        body:status===200?JSON.stringify(response):'{"error":"synthetic_unavailable"}'});
  }
  if(url.pathname==="/api/overview"){
   return route.fulfill({status:200,contentType:"application/json",
    body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),
    services:[],agent_policy:"Mock-only"})});
  }
  if(url.pathname.startsWith("/api/")){
   // Optional existing dashboard widgets have no synthetic evidence here.
   return route.fulfill({status:503,contentType:"application/json",
                         body:'{"error":"synthetic_not_available"}'});
  }
  return route.continue();
 });
 return violations;
}
async function openInbox(page){
 await page.goto("/");
 // Navigation is part of existing authenticated Atlas app.
 await page.getByRole("button",{name:"Operator Inbox"}).first().click();
 await expect(page.getByRole("heading",{name:"Operator Inbox"})).toBeVisible();
}
async function noOverflow(page,width){
 const actual=await page.evaluate(()=>document.documentElement.scrollWidth);
 expect(actual,`No horizontal overflow at ${width}px`).toBeLessThanOrEqual(width+1);
}
for(const width of [320,393,768,1440]){
 test(`approved mixed Atlas Operator Inbox, ${width}px and read-only evidence`,async({page})=>{
  await page.setViewportSize({width,height:width<768?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  const leaks=await safeSynthetic(page);
  await openInbox(page);
  await expect(page.getByRole("region",{name:"Общая сводка"})).toBeVisible();
  await expect(page.getByRole("heading",{name:"Источники данных"})).toBeVisible();
  await expect(page.getByRole("button",{name:/Ops Watch/}).last()).toBeVisible();
  await expect(page.getByText("Нет данных",{exact:true}).first()).toBeVisible();
  await expect(page.getByRole("link",{name:/Открыть исходные сведения/})).toHaveAttribute("href","/api/overview");
  await page.getByRole("button",{name:"Заблокировано"}).click();
  await expect(page.getByRole("button",{name:/Заблокированные задания/})).toBeVisible();
  await expect(page.getByRole("button",{name:/Ops Watch/})).toHaveCount(0);
  await page.getByRole("button",{name:"Все"}).click();
  await page.getByRole("textbox",{name:"Поиск событий"}).fill("QA Advisor");
  await expect(page.getByRole("button",{name:/QA Advisor/})).toBeVisible();
  await noOverflow(page,width);
  await page.getByRole("textbox",{name:"Поиск событий"}).fill("");
  await page.screenshot({path:resolve(screenshots,`inbox-${width}.png`),fullPage:true,animations:"disabled"});
  expect(leaks).toEqual([]);
 });
}
test("stale/missing coverage does not render a healthy claim",async({page})=>{
 await page.setViewportSize({width:393,height:844});
 const stale=inbox([],{
  systemd:{status:"STALE",label:"Службы и Ops Watch",details:"Снимок устарел"},
  brc:{status:"NOT_AVAILABLE",label:"Hermes BRC",details:"Нет данных"},
  delivery:{status:"NOT_AVAILABLE",label:"Доставка",details:"Нет доказательств"}
 });
 const leaks=await safeSynthetic(page,stale);
 await openInbox(page);
 await expect(page.getByText("Нет подтверждённых сигналов")).toBeVisible();
 await expect(page.getByText(/Нулевая очередь не гарантирует/)).toBeVisible();
 await expect(page.getByText("Устарел")).toBeVisible();
 await page.screenshot({path:resolve(screenshots,"inbox-empty-stale-393.png"),fullPage:true});
 expect(leaks).toEqual([]);
});
test("API 503 shows error and never stale data as healthy",async({page})=>{
 await page.setViewportSize({width:393,height:844});
 const leaks=await safeSynthetic(page,inbox(incidents),503);
 await openInbox(page);
 await expect(page.getByRole("alert")).toContainText("Не удалось загрузить очередь");
 await expect(page.getByRole("button",{name:/Ops Watch/})).toHaveCount(0);
 await page.screenshot({path:resolve(screenshots,"inbox-error-393.png"),fullPage:true});
 expect(leaks).toEqual([]);
});
test("keyboard access and evidence links do not mutate state",async({page})=>{
 const leaks=await safeSynthetic(page);
 await openInbox(page);
 await page.getByRole("button",{name:/QA Advisor/}).click();
 await expect(page.getByRole("heading",{name:"QA Advisor"})).toBeVisible();
 await expect(page.getByText("Просмотр ничего не запускает")).toBeVisible();
 await page.getByRole("button",{name:"Заблокировано"}).focus();
 await page.keyboard.press("Enter");
 await expect(page.getByRole("button",{name:/Заблокированные задания/})).toBeVisible();
 expect(leaks).toEqual([]);
});
