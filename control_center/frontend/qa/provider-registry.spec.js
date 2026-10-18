import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";
const evidence=resolve("../../docs/ux/evidence/h15-provider-registry");
const moment=new Date().toISOString();
const windows=(used,remaining,label)=>[{
  metric:"subscription_share",label,unit:"percent",quota_limit:null,
  used:null,remaining:null,used_percent:used,remaining_percent:remaining,
  reset_at_utc:new Date(Date.now()+3600_000).toISOString(),source_kind:"official_api"
}];
const data={schema:1,read_only:true,observed_at:moment,providers:[
 {id:"cloudflare_workers_ai",title:"Cloudflare Workers AI",status:"unknown",
  observed_at:null,notes:"account_usage_unavailable",source_kind:"unknown",
  limit_documentation:"https://developers.cloudflare.com/workers-ai/platform/pricing/",
  windows:[{metric:"neurons_daily",label:"Суточная квота Free",unit:"neurons",
    quota_limit:10000,used:null,remaining:null,used_percent:null,remaining_percent:null,
    reset_at_utc:new Date(Date.UTC(new Date().getUTCFullYear(),new Date().getUTCMonth(),new Date().getUTCDate()+1)).toISOString(),source_kind:"unknown"}]},
 {id:"codex",title:"Codex / ChatGPT",status:"low",observed_at:moment,
  notes:"official_account_snapshot",source_kind:"official_api",
  windows:windows(81,19,"300 мин")},
 {id:"desktop_commander",title:"Desktop Commander",status:"exhausted",
  observed_at:moment,notes:"remote_calls_blocked",source_kind:"local_meter",
  windows:[{...windows(100,0,"Удалённые вызовы")[0],source_kind:"local_meter"}]},
 {id:"github_api",title:"GitHub API",status:"unknown",observed_at:null,
  notes:"per_token_rate_limit_not_collected",source_kind:"unknown",windows:[]}
]};
async function setup(page){
 await page.route("**/api/overview",route=>route.fulfill({
   status:200,contentType:"application/json",
   body:JSON.stringify({schema:1,mode:"read_only",services:[],generated_at:moment})}));
 await page.route("**/api/providers/registry",route=>route.fulfill({
   status:200,contentType:"application/json",body:JSON.stringify(data)}));
 await page.route("**/api/providers/codex/history?*",route=>route.fulfill({
   status:200,contentType:"application/json",
   body:JSON.stringify({schema:1,samples:[
     {observed_at:new Date(Date.now()-600000).toISOString(),limits:[{windows:[{remaining_percent:70}]}]},
     {observed_at:new Date().toISOString(),limits:[{windows:[{remaining_percent:19}]}]}
   ]})}));
 await page.route("**/api/providers/desktop-commander/history?*",route=>route.fulfill({
   status:200,contentType:"application/json",body:JSON.stringify({schema:1,points:[
     {at:new Date(Date.now()-600000).toISOString(),remaining_percent:60},
     {at:new Date().toISOString(),remaining_percent:0}
   ]})}));
}
for(const width of [320,393,1440]){
 test("Separate provider cards without invented use, responsive "+width,async({page})=>{
   await page.setViewportSize({width,height:900});
   await setup(page);await page.goto("/");
   await page.getByRole("button",{name:"Квоты и инструменты"}).click();
   const region=page.getByRole("region",{name:"Квоты и инструменты Hermes"});
   await expect(region).toBeVisible();
   const cards=region.locator(".quota295-card");
   await expect(cards).toHaveCount(4);
   await expect(page.locator(".dc-toggle")).toBeHidden();
   const cloudflare=cards.nth(0),codex=cards.nth(1),desktop=cards.nth(2),github=cards.nth(3);
   await expect(cloudflare.getByRole("heading",{name:"Cloudflare Workers AI"})).toBeVisible();
   await expect(cloudflare.getByText("СЕРВИС / КВОТЫ")).toBeVisible();
   await expect(cloudflare.getByText("Последний замер квоты: отсутствует")).toBeVisible();
   await expect(codex.getByText(/Последний замер:/)).toBeVisible();
   await expect(cloudflare.getByText(/Billing Read даёт запаздывающие данные/)).toBeVisible();
   await expect(cloudflare.getByText(/Analytics Read доступен отдельно/)).toBeVisible();
   await expect(cloudflare.getByText(/точного остатка Free-квоты/)).toBeVisible();
   await expect(cloudflare.getByText(/требуется отдельный доступ Billing Read/)).toHaveCount(0);
   await expect(cloudflare.getByText(/Лимит:.*neurons/)).toBeVisible();
   await expect(cloudflare.getByText("Использовано: неизвестно", {exact:false})).toBeVisible();
   await expect(cloudflare.locator("[role=progressbar]")).toHaveCount(0);
   await expect(codex.getByText("Осталось: 19%")).toBeVisible();
   await expect(desktop.getByText("Осталось: 0%")).toBeVisible();
   await expect(desktop.getByText(/заблокированы/)).toBeVisible();
   await expect(github.getByText(/Общий остаток не измерен/)).toBeVisible();
   await expect(github.locator("[role=progressbar]")).toHaveCount(0);
   await codex.locator("summary").click();
   await expect(codex.locator(".quota295-chart polyline")).toHaveAttribute("points",/\d/);
   await desktop.locator("summary").click();
   await expect(desktop.locator(".quota295-chart polyline")).toHaveAttribute("points",/\d/);
   expect(await codex.locator(".quota295-chart polyline").getAttribute("points"))
    .not.toBe(await desktop.locator(".quota295-chart polyline").getAttribute("points"));
   expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false);
   mkdirSync(evidence,{recursive:true});
   await page.screenshot({path:resolve(evidence,"provider-cards-"+width+".png"),fullPage:true});
   await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
   await expect(region).toBeHidden();
 });
}

test("GitHub configured token has two separately measured history windows",async({page})=>{
  await page.setViewportSize({width:393,height:850});
  await setup(page);
  const current={...data,providers:data.providers.map(p=>p.id!=="github_api"?p:{
    ...p,status:"low",source_kind:"official_api",
    notes:"per_token_rate_limit_collected",observed_at:moment,
    windows:[{
      metric:"core",label:"API core",unit:"requests",
      quota_limit:5000,used:100,remaining:4900,
      used_percent:2,remaining_percent:98,reset_at_utc:moment,source_kind:"official_api"
    },{
      metric:"search",label:"API search",unit:"requests",
      quota_limit:30,used:29,remaining:1,
      used_percent:96.67,remaining_percent:3.33,
      reset_at_utc:moment,source_kind:"official_api"
    }]
  })};
  await page.route("**/api/providers/registry",route=>route.fulfill({
    status:200,contentType:"application/json",body:JSON.stringify(current)
  }));
  await page.route("**/api/providers/registry/history?*",route=>{
    const query=new URL(route.request().url()).searchParams;
    const resource=query.get("resource");
    return route.fulfill({status:200,contentType:"application/json",body:JSON.stringify({
      schema:1,resource,days:7,points:[
        {at:new Date(Date.now()-600000).toISOString(),
         remaining_percent:resource==="core"?90:55},
        {at:moment,remaining_percent:resource==="core"?98:3.33}
      ]
    })});
  });
  await page.goto("/");
  await page.getByRole("button",{name:"Квоты и инструменты"}).click();
  const github=page.locator('.quota295-card[data-provider="github_api"]');
  await expect(github.getByText(/Фактически использовано: 29/)).toBeVisible();
  await expect(github.locator("[role=progressbar]")).toHaveCount(2);
  await github.locator("summary").click();
  await expect(github.locator(".quota295-chart polyline")).toHaveAttribute("points",/\d/);
  const first=await github.locator(".quota295-chart polyline").getAttribute("points");
  await github.getByLabel("Отдельный ресурс GitHub API").selectOption("search");
  await expect(github.locator(".quota295-chart polyline")).not.toHaveAttribute("points",first);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false);
});

for(const width of [320,393,1440]){
 test("Cloudflare historical adaptive estimates never become Free quota "+width, async({page})=>{
   await page.setViewportSize({width,height:900});
   await setup(page);
   const previous={...data,providers:data.providers.map(p=>p.id!=="cloudflare_workers_ai"?p:{
     ...p,analytics_status:"historical_estimate",analytics_observed_at:moment,
     analytics_history:[{day:"2026-10-17",estimate_neurons:23.427,
       lower95_neurons:23.427,upper95_neurons:23.427,
       sample_size:2,quality:"very_small_sample"}]
   })};
   await page.route("**/api/providers/registry",route=>route.fulfill({
     status:200,contentType:"application/json",body:JSON.stringify(previous)
   }));
   await page.goto("/");
   await page.getByRole("button",{name:"Квоты и инструменты"}).click();
   const card=page.locator('.quota295-card[data-provider="cloudflare_workers_ai"]');
   await expect(card.getByText(/^Cloudflare Analytics за/)).toBeVisible();
   await expect(card.getByText(/очень маленькая выборка/).first()).toBeVisible();
   await expect(card.getByText(/Использовано: неизвестно/)).toBeVisible();
   await expect(card.getByText(/Осталось: неизвестно/)).toBeVisible();
   await expect(card.locator("[role=progressbar]")).toHaveCount(0);
   await card.getByText("История оценочных данных Cloudflare").click();
   await expect(card.getByText(/95% интервал 23,427 - 23,427/)).toBeVisible();
   expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false);
   mkdirSync(evidence,{recursive:true});
   await page.screenshot({path:resolve(evidence,"cloudflare-advisory-"+width+".png"),fullPage:true});
 });
}
