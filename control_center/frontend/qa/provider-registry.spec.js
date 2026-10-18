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
    reset_at_utc:new Date(Date.now()+8*3600_000).toISOString(),source_kind:"unknown"}]},
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
   body:JSON.stringify({schema:1,services:[],generated_at:moment})}));
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
   const cloudflare=cards.nth(0),codex=cards.nth(1),desktop=cards.nth(2),github=cards.nth(3);
   await expect(cloudflare.getByRole("heading",{name:"Cloudflare Workers AI"})).toBeVisible();
   await expect(cloudflare.getByText("Лимит: 10 000 neurons")).toBeVisible();
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
