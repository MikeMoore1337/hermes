import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";

const evidence=resolve("../../docs/ux/evidence/h15-codex-usage");
const services=[{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",kind:"schedule",state:"active"}];

function setup(page,status="low"){
 page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services})}));
 page.route("**/api/providers/codex/history?*",route=>{
  const now=Date.now();
  const samples=[20,35,55,70].map((remaining,i)=>({
   observed_at:new Date(now-(3-i)*5400000).toISOString(),
   status:"available",ordinary_usage_allowed:true,
   limits:[{limit_id:"codex",windows:[{remaining_percent:remaining,duration_minutes:300}]}],
  }));
  return route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify({schema:1,samples,transitions:[{
    observed_at:new Date(now-5400000).toISOString(),previous:"low",current:"available",
   }],last_successful_at:new Date(now).toISOString()})});
 });
 page.route("**/api/providers/codex/policy?*",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({decision:"DEFER",reason:"warning_threshold",threshold_percent:20}),
 }));
 page.route("**/api/providers/codex",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,source:"codex-app-server",status,
   observed_at:new Date().toISOString(),ordinary_usage_allowed:true,
   limits:status==="not_configured"?[]:[{limit_id:"codex",status:"low",windows:[
    {used_percent:42,remaining_percent:58,duration_minutes:300,resets_at:1792240000},
    {used_percent:85,remaining_percent:15,duration_minutes:10080,resets_at:1792540000},
   ]}]})}));
}

for(const width of [393,1440]){
 test("Codex interactive quota panel responsive "+width,async({page})=>{
  await page.setViewportSize({width,height:900});
  setup(page);
  await page.goto("/");
  const sectionNav=page.locator(".atlas-section-nav");
  await sectionNav.getByRole("button",{name:"Лимиты AI"}).click();
  await expect(page.getByRole("heading",{name:"Лимиты Codex"})).toBeVisible();
  await expect(page.getByText("58% осталось")).toBeVisible();
  await expect(page.getByText("15% осталось")).toBeVisible();
  await expect(page.getByRole("progressbar")).toHaveCount(2);
  await expect(page.getByText("История квот")).toBeVisible();
  await expect(page.getByRole("img",{name:/История минимального остатка/})).toBeVisible();
  await expect(page.getByText("Проверка новых задач:")).toBeVisible();
  await expect(page.getByRole("button",{name:"Обновить отображение лимитов Codex"})).toBeEnabled();
  const overflowing=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
  expect(overflowing).toBe(false);
  mkdirSync(evidence,{recursive:true});
  await page.screenshot({path:resolve(evidence,"codex-"+width+".png"),fullPage:true});
 });
}

test("No source is not misrepresented as available",async({page})=>{
 setup(page,"not_configured");
 await page.goto("/");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Лимиты AI"}).click();
 await expect(page.getByText("Не подключён",{exact:true})).toBeVisible();
 await expect(page.getByRole("progressbar")).toHaveCount(0);
 await expect(page.getByText(/после авторизации на VPS/i)).toBeVisible();
});

test("Review summary exposes read-only Codex panel",async({page})=>{
 setup(page);
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Лимиты Codex"})).toBeVisible();
 await expect(page.getByRole("button",{name:"Показать подробности"})).toBeVisible();
 await page.getByRole("button",{name:"Показать подробности"}).click();
 await expect(page.getByText("58% осталось")).toBeVisible();
});

test("Codex history period and threshold controls remain read-only",async({page})=>{
 setup(page);
 await page.goto("/");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Лимиты AI"}).click();
 await expect(page.getByText("История квот")).toBeVisible();
 await page.getByRole("button",{name:"30 дн."}).click();
 await expect(page.getByRole("button",{name:"30 дн."})).toHaveAttribute("aria-pressed","true");
 await page.locator("#codex-warning-threshold").fill("35");
 await expect(page.getByText("Порог предупреждения · 35% остатка")).toBeVisible();
 await expect(page.getByText(/не изменяет серверный порог Ops Watch/i)).toBeVisible();
});
