import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";
const folder=resolve(".artifacts/h15-visual");
mkdirSync(folder,{recursive:true});
const services=[
{id:"news",name:"Новости YFC",unit:"hermes-discovery.timer",state:"active",kind:"schedule"},
{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
{id:"alerts",name:"Telegram-уведомления",unit:"hermes-ops-alerts.timer",state:"active",kind:"schedule"},
{id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"active",kind:"schedule"},
{id:"research",name:"Research Scout",unit:"hermes-research-scout.timer",state:"active",kind:"schedule"},
{id:"network",name:"Защита сети",unit:"hermes-cloudflare-network-guard.service",state:"active",kind:"service"},
{id:"agent",name:"Постоянный AI Agent",unit:"hermes-agent-sandbox.service",state:"blocked",kind:"restricted"}];
function mock(page,extras={}){
 return page.route("**/api/overview", route=>route.fulfill({status:200,
   contentType:"application/json",
   body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services,...extras})}));
}
async function assertNoOverflow(page){
 const out=await page.evaluate(()=>({width:innerWidth,doc:document.documentElement.scrollWidth,body:document.body.scrollWidth}));
 expect(out.doc,"Horizontal document overflow").toBeLessThanOrEqual(out.width+1);
 expect(out.body,"Horizontal body overflow").toBeLessThanOrEqual(out.width+1);
}
test("C+A console, verified asset and navigation",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await mock(page);
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Состояние инфраструктуры"})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
 await expect(page.getByText("Resident AI Agent: NO-GO",{exact:true})).toBeVisible();
 await expect(page.locator('img[src="/brand.webp"]').first()).toHaveJSProperty("complete",true);
 const imageLoaded=await page.locator('img[src="/brand.webp"]').first().evaluate(x=>x.naturalWidth>0);
 expect(imageLoaded).toBe(true);
 expect((await page.request.get("/favicon.png")).status()).toBe(200);
 await page.screenshot({path:resolve(folder,"console-1440.png"),fullPage:true});
 await page.getByRole("button",{name:"QA и CI"}).click();
 await expect(page.getByRole("row",{name:/QA Advisor/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await page.getByRole("button",{name:"Обзор"}).click();
 await page.getByPlaceholder("Поиск по службам…").fill("Research");
 await expect(page.getByRole("row",{name:/Research Scout/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await assertNoOverflow(page);
});
test("C+B Atlas remains operator-first and truthful",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await mock(page);await page.goto("/");
 await page.getByRole("button",{name:"Атлас"}).click();
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
 await expect(page.getByRole("table")).toBeVisible();
 await expect(page.getByText("История инцидентов и доставки уведомлений пока не подключена.")).toBeVisible();
 await page.screenshot({path:resolve(folder,"atlas-1440.png"),fullPage:true});
 await assertNoOverflow(page);
});
test("login design is a preview only, OAuth button disabled",async({page})=>{
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/?preview=login");
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
 await expect(page.getByText(/OAuth не включён/)).toBeVisible();
 await page.screenshot({path:resolve(folder,"login-1440.png"),fullPage:true});
 await assertNoOverflow(page);
});
for(const width of [320,393,768]){
 test("responsive console and login "+width,async({page})=>{
  await page.setViewportSize({width,height:844});await mock(page);await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await assertNoOverflow(page);
  if(width===393)await page.screenshot({path:resolve(folder,"console-393.png"),fullPage:true});
  await page.getByRole("button",{name:"Атлас"}).click();
  await assertNoOverflow(page);
  await page.goto("/?preview=login");
  await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
  await assertNoOverflow(page);
  if(width===393)await page.screenshot({path:resolve(folder,"login-393.png"),fullPage:true});
 });
}
test("stale data never shown as healthy",async({page})=>{
 await mock(page,{generated_at:"2020-01-01T00:00:00Z"});await page.goto("/");
 await expect(page.getByRole("alert")).toContainText("устаревший");
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
});
