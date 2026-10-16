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
test("approved C+B Atlas with C+A fonts, working asset and navigation",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await mock(page);
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
 await expect(page.getByText("Resident AI Agent: NO-GO",{exact:true})).toBeVisible();
 await expect(page.locator('img[src="/brand.webp"]').first()).toHaveJSProperty("complete",true);
 const imageLoaded=await page.locator('img[src="/brand.webp"]').first().evaluate(x=>x.naturalWidth>0);
 expect(imageLoaded).toBe(true);
 expect((await page.request.get("/favicon.png")).status()).toBe(200);
 await page.screenshot({path:resolve(folder,"atlas-1440.png"),fullPage:true});
 await page.locator(".atlas-section-nav").getByRole("button",{name:"QA и CI"}).click();
 await expect(page.getByRole("row",{name:/QA Advisor/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
 await page.getByPlaceholder("Поиск по службам…").fill("Research");
 await expect(page.getByRole("row",{name:/Research Scout/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await assertNoOverflow(page);
});
test("approved typography is sans-serif throughout Atlas",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await mock(page);await page.goto("/");
 const families=await page.locator(".atlas-hero h1, .atlas-nav button, .atlas-section-nav .nav-link, .stat-tile strong, .registry-panel h2").evaluateAll(els=>els.map(el=>getComputedStyle(el).fontFamily));
 for(const family of families){expect(family).not.toContain("Georgia");expect(family.toLowerCase()).toContain("sans-serif");}
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
 await expect(page.getByRole("table")).toBeVisible();
 await expect(page.getByText("История инцидентов и доставки уведомлений пока не подключена.")).toBeVisible();
 await page.screenshot({path:resolve(folder,"atlas-fonts-1440.png"),fullPage:true});
 await assertNoOverflow(page);
});
test("login design is a preview only, OAuth button disabled",async({page})=>{
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/?preview=login");
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
 await expect(page.getByText(/OAuth не включён/)).toBeVisible();
 const logo=page.locator(".login-hero-mark");
 await expect(logo).toHaveJSProperty("naturalWidth",1096);
 expect(await logo.evaluate(el=>getComputedStyle(el).mixBlendMode)).toBe("normal");
 expect(await logo.evaluate(el=>{const c=document.createElement("canvas");c.width=c.height=1;const ctx=c.getContext("2d");ctx.drawImage(el,0,0);return ctx.getImageData(0,0,1,1).data[3];})).toBe(0);
 await page.screenshot({path:resolve(folder,"login-1440.png"),fullPage:true});
 await assertNoOverflow(page);
});
for(const width of [320,360,393,430,768,1920]){
 test("responsive Atlas and login "+width,async({page})=>{
  await page.setViewportSize({width,height:844});await mock(page);await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await assertNoOverflow(page);
  if(width===393)await page.screenshot({path:resolve(folder,"atlas-393.png"),fullPage:true});
  await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
  await assertNoOverflow(page);
  await page.goto("/?preview=login");
  await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
  await assertNoOverflow(page);
  if(width===393)await page.screenshot({path:resolve(folder,"login-393.png"),fullPage:true});
 });
}
test("keyboard-only Atlas navigation retains labels and read-only boundaries",async({page})=>{
 await page.setViewportSize({width:360,height:780});await mock(page);
 await page.goto("/");
 await expect(page.locator("html")).toHaveAttribute("lang","ru");
 const qa=page.locator(".atlas-section-nav").getByRole("button",{name:"QA и CI"});
 await qa.focus();
 await expect(qa).toBeFocused();
 await qa.press("Enter");
 await expect(page.getByRole("row",{name:/QA Advisor/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 const search=page.getByRole("textbox",{name:"Поиск по службам"});
 await search.focus();
 await search.fill("несуществующий-сервис");
 await expect(page.getByRole("row",{name:/QA Advisor/})).toHaveCount(0);
 await expect(page.getByText("По текущим условиям служб не найдено.")).toBeVisible();
 await assertNoOverflow(page);
});

test("stale data never shown as healthy",async({page})=>{
 await mock(page,{generated_at:"2020-01-01T00:00:00Z"});await page.goto("/");
 await expect(page.getByRole("alert")).toContainText("устаревший");
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
});

test("GitHub mode shows real owner login and gates the protected API",async({page})=>{
 let overviewRequests=0;
 await page.route("**/api/auth/session",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({mode:"github",authenticated:false})}));
 await page.route("**/api/overview",route=>{overviewRequests+=1;return route.abort();});
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 const signIn=page.getByRole("link",{name:/Войти через GitHub/});
 await expect(signIn).toHaveAttribute("href","/auth/github/start");
 await expect(signIn).toBeEnabled();
 await expect(page.getByRole("table")).toHaveCount(0);
 expect(overviewRequests).toBe(0);
});

test("session probe errors fail closed without showing protected dashboard",async({page})=>{
 await page.route("**/api/auth/session",route=>route.fulfill({status:503,body:"unavailable"}));
 await page.goto("/");
 await expect(page.getByText(/Проверка состояния авторизации не удалась/)).toBeVisible();
 await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
 await expect(page.getByRole("table")).toHaveCount(0);
});

test("owner GitHub session can log out and loses snapshot view",async({page})=>{
 await page.route("**/api/auth/session",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({mode:"github",authenticated:true})}));
 await mock(page);
 let logoutCalled=0;
 await page.route("**/auth/logout",route=>{
  logoutCalled++;
  expect(route.request().method()).toBe("POST");
  return route.fulfill({status:204,body:""});
 });
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
 await expect(page.getByRole("table")).toBeVisible();
 await page.getByRole("button",{name:"Выйти"}).click();
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 await expect(page.getByRole("link",{name:/Войти через GitHub/})).toHaveAttribute("href","/auth/github/start");
 await expect(page.getByRole("table")).toHaveCount(0);
 expect(logoutCalled).toBe(1);
});
