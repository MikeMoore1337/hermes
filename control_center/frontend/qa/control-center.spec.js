import {test,expect} from "@playwright/test";
// Auth routing tests own the document; the PWA worker is tested separately in pwa.spec.js.
test.use({serviceWorkers:"block"});
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
{id:"agent_bounded",name:"H-01 Ops AI (ограниченный)",unit:"hermes-h01-ops-agent.timer",state:"active",kind:"schedule"},
{id:"agent",name:"Полный AI Agent (без допуска)",unit:"hermes-agent-sandbox.service",state:"blocked",kind:"restricted"}];
function mock(page,extras={}){
 return page.route("**/api/overview", route=>route.fulfill({status:200,
   contentType:"application/json",
   body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services,agent_policy:"Ограниченный H-01 Ops AI: расписание активно. Полный AI Agent не допущен; успешность полезного цикла не доказана.",...extras})}));
}
async function fakeServerAuth(page,getState){
 await page.route("http://127.0.0.1:9133/",async route=>{
  const response=await route.fetch();
  const state=getState();
  let html=(await response.text()).replace(
    ' data-auth-mode="proxy" data-authenticated="true"',
    state.mode===null?'':` data-auth-mode="${state.mode}" data-authenticated="${state.authenticated}"`);
  if(!state.authenticated){
   for(const widget of ["desktop-commander","ai-analytics","infrastructure","provider-quota"]){
    html=html.replace(`<link rel="stylesheet" href="/${widget}.css">`,"");
    html=html.replace(`<script src="/${widget}.js" defer></script>`,"");
   }
  }
  await route.fulfill({response,body:html});
 });
}
async function assertNoOverflow(page){
 const out=await page.evaluate(()=>({width:innerWidth,doc:document.documentElement.scrollWidth,body:document.body.scrollWidth}));
 expect(out.doc,"Horizontal document overflow").toBeLessThanOrEqual(out.width+1);
 expect(out.body,"Horizontal body overflow").toBeLessThanOrEqual(out.width+1);
}
async function assertDesktopCaption(page){
 const r=await page.evaluate(()=>{
  const logo=document.querySelector(".login-hero-mark").getBoundingClientRect();
  const caption=document.querySelector(".login-overline").getBoundingClientRect();
  return {logoCenter:(logo.left+logo.right)/2, captionCenter:(caption.left+caption.right)/2,
   gap:caption.top-logo.bottom, align:getComputedStyle(document.querySelector(".login-overline")).textAlign};
 });
 expect(Math.abs(r.logoCenter-r.captionCenter),"Desktop wordmark centered relative to winged H").toBeLessThanOrEqual(1);
 expect(r.gap,"Desktop caption below winged H image").toBeGreaterThanOrEqual(16);
 expect(r.align).toBe("center");
}
test("approved C+B Atlas with C+A fonts, working asset and navigation",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await mock(page);
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
 await expect(page.getByText("H-01 Ops AI / полный агент",{exact:true})).toBeVisible();
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
  await assertDesktopCaption(page);
 await page.screenshot({path:resolve(folder,"login-1440.png"),fullPage:true});
 await assertNoOverflow(page);
});
for(const width of [320,360,393,430,750,768,1920]){
 test("responsive Atlas and login "+width,async({page})=>{
  await page.setViewportSize({width,height:844});await mock(page);await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await assertNoOverflow(page);
  if(width===393)await page.screenshot({path:resolve(folder,"atlas-393.png"),fullPage:true});
  await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
  await assertNoOverflow(page);
  await page.goto("/?preview=login");
  await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
  if(width<=750){
   const positions=await page.evaluate(()=>{
    const story=document.querySelector(".login-story").getBoundingClientRect();
    const logo=document.querySelector(".login-hero-mark").getBoundingClientRect();
    const caption=document.querySelector(".login-overline").getBoundingClientRect();
    return {sectionCenter:(story.left+story.right)/2,
      logoCenter:(logo.left+logo.right)/2,
      captionCenter:(caption.left+caption.right)/2,
      logoBottom:logo.bottom,captionTop:caption.top,
      captionAlign:getComputedStyle(document.querySelector(".login-overline")).textAlign};
   });
   expect(Math.abs(positions.logoCenter-positions.sectionCenter),"Logo must be centered").toBeLessThanOrEqual(1);
   expect(Math.abs(positions.captionCenter-positions.sectionCenter),"Caption block must be centered").toBeLessThanOrEqual(1);
   expect(positions.captionAlign).toBe("center");
   expect(positions.captionTop-positions.logoBottom,"Caption must sit clear below the wings").toBeGreaterThanOrEqual(16);
  }
   if(width>=768)await assertDesktopCaption(page);
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
 await fakeServerAuth(page,()=>({mode:"github",authenticated:false}));
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
 await fakeServerAuth(page,()=>({mode:null,authenticated:false}));
 await page.route("**/api/auth/session",route=>route.fulfill({status:503,body:"unavailable"}));
 await page.goto("/");
 await expect(page.getByText(/Проверка состояния авторизации не удалась/)).toBeVisible();
 await expect(page.getByRole("button",{name:/Войти через GitHub/})).toBeDisabled();
 await expect(page.getByRole("table")).toHaveCount(0);
});

test("server bootstrapped GitHub login paints without waiting for auth API",async({page})=>{
 let authRequests=0;
 await page.route("**/api/auth/session",route=>{
  authRequests++;
  return route.abort();
 });
 await fakeServerAuth(page,()=>({mode:"github",authenticated:false}));
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 await expect(page.getByRole("link",{name:/Войти через GitHub/})).toBeVisible();
 expect(authRequests).toBe(0);
 await expect(page.getByRole("button",{name:"Устройства"})).toHaveCount(0);
});

test("owner GitHub session can log out and loses snapshot view",async({page})=>{
 let loggedIn=true;
 await fakeServerAuth(page,()=>({mode:"github",authenticated:loggedIn}));
 await mock(page);
 let logoutCalled=0;
 await page.route("**/auth/logout",route=>{
  logoutCalled++;
  loggedIn=false;
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
