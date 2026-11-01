import {test,expect} from "@playwright/test";
async function chooseOrbitView(page,label){
 const width=page.viewportSize()?.width||1280;
 if(width<=980){
  const quickName=label==="QA и CI"?"QA / CI":label==="Operator Inbox"?"Входящие":label;
  const bottom=page.locator(".orbit-app-mobilebar").getByRole("button",{name:quickName,exact:true});
  if(await bottom.count()){await bottom.click();return;}
  await page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"}).click();
 }
 await page.locator(".atlas-section-nav").getByRole("button",{name:label,exact:true}).click();
}

// Orbit 3.0 integrates BRC in the primary React shell; the URL remains stable.
test.use({serviceWorkers:"block"});
async function overview(page){
 await page.route("**/api/overview",route=>route.fulfill({status:200,
  contentType:"application/json",body:JSON.stringify({
   schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]})}));
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,
  contentType:"application/json",body:'{"error":"synthetic_unavailable"}'}));
}
for(const width of [320,393,768,1440]){
 test("Commander shares Orbit shell and deep link at "+width,async({page})=>{
  await page.setViewportSize({width,height:width<=393?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});await overview(page);
  await page.goto("/");
  await chooseOrbitView(page,"Hermes Commander");
  await expect(page).toHaveURL(/\/hermes-brc$/);
  await expect(page.getByRole("main")).toHaveCount(1);
  await expect(page.locator(".orbit-topbar")).toBeVisible();
  await expect(page.locator(".orbit-main .oc-page")).toBeVisible();
  await expect(page.locator(".brc-shell")).toHaveCount(0);
  await expect(page.locator('script[src="/hermes-brc.js"]')).toHaveCount(0);
  await expect(page.getByRole("heading",{name:"Рабочие пространства"})).toBeVisible();
  await expect(page.locator("#brc-error")).toBeVisible();
  await expect(page.locator("#brc-selected-state")).toHaveText("НЕ ПРОВЕРЕНО");
  await expect(page.locator("body")).not.toContainText("D:\\Pet-projects");
  await page.getByRole("link",{name:"Архив Desktop Commander"}).click();
  await expect(page).toHaveURL(/\/desktop-commander-archive$/);
  await expect(page.getByRole("heading",{name:"Архив Desktop Commander"})).toBeVisible();
  const bounds=await page.evaluate(()=>({viewport:innerWidth,doc:document.documentElement.scrollWidth}));
  expect(bounds.doc).toBeLessThanOrEqual(bounds.viewport+1);
  await page.getByRole("link",{name:"Hermes BRC",exact:true}).click();
  await expect(page.getByRole("heading",{name:"Рабочие пространства"})).toBeVisible();
 });
}
test("Owner overview has no injected legacy floating widget",async({page})=>{
 await overview(page);await page.goto("/");
 await expect(page.locator("#dc-monitor")).toHaveCount(0);
 await expect(page.locator('script[src="/desktop-commander.js"]')).toHaveCount(0);
 await expect(page.locator(".nav-list").getByRole("button",{name:"Hermes Commander"})).toBeVisible();
});

test("BRC direct URL and browser history reuse one React app",async({page})=>{
 await overview(page);
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Hermes Commander"}).click();
 await expect(page).toHaveURL(/\/hermes-brc$/);
 await expect(page.locator(".orbit-rail")).toBeVisible();
 await expect(page.getByRole("main")).toHaveCount(1);
 await page.goBack();
 await expect(page).toHaveURL(/\/$/);
 await expect(page.getByRole("heading",{name:/Вся система/})).toBeVisible();
 await page.goForward();
 await expect(page).toHaveURL(/\/hermes-brc$/);
 await expect(page.getByRole("heading",{name:"Рабочие пространства"})).toBeVisible();
 await page.reload();
 await expect(page.getByRole("heading",{name:"Рабочие пространства"})).toBeVisible();
 await expect(page.locator(".oc-page")).toHaveCount(1);
});
test("BRC navigation on mobile is inside the same Orbit drawer",async({page})=>{
 await overview(page);await page.setViewportSize({width:393,height:844});await page.goto("/hermes-brc");
 await expect(page.locator(".orbit-app-mobilebar")).toBeVisible();
 await page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"}).click();
 await expect(page.locator(".orbit-rail")).toBeVisible();
 const nav=page.locator(".atlas-section-nav").getByRole("button",{name:"Hermes Commander"});
 await expect(nav).toHaveAttribute("aria-current","page");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
 await expect(page).toHaveURL(/\/$/);
 await expect(page.locator(".orbit-rail")).toBeHidden();
 await expect(page.getByRole("heading",{name:/Вся система/})).toBeVisible();
});
