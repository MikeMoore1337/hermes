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

// Approved C replaces the historical React Explorer in primary navigation.
test.use({serviceWorkers:"block"});
async function overview(page){
 await page.route("**/api/overview",route=>route.fulfill({status:200,
  contentType:"application/json",body:JSON.stringify({
   schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]})}));
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,
  contentType:"application/json",body:'{"error":"synthetic_unavailable"}'}));
}
for(const width of [320,393,768,1440]){
 test("Primary Commander uses owner-approved C at "+width,async({page})=>{
  await page.setViewportSize({width,height:width<=393?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});await overview(page);
  await page.goto("/");
  await chooseOrbitView(page,"Hermes Commander");
  await expect(page).toHaveURL(/\/hermes-brc$/);
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
