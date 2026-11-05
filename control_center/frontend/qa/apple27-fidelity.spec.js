import {test,expect} from "@playwright/test";

/** H779 visual fidelity to approved Aero Glass 27 v0.1.
 * Synthetic-only. No OAuth, private provider endpoints, real devices or external calls.
 */
test.use({serviceWorkers:"block"});
async function syntheticNoSnapshot(page){
 const unexpected=[],errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133" || url.pathname.startsWith("/auth/")||url.pathname.startsWith("/api/auth/")){
   unexpected.push(url.pathname.startsWith("/api/")?"auth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"synthetic_unavailable"})});
  }
  return route.continue();
 });
 return {unexpected,errors};
}
function approx(actual,expected,delta=3){
 expect(actual).toBeGreaterThanOrEqual(expected-delta);
 expect(actual).toBeLessThanOrEqual(expected+delta);
}
async function rects(page){
 return page.evaluate(()=>{
  const selectors={
   window:".orbit-app-layout",sidebar:".orbit-rail",toolbar:".orbit-topbar",
   main:".orbit-main",hero:".hcc-intro",kpis:".hcc-kpis",panels:".hcc-grid",
   dock:".orbit-app-mobilebar",notice:".hcc-snapshot-notice"
  };
  const result={document:document.documentElement.scrollWidth,viewport:innerWidth};
  for(const [key,selector] of Object.entries(selectors)){
   const el=document.querySelector(selector);
   if(!el){result[key]=null;continue;}
   const r=el.getBoundingClientRect(),css=getComputedStyle(el);
   result[key]={x:r.x,y:r.y,width:r.width,height:r.height,display:css.display};
  }
  return result;
 });
}
for(const [width,height,windowX,windowY,windowW] of [
 [1440,900,43,28,1354],[768,900,23,28,722],[393,852,0,0,393],[320,770,0,0,320]
]){
 for(const theme of ["dark","light"]){
  test("approved v0.1 geometry "+theme+" "+width,async({page},testInfo)=>{
   const {unexpected,errors}=await syntheticNoSnapshot(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({colorScheme:"dark",reducedMotion:"reduce"});
   await page.goto("/");
   await page.evaluate(theme=>localStorage.setItem("hermes-control-center-ui-theme",theme),theme);
   await page.reload();
   await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
   await expect(page.locator("html")).toHaveAttribute("data-hermes-theme",theme);
   const m=await rects(page);
   expect(m.document,"horizontal overflow").toBeLessThanOrEqual(m.viewport+1);
   approx(m.window.x,windowX,2);approx(m.window.y,windowY,2);approx(m.window.width,windowW,3);
   if(width>700){
    approx(m.window.height,height-56,2);
    approx(m.toolbar.height,72,2);
    approx(m.sidebar.width,width>=1181?260:width>=921?216:190,2);
    await expect(page.locator(".orbit-macos-dots")).toHaveCount(0);
    await expect(page.locator(".orbit-project-label,.footer")).toHaveCount(0);
    await expect(page.getByRole("navigation",{name:"Разделы управления"})).toBeVisible();
    await expect(page.locator(".orbit-nav-group-title").filter({hasText:"РАБОЧЕЕ ПРОСТРАНСТВО"})).toBeVisible();
    await expect(page.locator(".orbit-nav-group-title").filter({hasText:"НАБЛЮДЕНИЕ"})).toBeVisible();
    await expect(page.locator(".orbit-nav-group-title").filter({hasText:"КОНТЕНТ"})).toHaveCount(0); // proxy auth cannot expose YFC editor
   }else{
    approx(m.toolbar.height,70,2);
    expect(m.dock.display).toBe("flex");
    approx(m.dock.x,12,2);
    approx(m.dock.width,width-24,2);
    approx(m.dock.height,64,2);
    await expect(page.locator(".orbit-topbar-mobile-identity")).toBeVisible();
    await expect(page.locator(".hcc-snapshot-notice")).toBeVisible();
    await expect(page.locator(".orbit-topbar-breadcrumb")).toBeHidden();
    await expect(page.locator(".orbit-app-mobilebar")).toBeVisible();
   }
   await testInfo.attach("h779-v01-"+theme+"-"+width+".png",{contentType:"image/png",
    body:await page.screenshot({animations:"disabled",fullPage:false})});
   await testInfo.attach("geometry-"+theme+"-"+width+".json",{contentType:"application/json",
    body:JSON.stringify(m,null,2)});
   expect(errors).toEqual([]);expect(unexpected).toEqual([]);
  });
 }
}
test("approved mobile More is a bottom sheet; navigation and search remain usable",async({page})=>{
 const {errors,unexpected}=await syntheticNoSnapshot(page);
 await page.setViewportSize({width:393,height:852});
 await page.goto("/");
 const more=page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"});
 await more.click();
 await expect(more).toHaveAttribute("aria-expanded","true");
 await expect(page.locator(".orbit-rail")).toBeVisible();
 const bounds=await page.locator(".orbit-rail").boundingBox();
 expect(bounds.y).toBeGreaterThanOrEqual(0);
 expect(bounds.y+bounds.height).toBeLessThanOrEqual(852-50);
 await page.locator(".atlas-section-nav").getByRole("button",{name:"QA и CI"}).click();
 await expect(page.locator(".orbit-module-intro h1")).toHaveText("QA и CI");
 await expect(more).toHaveAttribute("aria-expanded","false");
 await page.locator(".orbit-topbar").getByRole("button",{name:"Поиск по разделам"}).click();
 const input=page.getByRole("textbox",{name:"Найти раздел"});
 await input.fill("исслед");
 await expect(page.locator(".orbit-header-search-results button")).toHaveCount(1);
 await page.locator(".orbit-header-search-results button").click();
 await expect(page.locator(".orbit-module-intro h1")).toHaveText("Исследования");
 expect(errors).toEqual([]);expect(unexpected).toEqual([]);
});
test("unauthorized API remains unavailable without fake healthy KPIs",async({page})=>{
 await syntheticNoSnapshot(page);
 await page.setViewportSize({width:393,height:852});
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
 for(const tile of await page.locator(".hcc-kpi-value").all()){
  const text=(await tile.innerText()).trim();
  expect(["—","Только чтение"]).toContain(text);
 }
 await expect(page.getByRole("alert")).toContainText("503");
 await expect(page.locator(".hcc-snapshot-notice")).toContainText("Нет подтверждённого снимка");
});
