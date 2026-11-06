import {test,expect} from "@playwright/test";

/** #816. Deterministic iPhone standalone safe-area simulation; no real owner OAuth. */
test.use({serviceWorkers:"block"});
async function isolated(page,{safeTop=59,safeBottom=34}={}){
 const errors=[],external=[];
 page.on("pageerror",err=>errors.push(err.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133"||
     url.pathname.startsWith("/auth/")||url.pathname.startsWith("/api/auth/")){
   external.push(url.pathname.startsWith("/auth/")?"auth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname.startsWith("/api/"))return route.fulfill({
   status:503,contentType:"application/json",
   body:'{"error":"synthetic_unavailable"}'});
  return route.continue();
 });
 // Inject the safe-area fixture via the existing same-origin CSS response.
 // Production CSP disallows inline style tags; never bypass that policy.
 await page.route("**/style.css",async route=>{
  const response=await route.fetch();
  const originalCSS=await response.text();
  const override="\n.theme-orbit{--hermes-pwa-safe-top:"+safeTop+
   "px!important;--hermes-pwa-safe-bottom:"+safeBottom+"px!important}\n";
  await route.fulfill({response,body:originalCSS+override});
 });
 return {errors,external};
}

async function rect(locator){
 return locator.evaluate(node=>{
  const {x,y,width,height,right,bottom}=node.getBoundingClientRect();
  return {x,y,width,height,right,bottom};
 });
}
async function hitTest(locator){
 return locator.evaluate(node=>{
  const r=node.getBoundingClientRect();
  const hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
  return hit===node||node.contains(hit);
 });
}

for(const [w,h] of [[320,770],[393,852],[430,932],[700,900]]){
 for(const theme of ["light","dark"]){
  test("iPhone PWA safe top and centred lower dock "+theme+" "+w,async({page},testInfo)=>{
   const {errors,external}=await isolated(page);
   await page.setViewportSize({width:w,height:h});
   await page.emulateMedia({colorScheme:theme,reducedMotion:"reduce"});
   await page.goto("/");
   await page.evaluate(t=>localStorage.setItem("hermes-control-center-ui-theme",t),theme);
   await page.reload();
   await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme",theme);
   const header=page.locator(".orbit-topbar"),dock=page.locator(".orbit-app-mobilebar");
   await expect(header).toBeVisible();await expect(dock).toBeVisible();
   const hdr=await rect(header),nav=await rect(dock);
   expect(hdr.height,"Safe top is added to natural header height").toBeCloseTo(129,0);
   expect(hdr.y).toBeGreaterThanOrEqual(-1);
   expect(nav.bottom).toBeCloseTo(h-34,0);
   expect(nav.x,"Equal left/right dock gutters").toBeCloseTo(w-nav.right,0);
   expect(nav.width).toBeCloseTo(Math.min(440,w-24),0);

   for(const name of ["Поиск по разделам","Информация о центре"]){
    const button=header.getByRole("button",{name});
    await expect(button).toBeVisible();
    const bb=await rect(button);
    expect(bb.y,"Button must be below simulated status bar").toBeGreaterThanOrEqual(59);
    expect(bb.bottom,"Button must remain inside header").toBeLessThanOrEqual(hdr.bottom-2);
    expect(await hitTest(button),"Button can receive real pointer hits").toBe(true);
   }
   await header.getByRole("button",{name:"Поиск по разделам"}).click();
   await expect(page.getByRole("dialog",{name:"Поиск раздела"})).toBeVisible();
   await page.locator(".orbit-search-close").click();
   await header.getByRole("button",{name:"Информация о центре"}).click();
   await expect(page.locator(".orbit-header-info")).toBeVisible();
   await page.locator(".orbit-header-info button").last().click();

   const more=dock.getByRole("button",{name:"Ещё"});
   await more.click();
   await expect(more).toHaveAttribute("aria-expanded","true");
   const sheet=await rect(page.locator(".orbit-rail"));
   expect(sheet.y,"Bottom sheet does not cover status bar/header").toBeGreaterThanOrEqual(hdr.bottom+4);
   expect(sheet.bottom,"Bottom sheet remains above dock").toBeLessThanOrEqual(nav.y-8);
   await page.keyboard.press("Escape");
   await expect(more).toHaveAttribute("aria-expanded","false");

   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
   expect(overflow,"No horizontal scroll").toBeLessThanOrEqual(1);
   await testInfo.attach("pwa-safe-"+theme+"-"+w+".png",{
    body:await page.screenshot({animations:"disabled"}),contentType:"image/png"});
   expect(errors).toEqual([]);
   expect(external).toEqual([]);
  });
 }
}

test("Safari-like no safe-area keeps 70px header and symmetrical 12px bottom dock",async({page})=>{
 const {errors,external}=await isolated(page,{safeTop:0,safeBottom:0});
 await page.setViewportSize({width:393,height:852});
 await page.goto("/");
 const header=await rect(page.locator(".orbit-topbar"));
 const dock=await rect(page.locator(".orbit-app-mobilebar"));
 expect(header.height).toBeCloseTo(70,0);
 expect(dock.bottom).toBeCloseTo(840,0);
 expect(dock.x).toBeCloseTo(393-dock.right,0);
 expect(await hitTest(page.getByRole("button",{name:"Поиск по разделам"}))).toBe(true);
 expect(errors).toEqual([]);expect(external).toEqual([]);
});
