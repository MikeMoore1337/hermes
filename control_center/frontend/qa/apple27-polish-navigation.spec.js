import {test,expect} from "@playwright/test";

/** #811: App navigation and light/dark material checks. All data are synthetic. */
test.use({serviceWorkers:"block"});

async function fakeGithubSession(page){
 const pageErrors=[],external=[];
 page.on("pageerror",e=>pageErrors.push(e.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133" ||
      url.pathname.startsWith("/auth/")||url.pathname.startsWith("/api/auth/")){
   external.push(url.pathname.startsWith("/auth/")?"oauth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"synthetic_unavailable"})});
  }
  return route.continue();
 });
 for(const path of ["/","/hermes-brc"]){
  await page.route("http://127.0.0.1:9133"+path,async route=>{
   const response=await route.fetch();
   const html=await response.text();
   const old=' data-auth-mode="proxy" data-authenticated="true"';
   expect(html).toContain(old);
   await route.fulfill({response,body:html.replace(old,
     ' data-auth-mode="github" data-authenticated="true"')});
  });
 }
 return {pageErrors,external};
}
async function setTheme(page,theme){
 await page.evaluate(theme=>localStorage.setItem("hermes-control-center-ui-theme",theme),theme);
 await page.reload();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme",theme);
}
async function openMobileNav(page){
 const dock=page.locator(".orbit-app-mobilebar");
 if(await dock.isVisible()){
  const more=dock.getByRole("button",{name:"Ещё"});
  if(await more.getAttribute("aria-expanded")!=="true")await more.click();
 }
}
async function navigateFromArticles(page,buttonClass,panelClass){
 await openMobileNav(page);
 const sidebar=page.locator(".atlas-section-nav");
 await sidebar.getByRole("button",{name:"Статьи YFC"}).click();
 await expect(page.locator(".ye-root")).toBeVisible();
 await openMobileNav(page);
 const widget=sidebar.locator("."+buttonClass);
 await expect(widget).toBeVisible();
 await widget.focus();
 await widget.press("Enter");
 await expect(widget).toHaveAttribute("aria-current","page");
 await expect(page.locator("."+panelClass)).toBeVisible();
 await expect(page.locator(".ye-root")).toHaveCount(0);
 await expect(page.locator(".orbit-widget-host ."+panelClass)).toBeVisible();
}
for(const [width,height] of [[393,852],[1440,900]]){
 for(const theme of ["dark","light"]){
  test("themed search, logout and legacy navigation "+theme+" "+width,async({page},testInfo)=>{
   const {pageErrors,external}=await fakeGithubSession(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({colorScheme:theme,reducedMotion:"reduce"});
   await page.goto("/");
   await setTheme(page,theme);
   await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
   await expect(page.locator(".hcc-actions button")).toHaveCount(1);
   await expect(page.locator(".hcc-actions")).not.toContainText("Hermes Commander");
   await expect(page.getByRole("button",{name:"Выйти"})).toBeVisible();
   await expect(page.getByRole("button",{name:"Выйти"})).toContainText("Выйти");
   await expect(page.locator(".orbit-project-label,.footer")).toHaveCount(0);
   const search=page.getByRole("button",{name:"Поиск по разделам"});
   await search.click();
   const buttons=page.locator(".orbit-header-search-results button");
   await expect(buttons.first()).toBeVisible();
   const color=await buttons.first().evaluate(el=>getComputedStyle(el).backgroundColor);
   expect(color,"Search button must not be native grey").toBe("rgba(0, 0, 0, 0)");
   await buttons.first().hover();
   expect(await buttons.first().evaluate(el=>getComputedStyle(el).backgroundColor)).not.toBe(color);
   await page.locator(".orbit-search-close").click();

   // Reproduce owner screenshot: a legacy nav item after entering YFC Articles.
   for(const [buttonClass,panelClass] of [
    ["ai272-nav","ai272-panel"],
    ["infra294-nav","infra294-panel"],
    ["quota295-nav","quota295-panel"]]){
    await navigateFromArticles(page,buttonClass,panelClass);
   }
   await openMobileNav(page);
   await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
   await expect(page.locator(".hcc-overview")).toBeVisible();
   await expect(page.locator(".orbit-widget-module")).toHaveCount(0);
   await openMobileNav(page);
   await page.locator(".atlas-section-nav").getByRole("button",{name:"Hermes Commander"}).click();
   await expect(page.locator(".oc-page")).toBeVisible();
   const materials=await page.evaluate(()=>({
    path:getComputedStyle(document.querySelector(".oc-path")).backgroundColor,
    search:getComputedStyle(document.querySelector(".oc-search")).backgroundColor,
    facts:getComputedStyle(document.querySelector(".oc-context-facts>div")).backgroundColor,
    guide:getComputedStyle(document.querySelector(".oc-check-guide")).backgroundColor,
    surface:getComputedStyle(document.querySelector(".oc-project:not(.selected)")).backgroundColor
   }));
   expect(materials.path,"Path follows inset theme color").toBe(materials.search);
   expect(materials.facts,"Facts use theme secondary surface").toBe(materials.surface);
   if(theme==="light")expect(materials.guide).not.toBe("rgb(12, 37, 57)");
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
   expect(overflow,"No horizontal document overflow").toBeLessThanOrEqual(1);
   await testInfo.attach("apple27-"+theme+"-"+width+".png",{
    body:await page.screenshot({animations:"disabled"}),contentType:"image/png"});
   expect(pageErrors).toEqual([]);expect(external).toEqual([]);
  });
 }
}

test("legacy navigation mounts from direct Commander route, no initial center-area",async({page})=>{
 const {pageErrors,external}=await fakeGithubSession(page);
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/hermes-brc");
 await expect(page.locator(".oc-page")).toBeVisible();
 const widget=page.locator(".atlas-section-nav .infra294-nav");
 await expect(widget).toBeVisible();
 await widget.click();
 await expect(page.locator(".infra294-panel")).toBeVisible();
 await expect(page.locator(".oc-page")).toHaveCount(0);
 await page.goBack();
 await expect(page.locator(".oc-page")).toBeVisible();
 expect(pageErrors).toEqual([]);expect(external).toEqual([]);
});
