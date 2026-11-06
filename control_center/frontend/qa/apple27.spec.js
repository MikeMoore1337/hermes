import {test,expect} from "@playwright/test";

// H779: all captures synthetic; network cannot reach owner OAuth, other APIs or external origins.
test.use({serviceWorkers:"block"});
async function sandbox(page){
 const denied=[],errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.route("**/*",route=>{
  const u=new URL(route.request().url());
  if(u.origin!=="http://127.0.0.1:9133"||u.pathname.startsWith("/auth/")||u.pathname.startsWith("/api/auth/")){
   denied.push(u.origin==="http://127.0.0.1:9133"?"auth":"external");
   return route.abort("blockedbyclient");
  }
  if(u.pathname==="/api/overview")return route.fulfill({status:200,contentType:"application/json",
    body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),
     services:[{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
       {id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed",kind:"schedule"}]})});
  if(u.pathname.startsWith("/api/"))return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"unavailable_synthetic"})});
  return route.continue();
 });
 return {denied,errors};
}
const snapshot=page=>page.evaluate(()=>{
 const root=document.querySelector(".theme-orbit");
 return {theme:document.documentElement.dataset.hermesTheme,
  panel:getComputedStyle(root).getPropertyValue("--orbit-panel").trim(),
  width:innerWidth,document:document.documentElement.scrollWidth,
  topbar:!!document.querySelector(".orbit-topbar"),dock:!!document.querySelector(".orbit-app-mobilebar")};
});
test("Aero Glass theme control persists light/dark without storing protected state",async({page})=>{
 const {denied,errors}=await sandbox(page);
 await page.emulateMedia({colorScheme:"light"});
 await page.goto("/");
 await page.evaluate(()=>localStorage.setItem("hermes-control-center-ui-theme","light"));
 await page.reload();
 const button=page.getByRole("button",{name:/Тема:/});
 await expect(button).toBeVisible();
 expect((await snapshot(page)).panel).toBe("#fff");
 await button.click();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme","dark");
 expect((await snapshot(page)).panel).toBe("#1d2a3d");
 await button.click();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme","light");
 expect((await snapshot(page)).panel).toBe("#fff");
 await page.reload();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme","light");
 const prefs=await page.evaluate(()=>({
  keys:Object.keys(localStorage),
  theme:localStorage.getItem("hermes-control-center-ui-theme")
 }));
 expect(prefs.theme).toBe("light");
 expect(prefs.keys.filter(x=>x.includes("hermes-control-center-ui-theme"))).toEqual(["hermes-control-center-ui-theme"]);
 await page.goto("/?preview=login");
 await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme","light");
 const authBackground=await page.locator(".orbit-auth").evaluate(el=>getComputedStyle(el).backgroundColor);
 expect(authBackground).toBe("rgb(230, 234, 243)");
 expect(denied).toEqual([]);expect(errors).toEqual([]);
});
test("Aero Glass navigation and disclosure work by keyboard at 393px",async({page})=>{
 const {denied,errors}=await sandbox(page);
 await page.setViewportSize({width:393,height:844});
 await page.emulateMedia({reducedMotion:"reduce",colorScheme:"dark"});
 await page.goto("/");
 await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
 const dock=page.locator(".orbit-app-mobilebar");
 await expect(dock.getByRole("button",{name:"Commander"})).toBeVisible();
 await expect(dock.getByRole("button",{name:"Обзор"})).toHaveAttribute("aria-current","page");
 const disclosure=page.locator(".hcc-topology-details summary");
 await expect(disclosure.locator("svg.hcc-topology-chevron")).toHaveCount(1);
 await disclosure.focus();await disclosure.press("Enter");
 await expect(page.locator(".orbit-graph")).toBeVisible();
 const more=dock.getByRole("button",{name:"Ещё"});
 await more.focus();await more.press("Enter");
 await expect(more).toHaveAttribute("aria-expanded","true");
 const qa=page.locator(".atlas-section-nav").getByRole("button",{name:"QA и CI"});
 await qa.focus();await qa.press("Enter");
 await expect(more).toHaveAttribute("aria-expanded","false");
 await expect(page.locator(".orbit-module-intro h1")).toHaveText("QA и CI");
 await more.click();
 await page.keyboard.press("Escape");
 await expect(more).toHaveAttribute("aria-expanded","false");
 expect((await snapshot(page)).document).toBeLessThanOrEqual(394);
 expect(denied).toEqual([]);expect(errors).toEqual([]);
});
for(const width of [320,393,768,1440,1920]){
 test("Aero Glass dark/light synthetic layout "+width,async({page},testInfo)=>{
  const {denied,errors}=await sandbox(page);
  await page.setViewportSize({width,height:width<768?844:900});
  await page.emulateMedia({colorScheme:"dark",reducedMotion:"reduce"});
  await page.goto("/");
  await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
  await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
  for(const theme of ["dark","light"]){
   await page.evaluate(theme=>{
     localStorage.setItem("hermes-control-center-ui-theme",theme);
   },theme);
   await page.reload();
   await expect(page.locator("html")).toHaveAttribute("data-hermes-theme",theme);
   const obs=await snapshot(page);
   expect(obs.document,"overflow "+theme+" at "+width).toBeLessThanOrEqual(width+1);
   expect(obs.panel).toBe(theme==="dark"?"#1d2a3d":"#fff");
   await testInfo.attach("h779-"+theme+"-"+width+".png",{body:await page.screenshot({fullPage:false,animations:"disabled"}),contentType:"image/png"});
  }
  expect(denied).toEqual([]);expect(errors).toEqual([]);
 });
}


test("Aero Glass light theme keeps registry, refresh and workspace readable",async({page})=>{
 const {denied,errors}=await sandbox(page);
 await page.setViewportSize({width:1440,height:900});
 await page.emulateMedia({colorScheme:"light",reducedMotion:"reduce"});
 await page.goto("/");
 await page.evaluate(()=>localStorage.setItem("hermes-control-center-ui-theme","light"));
 await page.reload();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme","light");
 await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
 const styles=await page.evaluate(()=>{
  const css=selector=>getComputedStyle(document.querySelector(selector));
  return {
   refreshBackground:css(".atlas-section-nav .refresh-button").backgroundColor,
   refreshText:css(".atlas-section-nav .refresh-button").color,
   workspaceText:css(".orbit-workspace-pill strong").color,
   searchBackground:css(".search-field").backgroundColor,
   searchText:css(".search-field input").color,
   tableBackground:css(".service-table th").backgroundColor,
   labelText:css(".service-label strong").color,
   width:document.documentElement.scrollWidth
  };
 });
 expect(styles.refreshBackground).not.toBe("rgb(16, 37, 58)");
 expect(styles.refreshText).toBe("rgb(23, 36, 58)");
 expect(styles.workspaceText).toBe("rgb(23, 36, 58)");
 expect(styles.searchBackground).toBe("rgb(243, 246, 251)");
 expect(styles.searchText).toBe("rgb(23, 36, 58)");
 expect(styles.tableBackground).toBe("rgb(240, 244, 249)");
 expect(styles.labelText).toBe("rgb(23, 36, 58)");
 expect(styles.width).toBeLessThanOrEqual(1441);
 expect(denied).toEqual([]);expect(errors).toEqual([]);
});
test("Aero Glass iOS toolbar shows brand and three functional tool buttons without breadcrumb",async({page})=>{
 const {denied,errors}=await sandbox(page);
 await page.setViewportSize({width:393,height:844});
 await page.goto("/");
 const bar=page.locator(".orbit-topbar");
 await expect(bar.locator(".orbit-topbar-mobile-brand")).toBeVisible();
 await expect(bar.locator(".orbit-topbar-breadcrumb")).toBeHidden();
 await expect(bar.getByRole("button",{name:"Поиск по разделам"})).toBeVisible();
 await expect(bar.getByRole("button",{name:/Тема:/})).toBeVisible();
 await expect(bar.getByRole("button",{name:"Информация о центре"})).toBeVisible();
 const more=page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"});
 await more.click();
 await expect(page.locator(".orbit-rail")).toBeVisible();
 await expect(page.locator(".orbit-nav-group-title").first()).toHaveText("РАБОЧЕЕ ПРОСТРАНСТВО");
 expect(denied).toEqual([]);expect(errors).toEqual([]);
});
