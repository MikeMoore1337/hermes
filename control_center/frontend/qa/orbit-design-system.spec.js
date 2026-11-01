import {test,expect} from "@playwright/test";
// All data synthetic; no owner OAuth or public provider requests.
test.use({serviceWorkers:"block"});
async function isolate(page){
 const unexpected=[];
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.hostname!=="127.0.0.1"||url.port!=="9133"){
   unexpected.push(url.origin);return route.abort("blockedbyclient");
  }
  return route.continue();
 });
 await page.route("**/api/**",route=>{
  const u=new URL(route.request().url());
  if(u.pathname==="/api/overview")return route.fulfill({
   status:200,contentType:"application/json",body:JSON.stringify({
    schema:1,mode:"read_only",generated_at:new Date().toISOString(),
    services:[{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active"},
     {id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed"}]
   })});
  return route.fulfill({status:503,contentType:"application/json",
   body:JSON.stringify({error:"synthetic_unavailable"})});
 });
 return unexpected;
}
async function navigate(page,name,width){
 if(width<=980){
  const dock=page.locator(".orbit-app-mobilebar").getByRole("button",{name,exact:true});
  if(await dock.count()){await dock.click();return;}
  const more=page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"});
  if(await more.getAttribute("aria-expanded")!=="true")await more.click();
 }
 await page.locator(".atlas-section-nav").getByRole("button",{name,exact:true}).click();
}
const geometry=page=>page.evaluate(()=>({
 viewport:innerWidth,doc:document.documentElement.scrollWidth,body:document.body.scrollWidth
}));
test("one Orbit type system across React routes",async({page})=>{
 const unexpected=await isolate(page),errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/");
 await expect(page.locator(".orbit-rail-brand img")).toHaveAttribute("src","/orbit-brand.svg");
 for(const [label,container,title] of [
  ["Operator Inbox",".oi-root",".oi-header h1"],
  ["Исследования",".orbit-module-shell",".orbit-module-intro h1"],
  ["QA и CI",".orbit-module-shell",".orbit-module-intro h1"],
  ["AI Agent",".orbit-module-shell",".orbit-module-intro h1"],
  ["Лимиты AI",".orbit-module-shell",".orbit-module-intro h1"],
  ["Hermes Commander",".oc-page","#brc-title"]
 ]){
  await navigate(page,label,1440);
  await expect(page.locator(container)).toBeVisible();
  await expect(page.locator(title)).toBeVisible();
  const values=await page.locator(title).evaluate(el=>{
   const c=getComputedStyle(el),root=getComputedStyle(el.closest(".theme-orbit"));
   return {font:c.fontFamily,panel:root.getPropertyValue("--orbit-panel").trim()};
  });
  expect(values.font.toLowerCase()).toContain("sans-serif");
  expect(values.font).not.toContain("Georgia");
  expect(values.panel).toBe("#0b1d2c");
  const bounds=await geometry(page);
  expect(bounds.doc,"overflow on "+label).toBeLessThanOrEqual(bounds.viewport+1);
 }
 expect(errors).toEqual([]);
 expect(unexpected).toEqual([]);
});
test("injected widgets have matching line icons, headings and active breadcrumb",async({page})=>{
 const unexpected=await isolate(page),errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.setViewportSize({width:1440,height:900});
 await page.goto("/");
 for(const [klass,label,panel] of [
  ["ai272-nav","AI Usage Analytics",".ai272-panel"],
  ["infra294-nav","Инфраструктура",".infra294-panel"],
  ["quota295-nav","Квоты и инструменты",".quota295-panel"]
 ]){
  const nav=page.locator(".atlas-section-nav ."+klass);
  await expect(nav.locator(".orbit-nav-icon svg")).toHaveCount(1);
  await expect(nav.locator(".orbit-nav-icon")).toHaveAttribute("aria-hidden","true");
  await nav.focus();await nav.press("Enter");
  await expect(page.locator(panel)).toBeVisible();
  await expect(page.locator(panel+" .orbit-panel-icon svg")).toHaveCount(1);
  await expect(page.locator(".orbit-topbar-breadcrumb strong")).toHaveText(label);
  await expect(nav).toHaveAttribute("aria-current","page");
  await expect(page.locator(".atlas-section-nav .nav-link.is-active:not(."+klass+")")).toHaveCount(0);
  const font=await page.locator(panel+" h2").first().evaluate(el=>getComputedStyle(el).fontFamily);
  expect(font.toLowerCase()).toContain("sans-serif");
 }
 await navigate(page,"Обзор",1440);
 await expect(page.locator(".quota295-panel")).toBeHidden();
 await expect(page.locator(".orbit-topbar-breadcrumb strong")).toHaveText("Обзор");
 expect(errors).toEqual([]);
 expect(unexpected).toEqual([]);
});
for(const width of [320,393,768,1440]){
 test("Orbit responsive modules "+width,async({page})=>{
  const unexpected=await isolate(page),errors=[];
  page.on("pageerror",e=>errors.push(e.message));
  await page.setViewportSize({width,height:width<768?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await page.goto("/");
  await navigate(page,"Operator Inbox",width);
  const h=page.locator(".oi-header h1");
  await expect(h).toBeVisible();
  expect((await h.evaluate(el=>getComputedStyle(el).fontFamily))).not.toContain("Georgia");
  let sizes=await geometry(page);
  expect(sizes.doc).toBeLessThanOrEqual(width+1);
  await navigate(page,"Hermes Commander",width);
  await expect(page.locator(".oc-page")).toBeVisible();
  sizes=await geometry(page);
  expect(sizes.doc).toBeLessThanOrEqual(width+1);
  if(width===393){
   const input=page.locator(".oc-search input");
   await input.focus();
   const outline=await input.evaluate(el=>getComputedStyle(el.parentElement).outlineStyle);
   expect(outline).not.toBe("none");
  }
  expect(errors).toEqual([]);
  expect(unexpected).toEqual([]);
 });
}
test("read-only archive uses Orbit mark, icons and typography",async({page})=>{
 const unexpected=await isolate(page);
 await page.setViewportSize({width:393,height:844});
 await page.goto("/desktop-commander-archive");
 await expect(page.locator(".top .brand img")).toHaveAttribute("src","/orbit-brand.svg");
 await expect(page.locator(".top nav a svg")).toHaveCount(2);
 await expect(page.getByRole("heading",{name:"Архив Desktop Commander"})).toBeVisible();
 const values=await page.locator("h1").evaluate(el=>({
  font:getComputedStyle(el).fontFamily,
  border:getComputedStyle(document.querySelector(".panel")).borderColor
 }));
 expect(values.font.toLowerCase()).toContain("sans-serif");
 expect(values.border).toBe("rgb(43, 75, 100)");
 const g=await geometry(page);
 expect(g.doc).toBeLessThanOrEqual(g.viewport+1);
 expect(unexpected).toEqual([]);
});

test("authorized YFC editor retains owner gate with Orbit typography",async({page},testInfo)=>{
 const unexpected=await isolate(page),errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.route("http://127.0.0.1:9133/",async route=>{
  const response=await route.fetch();
  const html=await response.text();
  const old=' data-auth-mode="proxy" data-authenticated="true"';
  expect(html).toContain(old);
  await route.fulfill({response,body:html.replace(old,
    ' data-auth-mode="github" data-authenticated="true"')});
 });
 await page.setViewportSize({width:393,height:844});
 await page.goto("/");
 await navigate(page,"Статьи YFC",393);
 await expect(page.locator(".ye-root")).toBeVisible();
 await expect(page.locator(".orbit-topbar")).toBeVisible();
 const heading=page.locator(".ye-header h1");
 await expect(heading).toBeVisible();
 const font=await heading.evaluate(el=>getComputedStyle(el).fontFamily);
 expect(font.toLowerCase()).toContain("sans-serif");
 expect(font).not.toContain("Georgia");
 const g=await geometry(page);
 expect(g.doc).toBeLessThanOrEqual(g.viewport+1);
 await testInfo.attach("orbit-editor-393.png",{
  body:await page.screenshot({fullPage:true,animations:"disabled"}),contentType:"image/png"
 });
 expect(errors).toEqual([]);
 expect(unexpected).toEqual([]);
});
