import {test,expect} from "@playwright/test";

/** H796: synthetic-only wide desktop and login regression; no OAuth redirects. */
test.use({serviceWorkers:"block"});

async function isolation(page){
 const unauthorized=[],errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133"||url.pathname.startsWith("/auth/")
      ||url.pathname.startsWith("/api/auth/")){
   unauthorized.push(url.pathname.startsWith("/auth/")?"oauth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname==="/api/overview"){
   return route.fulfill({status:200,contentType:"application/json",
    body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]})});
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"synthetic_unavailable"})});
  }
  return route.continue();
 });
 return {unauthorized,errors};
}

async function setTheme(page,theme){
 await page.evaluate(value=>localStorage.setItem("hermes-control-center-ui-theme",value),theme);
 await page.reload();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme",theme);
}
function bounds(page,selectors){
 return page.evaluate(selectors=>{
  const result={vw:innerWidth,vh:innerHeight,
    scrollWidth:document.documentElement.scrollWidth,
    scrollHeight:document.documentElement.scrollHeight};
  for(const [key,sel] of Object.entries(selectors)){
   const el=document.querySelector(sel);
   if(!el){result[key]=null;continue;}
   const b=el.getBoundingClientRect(),cs=getComputedStyle(el);
   result[key]={x:b.x,y:b.y,w:b.width,h:b.height,right:b.right,bottom:b.bottom,
    display:cs.display,position:cs.position,background:cs.backgroundColor};
  }
  return result;
 },selectors);
}
function separated(a,b){return a.right<=b.x+1||b.right<=a.x+1||a.bottom<=b.y+1||b.bottom<=a.y+1;}

for(const [width,height] of [[1440,900],[1920,1080],[2048,1152],[2560,1440],[3440,1440]]){
 test("fluid Aero desktop at "+width+"x"+height+" without 1540px cap",async({page},testInfo)=>{
  const {unauthorized,errors}=await isolation(page);
  await page.setViewportSize({width,height});
  await page.emulateMedia({colorScheme:"dark",reducedMotion:"reduce"});
  await page.goto("/");
  await expect(page.getByRole("heading",{name:"Рабочий стол"})).toBeVisible();
  const m=await bounds(page,{shell:".orbit-app-layout",rail:".orbit-rail",topbar:".orbit-topbar",kpis:".hcc-kpis"});
  expect(m.scrollWidth).toBeLessThanOrEqual(width+1);
  expect(m.topbar.w).toBeGreaterThan(500);
  if(width===1440){
   expect(Math.abs(m.shell.w-1354)).toBeLessThan(4);
   expect(Math.abs(m.shell.h-805)).toBeLessThan(4);
  }else{
   expect(m.shell.w).toBeGreaterThan(width===3440?2490:width*.88);
   expect(m.shell.h).toBeGreaterThan(height*.86);
   expect(m.rail.h).toBeGreaterThan(height*.84);
  }
  expect(m.kpis.w).toBeGreaterThan(m.shell.w*.52);
  await testInfo.attach("desktop-"+width+".png",{body:await page.screenshot({animations:"disabled"}),
    contentType:"image/png"});
  await testInfo.attach("desktop-"+width+".json",{body:JSON.stringify(m,null,2),
    contentType:"application/json"});
  expect(errors).toEqual([]);expect(unauthorized).toEqual([]);
 });
}

for(const [width,height] of [[320,770],[393,852],[768,1024],[1440,900],[2048,1152],[2560,1440]]){
 for(const theme of ["dark","light"]){
  test("login "+theme+" "+width+": theme switch stays in header, no overlap",async({page},testInfo)=>{
   const {unauthorized,errors}=await isolation(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({colorScheme:theme,reducedMotion:"reduce"});
   await page.goto("/?preview=login");
   await setTheme(page,theme);
   await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
   const m=await bounds(page,{
    header:".orbit-auth-header",brand:".orbit-auth-brand",
    access:".orbit-auth-header-meta",actions:".orbit-auth-header-actions",
    theme:".hcc-login-theme",login:".orbit-access-form",route:".orbit-auth-route"
   });
   expect(m.scrollWidth,"No horizontal overflow").toBeLessThanOrEqual(width+1);
   expect(m.theme.position,"Theme button must not be fixed").not.toBe("fixed");
   expect(m.theme.x).toBeGreaterThanOrEqual(m.header.x-1);
   expect(m.theme.right).toBeLessThanOrEqual(m.header.right+1);
   expect(m.theme.y).toBeGreaterThanOrEqual(m.header.y-1);
   expect(m.theme.bottom).toBeLessThanOrEqual(m.header.bottom+1);
   expect(separated(m.brand,m.theme),"Theme overlaps logo").toBe(true);
   if(m.access.display!=="none"){
    expect(separated(m.access,m.theme),"Theme overlaps private access label").toBe(true);
   }
   await expect(page.getByRole("button",{name:/Тема:/})).toBeVisible();
   await expect(page.getByRole("button",{name:"Войти через GitHub"})).toBeDisabled();
   await testInfo.attach("login-"+theme+"-"+width+".png",{
    body:await page.screenshot({animations:"disabled",fullPage:false}),contentType:"image/png"});
   await testInfo.attach("login-"+theme+"-"+width+".json",{body:JSON.stringify(m,null,2),
    contentType:"application/json"});
   const btn=page.getByRole("button",{name:/Тема:/});
   await btn.focus();
   await expect(btn).toBeFocused();
   await btn.press("Enter");
   await expect(page.locator("html")).not.toHaveAttribute("data-hermes-theme",theme);
   expect(unauthorized).toEqual([]);expect(errors).toEqual([]);
  });
 }
}

test("login theme is in layout flow at narrow viewport",async({page})=>{
 const {unauthorized,errors}=await isolation(page);
 await page.setViewportSize({width:360,height:850});
 await page.goto("/?preview=login");
 await expect(page.locator(".orbit-auth-header-actions .hcc-login-theme")).toBeVisible();
 const m=await bounds(page,{header:".orbit-auth-header",brand:".orbit-auth-brand",
  theme:".hcc-login-theme",form:".orbit-access-form"});
 expect(m.scrollWidth).toBeLessThanOrEqual(361);
 expect(separated(m.brand,m.theme)).toBe(true);
 expect(m.theme.right).toBeLessThanOrEqual(361);
 expect(m.form.w).toBeGreaterThan(250);
 expect(unauthorized).toEqual([]);expect(errors).toEqual([]);
});
