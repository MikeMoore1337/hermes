import {test,expect} from "@playwright/test";

// #818. Only two explicit user themes; all requests are synthetic/same-origin.
test.use({serviceWorkers:"block"});

async function isolate(page){
 const errors=[],external=[];
 page.on("pageerror",error=>errors.push(error.message));
 await page.route("**/*",route=>{
  const u=new URL(route.request().url());
  if(u.origin!=="http://127.0.0.1:9133"||
     u.pathname.startsWith("/auth/")||u.pathname.startsWith("/api/auth/")){
   external.push(u.pathname.startsWith("/auth/")?"auth":"external");
   return route.abort("blockedbyclient");
  }
  if(u.pathname.startsWith("/api/"))return route.fulfill({
   status:503,contentType:"application/json",
   body:'{"error":"synthetic_unavailable"}'});
  return route.continue();
 });
 return {errors,external};
}

const opposite=theme=>theme==="dark"?"light":"dark";
const display=theme=>theme==="dark"?"Тёмная":"Светлая";
const current=page=>page.evaluate(()=>localStorage.getItem("hermes-control-center-ui-theme"));

async function assertTheme(page,theme){
 await expect(page.locator("html")).toHaveAttribute("data-hermes-theme",theme);
 await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme",theme);
 await expect.poll(()=>current(page)).toBe(theme);
 const color=await page.evaluate(()=>getComputedStyle(document.documentElement).colorScheme);
 expect(color).toBe(theme);
 await expect(page.getByRole("button",{name:/^Тема:/})).toHaveAttribute(
  "aria-label","Тема: "+display(theme)+". Переключить");
 await expect(page.getByRole("button",{name:/Системная/})).toHaveCount(0);
}

for(const [width,height] of [[320,770],[393,852],[1440,900]]){
 for(const theme of ["dark","light"]){
  test("explicit "+theme+" at "+width+" sticks across login and OS changes",async({page},testInfo)=>{
   const {errors,external}=await isolate(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({colorScheme:opposite(theme),reducedMotion:"reduce"});
   await page.goto("/");
   await page.evaluate(theme=>localStorage.setItem("hermes-control-center-ui-theme",theme),theme);
   await page.reload();
   await assertTheme(page,theme);
   const toggle=page.getByRole("button",{name:/^Тема:/});
   await toggle.focus();await expect(toggle).toBeFocused();
   await toggle.press("Enter");
   await assertTheme(page,opposite(theme));
   await page.emulateMedia({colorScheme:theme});
   await assertTheme(page,opposite(theme));
   await page.reload();
   await assertTheme(page,opposite(theme));
   await page.goto("/?preview=login");
   await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
   await assertTheme(page,opposite(theme));
   await page.getByRole("button",{name:/^Тема:/}).click();
   await assertTheme(page,theme);
   await page.goto("/");
   await assertTheme(page,theme);
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
   expect(overflow).toBeLessThanOrEqual(1);
   await testInfo.attach("themes-"+theme+"-"+width+".png",{
    body:await page.screenshot({animations:"disabled"}),contentType:"image/png"});
   expect(errors).toEqual([]);
   expect(external).toEqual([]);
  });
 }
}

for(const osTheme of ["dark","light"]){
 test("legacy system setting migrates once to "+osTheme,async({page})=>{
  const {errors,external}=await isolate(page);
  await page.emulateMedia({colorScheme:osTheme,reducedMotion:"reduce"});
  await page.goto("/");
  await page.evaluate(()=>localStorage.setItem("hermes-control-center-ui-theme","system"));
  await page.reload();
  await assertTheme(page,osTheme);
  await page.emulateMedia({colorScheme:opposite(osTheme)});
  await assertTheme(page,osTheme);
  await page.reload();
  await assertTheme(page,osTheme);
  expect(errors).toEqual([]);expect(external).toEqual([]);
 });
}

test("new session defaults to dark, not system",async({page})=>{
 const {errors,external}=await isolate(page);
 await page.emulateMedia({colorScheme:"light"});
 await page.goto("/");
 await assertTheme(page,"dark");
 await page.goto("/?preview=login");
 await assertTheme(page,"dark");
 expect(errors).toEqual([]);expect(external).toEqual([]);
});
