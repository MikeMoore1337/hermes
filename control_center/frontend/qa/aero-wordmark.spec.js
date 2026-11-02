import {test,expect} from "@playwright/test";

/** H-733: visual-width contract for the already approved Aero wordmark.
 * The server and API remain read-only: no owner credentials or production calls.
 */
test.use({serviceWorkers:"block"});

async function isolate(page){
 const blocked=[];
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  const local=url.origin==="http://127.0.0.1:9133";
  if(!local||url.pathname.startsWith("/auth/")||url.pathname.startsWith("/api/auth/")){
   blocked.push(local?"auth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname==="/api/overview"){
   return route.fulfill({status:200,contentType:"application/json",
    body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),
     services:[{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",
      state:"active",kind:"schedule"}]})});
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"synthetic_unavailable"})});
  }
  return route.continue();
 });
 return blocked;
}

async function measureWordmark(page,selector){
 return page.locator(selector).evaluate(container=>{
  const [title,subtitle]=container.children;
  const textRect=el=>{
   const range=document.createRange();
   range.selectNodeContents(el);
   const rect=range.getBoundingClientRect();
   return {left:rect.left,right:rect.right,width:rect.width,
    whiteSpace:getComputedStyle(el).whiteSpace};
  };
  const bounds=container.getBoundingClientRect();
  return {title:textRect(title),subtitle:textRect(subtitle),
   container:{left:bounds.left,right:bounds.right},
   viewport:document.documentElement.clientWidth,
   scrollWidth:document.documentElement.scrollWidth};
 });
}

function assertAligned(m,label){
 // Match text advances, not only the stretched block widths.
 const difference=Math.abs(m.title.width-m.subtitle.width);
 expect(difference, label+": wordmark text-length delta").toBeLessThanOrEqual(2.5);
 expect(Math.abs(m.title.left-m.subtitle.left),
   label+": shared starting edge").toBeLessThanOrEqual(1.5);
 expect(m.title.whiteSpace).toBe("nowrap");
 expect(m.subtitle.whiteSpace).toBe("nowrap");
 expect(m.container.left, label+": clipped at the left").toBeGreaterThanOrEqual(-1);
 expect(m.container.right, label+": clipped at the right").toBeLessThanOrEqual(m.viewport+1);
 expect(m.scrollWidth, label+": horizontal overflow").toBeLessThanOrEqual(m.viewport+1);
}

for(const width of [320,393,768,1440,1920]){
 test("Aero login wordmark equal text widths at "+width, async({page},testInfo)=>{
  const blocked=await isolate(page),errors=[];
  page.on("pageerror",err=>errors.push(err.message));
  await page.setViewportSize({width,height:width<768?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await page.goto("/?preview=login");
  await expect(page.locator(".orbit-auth-brand")).toBeVisible();
  await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
  const metrics=await measureWordmark(page,".orbit-auth-brand > div");
  assertAligned(metrics, "login "+width);
  await testInfo.attach("aero-login-"+width+".png",{
   body:await page.locator(".orbit-auth-header").screenshot({animations:"disabled"}),
   contentType:"image/png"});
  expect(errors).toEqual([]);
  expect(blocked).toEqual([]);
 });
}

for(const width of [1024,1440,1920]){
 test("Aero operator sidebar wordmark equal text widths at "+width, async({page},testInfo)=>{
  const blocked=await isolate(page),errors=[];
  page.on("pageerror",err=>errors.push(err.message));
  await page.setViewportSize({width,height:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await page.goto("/");
  await expect(page.locator(".orbit-rail-brand .brand-text")).toBeVisible();
  const metrics=await measureWordmark(page,".orbit-rail-brand .brand-text");
  assertAligned(metrics, "operator "+width);
  await testInfo.attach("aero-operator-"+width+".png",{
   body:await page.locator(".orbit-rail-brand").screenshot({animations:"disabled"}),
   contentType:"image/png"});
  expect(errors).toEqual([]);
  expect(blocked).toEqual([]);
 });
}
