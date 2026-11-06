import {test,expect} from "@playwright/test";

/** #814: synthetic-only Aero palette, single focus ring and quota-grid regression. */
test.use({serviceWorkers:"block"});

const observedAt="2026-11-06T02:00:00Z";
const services=[
 {id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
 {id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed",kind:"schedule"}
];
const percentage=(label,remaining)=>({
 metric:"subscription_share",label,unit:"percent",quota_limit:null,
 used:null,remaining:null,used_percent:100-remaining,remaining_percent:remaining,
 reset_at_utc:observedAt,source_kind:"official_api"
});
const providers=[
 {id:"cloudflare_workers_ai",status:"unknown",observed_at:null,
  notes:"account_usage_unavailable",source_kind:"unknown",
  limit_documentation:"https://developers.cloudflare.com/workers-ai/platform/pricing/",
  windows:[{metric:"neurons_daily",label:"Суточная квота Free",unit:"neurons",
   quota_limit:10000,used:null,remaining:null,used_percent:null,remaining_percent:null,
   reset_at_utc:observedAt,source_kind:"unknown"}]},
 {id:"codex",status:"low",observed_at:observedAt,notes:"official_account_snapshot",
  source_kind:"official_api",windows:[percentage("300 мин",82)]},
 {id:"desktop_commander",status:"unknown",observed_at:null,
  notes:"not_configured",source_kind:"unknown",windows:[]},
 {id:"github_api",status:"low",observed_at:observedAt,
  notes:"per_token_rate_limit_collected",source_kind:"official_api",
  windows:[percentage("API core",93),percentage("API search",80)]}
];
const inbox={
 schema:1,mode:"read_only",actions_enabled:false,completeness:"PARTIAL",
 summary:{total:1,critical:1,review:0,available_sources:1,source_count:2},
 sources:{ops:{status:"SUPPORTED",label:"Ops Watch"},
  github:{status:"PARTIAL",label:"GitHub"}},
 events:[{event_id:"synthetic-1",title:"Синтетический сбой",
  detail:"Только тестовая фикстура",action_hint:"Проверить источник отдельно",
  severity:"critical",category:"failure",status:"needs_review",
  source:"synthetic",evidence_link:null,observed_at:observedAt,last_verified_at:observedAt}]
};
async function synthetic(page){
 const errors=[],outbound=[];
 page.on("pageerror",error=>errors.push(error.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133"||
     url.pathname.startsWith("/auth/")||url.pathname.startsWith("/api/auth/")){
   outbound.push(url.pathname.startsWith("/auth/")?"auth":"external");
   return route.abort("blockedbyclient");
  }
  const bodies={
   "/api/overview":{schema:1,mode:"read_only",generated_at:observedAt,services},
   "/api/operator/inbox":inbox,
   "/api/providers/registry":{schema:1,read_only:true,observed_at:observedAt,providers}
  };
  if(url.pathname in bodies)return route.fulfill({
   status:200,contentType:"application/json",body:JSON.stringify(bodies[url.pathname])});
  if(url.pathname.startsWith("/api/"))return route.fulfill({
   status:503,contentType:"application/json",body:'{"error":"synthetic_unavailable"}'});
  return route.continue();
 });
 return {errors,outbound};
}
async function openView(page,name,width){
 const nav=page.locator(".atlas-section-nav");
 if(width<=700){
  const quick=page.locator(".orbit-app-mobilebar").getByRole("button",{name,exact:true});
  if(await quick.count()){await quick.click();return;}
  const more=page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"});
  if(await more.getAttribute("aria-expanded")!=="true")await more.click();
 }
 await nav.getByRole("button",{name,exact:true}).click();
}
async function contrast(page,foreground,background){
 return page.evaluate(([fg,bg])=>{
  const channels=color=>(color.match(/[0-9.]+/g)||[]).slice(0,3).map(Number);
  const luminance=color=>{
   const rgb=channels(color);
   if(rgb.length!==3)throw Error("Invalid CSS RGB "+color);
   const linear=rgb.map(x=>{const y=x/255;return y<=.04045?y/12.92:Math.pow((y+.055)/1.055,2.4);});
   return linear[0]*.2126+linear[1]*.7152+linear[2]*.0722;
  };
  const a=luminance(getComputedStyle(document.querySelector(fg)).color);
  const b=luminance(getComputedStyle(document.querySelector(bg)).backgroundColor);
  return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
 },[foreground,background]);
}

for(const [width,height] of [[320,770],[393,852],[1440,900],[2048,1152]]){
 for(const theme of ["light","dark"]){
  test("Aero readability and quota grid "+theme+" "+width,async({page},testInfo)=>{
   const {errors,outbound}=await synthetic(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({colorScheme:theme,reducedMotion:"reduce"});
   await page.goto("/");
   await page.evaluate(value=>localStorage.setItem("hermes-control-center-ui-theme",value),theme);
   await page.reload();
   await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme",theme);

   await openView(page,"Ops Watch",width);
   await expect(page.locator(".registry-panel")).toBeVisible();
   const field=page.locator(".search-field"),input=field.locator("input");
   await input.focus();
   const focus=await input.evaluate(el=>({
    inner:getComputedStyle(el).outlineStyle,
    shadow:getComputedStyle(el.closest(".search-field")).boxShadow,
    outer:getComputedStyle(el.closest(".search-field")).outlineStyle
   }));
   expect(focus.inner,"The input must not draw a second blue outline").toBe("none");
   expect(focus.outer,"Composite control must not draw an additional outline").toBe("none");
   expect(focus.shadow,"One visible focus ring around the search container").not.toBe("none");
   await input.fill("Ops");
   await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
   const labelFont=await page.locator(".service-label small").first().evaluate(el=>parseFloat(getComputedStyle(el).fontSize));
   expect(labelFont).toBeGreaterThanOrEqual(12);

   await openView(page,"Входящие",width);
   await expect(page.locator(".oi-row-copy small")).toBeVisible();
   const smallFont=await page.locator(".oi-row-copy small").first().evaluate(el=>parseFloat(getComputedStyle(el).fontSize));
   expect(smallFont).toBeGreaterThanOrEqual(12);
   expect(await contrast(page,".oi-row-copy small",".oi-queue")).toBeGreaterThanOrEqual(4.5);
   await expect(page.locator(".oi-notice")).toBeVisible();
   expect(await contrast(page,".oi-notice",".oi-notice")).toBeGreaterThanOrEqual(4.5);
   const hint=page.locator(".oi-action-hint");
   await expect(hint).toBeVisible();
   const hintSurface=await hint.evaluate(el=>getComputedStyle(el).backgroundColor);
   expect(hintSurface).not.toBe("rgb(17, 44, 73)");
   const inboxInput=page.locator(".oi-search input");
   await inboxInput.focus();
   expect(await inboxInput.evaluate(el=>getComputedStyle(el).outlineStyle)).toBe("none");
   expect(await page.locator(".oi-search").evaluate(el=>getComputedStyle(el).boxShadow)).not.toBe("none");

   await openView(page,"Квоты и инструменты",width);
   const cards=page.locator(".quota295-card");
   await expect(cards).toHaveCount(4);
   await expect(page.locator(".quota295-card[data-provider='cloudflare_workers_ai']")).toBeVisible();
   await expect(page.locator(".quota295-card[data-provider='github_api']")).toBeVisible();
   const boxes=await cards.evaluateAll(items=>items.map(el=>{
    const r=el.getBoundingClientRect();
    return {x:r.x,y:r.y,w:r.width,h:r.height,bottom:r.bottom};
   }));
   if(width>=1440){
    expect(Math.abs(boxes[0].y-boxes[1].y),"Top row aligned").toBeLessThanOrEqual(1);
    expect(Math.abs(boxes[0].h-boxes[1].h),"Top cards equal height").toBeLessThanOrEqual(1);
    expect(Math.abs(boxes[2].y-boxes[3].y),"Second row aligned").toBeLessThanOrEqual(1);
    expect(Math.abs(boxes[2].h-boxes[3].h),"Second row cards equal height").toBeLessThanOrEqual(1);
    expect(Math.abs(boxes[0].w-boxes[1].w),"Equal column widths").toBeLessThanOrEqual(1);
    expect(boxes[2].y).toBeGreaterThanOrEqual(boxes[0].bottom+10);
   }else{
    for(let i=1;i<boxes.length;i++)expect(boxes[i].y).toBeGreaterThan(boxes[i-1].bottom);
   }
   const smallQuota=await cards.first().locator(".quota295-note").first()
    .evaluate(el=>parseFloat(getComputedStyle(el).fontSize));
   expect(smallQuota).toBeGreaterThanOrEqual(12);
   await testInfo.attach("aero814-"+theme+"-"+width+".png",{
    body:await page.screenshot({animations:"disabled"}),contentType:"image/png"});
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
   expect(overflow,"No horizontal overflow").toBeLessThanOrEqual(1);
   expect(errors).toEqual([]);
   expect(outbound).toEqual([]);
  });
 }
}
