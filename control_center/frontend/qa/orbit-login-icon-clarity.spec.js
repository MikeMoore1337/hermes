import {test,expect} from "@playwright/test";

/** Issue #807: synthetic login icon and visual-noise regression, no live OAuth. */
test.use({serviceWorkers:"block"});

async function isolatedPreview(page) {
 const errors=[],unexpected=[];
 page.on("pageerror",error=>errors.push(error.message));
 await page.route("**/*",route=>{
  const url=new URL(route.request().url());
  if(url.origin!=="http://127.0.0.1:9133" ||
      url.pathname.startsWith("/auth/") || url.pathname.startsWith("/api/auth/")){
   unexpected.push(url.pathname.startsWith("/auth/")?"oauth":"external");
   return route.abort("blockedbyclient");
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"synthetic_unavailable"})});
  }
  return route.continue();
 });
 return {errors,unexpected};
}

async function setTheme(page,theme) {
 await page.evaluate(value=>localStorage.setItem("hermes-control-center-ui-theme",value),theme);
 await page.reload();
 await expect(page.locator("html")).toHaveAttribute("data-hermes-resolved-theme",theme);
}

// WCAG non-text contrast: the stroke must stand apart from its local card.
async function iconContrast(page,iconSelector,backgroundSelector) {
 return page.evaluate(([iconSelector,backgroundSelector])=>{
  const icon=document.querySelector(iconSelector);
  const surface=document.querySelector(backgroundSelector);
  if(!icon||!surface)throw new Error("Missing icon or background");
  const channels=color=>{
   const numbers=color.match(/[0-9.]+/g)?.slice(0,3).map(Number);
   if(!numbers||numbers.length!==3)throw new Error("Invalid RGB: "+color);
   return numbers;
  };
  const luminance=color=>{
   const rgb=channels(color).map(value=>{
    const n=value/255;
    return n<=0.04045?n/12.92:Math.pow((n+0.055)/1.055,2.4);
   });
   return rgb[0]*0.2126+rgb[1]*0.7152+rgb[2]*0.0722;
  };
  const foreground=luminance(getComputedStyle(icon).color);
  const background=luminance(getComputedStyle(surface).backgroundColor);
  return (Math.max(foreground,background)+0.05)/
   (Math.min(foreground,background)+0.05);
 },[iconSelector,backgroundSelector]);
}

for(const [width,height] of [[320,770],[393,852],[1440,900],[2560,1440]]){
 for(const theme of ["light","dark"]){
  test("quiet Orbit login "+theme+" at "+width,async({page},testInfo)=>{
   const {errors,unexpected}=await isolatedPreview(page);
   await page.setViewportSize({width,height});
   await page.emulateMedia({reducedMotion:"reduce",colorScheme:theme});
   await page.goto("/?preview=login");
   await setTheme(page,theme);
   await expect(page.getByRole("heading",{name:"Вход в систему"})).toBeVisible();
   await expect(page.getByRole("button",{name:"Войти через GitHub"})).toBeDisabled();
   await expect(page.locator(".orbit-route-node .orbit-node-name svg")).toHaveCount(3);
   await expect(page.locator(".orbit-access-steps > div:not(.orbit-access-steps-head) > svg")).toHaveCount(3);
   await expect(page.locator(".orbit-route-node .orbit-node-name img, .orbit-access-steps img")).toHaveCount(0);
   await expect(page.locator(".orbit-auth-header-meta, .orbit-access-top, .orbit-access-security, .orbit-right-foot, .orbit-auth-footer, .orbit-auth-schematic-note")).toHaveCount(0);
   const routeContrast=await iconContrast(page,
    ".orbit-node-policy .orbit-route-icon",".orbit-node-policy");
   const stepContrast=await iconContrast(page,
    ".orbit-access-steps .orbit-step-icon",".orbit-access-form");
   expect(routeContrast,"Route SVG should be perceptible").toBeGreaterThanOrEqual(3);
   expect(stepContrast,"Steps SVG should be perceptible").toBeGreaterThanOrEqual(3);
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
   expect(overflow,"No horizontal overflow").toBeLessThanOrEqual(1);
   const policy=page.locator(".orbit-node-policy");
   await policy.focus();await expect(policy).toBeFocused();
   await policy.press("Enter");
   await expect(policy).toHaveAttribute("aria-pressed","true");
   await expect(page.locator(".orbit-route-caption strong")).toContainText("Проверка доступа");
   await testInfo.attach("orbit-login-"+theme+"-"+width+".png",{
    body:await page.screenshot({animations:"disabled"}),
    contentType:"image/png"});
   expect(errors).toEqual([]);expect(unexpected).toEqual([]);
  });
 }
}
