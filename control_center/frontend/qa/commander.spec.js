import {test,expect} from "@playwright/test";
// Approved Project Explorer (#455), all API data synthetic and fail-closed.
test.use({serviceWorkers:"block"});
const projects=[
 ["Hermes","D:\\Pet-projects\\hermes"],
 ["AI Development Toolkit","D:\\Pet-projects\\ai-development-toolkit"],
 ["Second Brain","D:\\Pet-projects\\second-brain-workspace\\second-brain"],
 ["Your Fitness Coach","D:\\Pet-projects\\your-fitness-coach"],
];
async function openCommander(page){
 await page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]})}));
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,contentType:"application/json",
  body:JSON.stringify({error:"synthetic_unavailable"})}));
 await page.goto("/");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Hermes Commander"}).click();
 await expect(page.locator(".hc-root")).toBeVisible();
}
test("approved Explorer renders project and distinct Windows/sandbox scopes",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await openCommander(page);
 await expect(page.getByRole("heading",{name:"Hermes",exact:true})).toBeVisible();
 await expect(page.locator(".hc-map")).toContainText("/workspace/projects/hermes");
 await expect(page.locator(".hc-map")).toContainText("D:\\Pet-projects\\hermes");
 await expect(page.locator(".hc-map")).toContainText("НЕ ПОДКЛЮЧЁН");
 await expect(page.locator(".hc-observe")).toContainText("503");
 for(const [label,path] of projects){
  await page.locator(".hc-projects").getByRole("button",{name:new RegExp(label)}).click();
  await expect(page.locator(".hc-contexts")).toContainText(path);
 }
 await page.locator(".hc-projects").getByRole("button",{name:/Second Brain/}).click();
 await page.getByRole("tab",{name:"Windows"}).click();
 await expect(page.locator(".hc-tabpanel")).toContainText("second-brain-workspace");
 await expect(page.locator(".hc-tabpanel")).toContainText("не предоставлен");
 await page.getByRole("button",{name:"К панели"}).click();
 await expect(page.getByRole("heading",{name:"Система. Под наблюдением."})).toBeVisible();
});
for(const width of [320,393,768,1440]){
 test("Explorer responsive, safe defaults and keyboard "+width,async({page},testInfo)=>{
  await page.setViewportSize({width,height:width<=393?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await openCommander(page);
  await expect(page.locator(".hc-status-online")).toHaveCount(0);
  await expect(page.locator(".hc-map")).toBeVisible();
  if(width<=393){
    const devices=page.locator(".hc-mobilebar").getByRole("button",{name:"Устройства"});
    await devices.click();await expect(devices).toHaveAttribute("aria-expanded","true");
    await expect(page.locator("#hc-device-list")).toBeVisible();
    await devices.click();await expect(devices).toHaveAttribute("aria-expanded","false");
  }
  const layout=await page.evaluate(()=>({w:innerWidth,doc:document.documentElement.scrollWidth}));
  expect(layout.doc,"horizontal overflow").toBeLessThanOrEqual(layout.w+1);
  await page.getByRole("tab",{name:"Git"}).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".hc-tabpanel")).toContainText("NOT VERIFIED");
  await testInfo.attach("commander-approved-"+width+".png",{
   body:await page.screenshot({fullPage:true,animations:"disabled"}),contentType:"image/png"
  });
 });
}
test("Explorer never renders forged BRC runtime status",async({page})=>{
 await page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]})}));
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,source:"hermes_brc_mcp",status:"online",
   execution_verified:true,native_host_access:true,deviceId:"secret",
   observed_at:new Date().toISOString(),devices:[],workspaces:[]})}));
 await page.goto("/");
 await page.locator(".atlas-section-nav").getByRole("button",{name:"Hermes Commander"}).click();
 await expect(page.locator(".hc-observe")).toContainText("контракту");
 await expect(page.locator(".hc-status-online")).toHaveCount(0);
 await expect(page.locator(".hc-root")).not.toContainText("secret");
});
