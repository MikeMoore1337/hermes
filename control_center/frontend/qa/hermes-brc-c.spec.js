import {test,expect} from "@playwright/test";
// #455 approved C visual. Always synthetic API: never use live owner credentials.
test.use({serviceWorkers:"block"});
const projects=[
 ["Hermes Agent","hermes","main"],
 ["Your Fitness Coach","your-fitness-coach","master"],
 ["Second Brain","second-brain","main"],
 ["AI Development Toolkit","ai-development-toolkit","main"],
];
const devices=["H15 Windows permanent sandbox","H15 Hermes VPS sandbox","H15 YFC VPS sandbox"];
const snapshot=()=>({
 schema:1,source:"hermes_brc_mcp",status:"online",observed_at:new Date().toISOString(),
 execution_verified:false,native_host_access:false,onboarding_enabled:false,
 devices:devices.map(name=>({name,status:"online",last_seen_age_seconds:9,command_execution:"not_verified"})),
 workspaces:projects.map(([_,name,branch])=>({name,root:"/workspace/projects/"+name,
  branch,git_verified:false,state:"reachable_not_git_verified"}))
});
async function setup(page,packet=snapshot()){
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({
  status:200,contentType:"application/json",body:JSON.stringify(packet)
 }));
 await page.goto("/hermes-brc");
}
test("concept C reads only sanitized source and switches four projects",async({page})=>{
 await page.setViewportSize({width:1440,height:900});await setup(page);
 await expect(page.getByRole("heading",{name:"Рабочие пространства"})).toBeVisible();
 await expect(page.locator("#brc-health")).toHaveText("Hermes BRC · подключён");
 await expect(page.locator("#brc-device-count")).toHaveText("3/3");
 await expect(page.locator("#brc-project-count")).toHaveText("4/4");
 await expect(page.locator("#brc-devices li")).toHaveCount(3);
 for(const [title,repo,branch] of projects){
  const button=page.locator(`#brc-projects button[data-project="${repo}"]`);
  await button.click();
  await expect(button).toHaveAttribute("aria-pressed","true");
  await expect(page.locator("#brc-selected-name")).toHaveText(title);
  await expect(page.locator("#brc-path")).toHaveText("/workspace/projects/"+repo);
  await expect(page.locator("#brc-branch")).toHaveText(branch);
 }
 await expect(page.locator(".brc-facts")).toContainText("Не проверено");
 await expect(page.getByRole("button",{name:/Проверить инструменты/})).toBeDisabled();
 await expect(page.locator("body")).not.toContainText("D:\\Pet-projects");
});
for(const width of [320,390,768,1440]){
 test("C mobile/desktop overflow and unknown state "+width,async({page},testInfo)=>{
  await page.setViewportSize({width,height:width<400?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,
    contentType:"application/json",body:'{"error":"unavailable"}'}));
  await page.goto("/hermes-brc");
  await expect(page.locator("#brc-error")).toBeVisible();
  await expect(page.locator("#brc-device-count")).toHaveText("—");
  await expect(page.locator("#brc-selected-state")).toHaveText("НЕ ПРОВЕРЕНО");
  await expect(page.locator(".brc-state.online")).toHaveCount(0);
  await page.locator('button[data-project="second-brain"]').click();
  await expect(page.locator("#brc-path")).toHaveText("/workspace/projects/second-brain");
  const scroll=await page.evaluate(()=>({viewport:innerWidth,actual:document.documentElement.scrollWidth}));
  expect(scroll.actual,"unexpected horizontal scrolling").toBeLessThanOrEqual(scroll.viewport+1);
  await testInfo.attach("h455-concept-c-"+width+".png",{
   body:await page.screenshot({fullPage:true,animations:"disabled"}),contentType:"image/png"
  });
 });
}
test("C rejects forged capabilities, extra keys and expired snapshots",async({page})=>{
 for(const mutate of [
   v=>v.execution_verified=true,v=>v.native_host_access=true,v=>v.onboarding_enabled=true,
   v=>v.deviceId="SECRET_SENTINEL",
   v=>v.devices[1].command_execution="verified",
   v=>v.workspaces[0].root="/host-private",
   v=>v.observed_at="2020-01-01T00:00:00Z"
 ]){
  const bad=snapshot();mutate(bad);
  await setup(page,bad);
  await expect(page.locator("#brc-error")).toBeVisible();
  await expect(page.locator("#brc-health")).toContainText("недоступен");
  await expect(page.locator("body")).not.toContainText("SECRET_SENTINEL");
 }
});
