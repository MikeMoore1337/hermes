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
 await expect(page.getByRole("button",{name:"Скопировать запрос проверки"})).toBeEnabled();
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

test("C read-only diagnostics explain auth failure without granting tools",async({page})=>{
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:401,
  contentType:"application/json",body:'{"error":"authentication_required"}'}));
 await page.goto("/hermes-brc");
 await expect(page.locator("#brc-error")).toContainText("Войдите через GitHub");
 await expect(page.locator("#brc-diagnostic")).toContainText("Сессия");
 await expect(page.locator("#brc-device-count")).toHaveText("—");
 await expect(page.getByRole("button",{name:"Скопировать запрос проверки"})).toBeEnabled();
});
test("C corrects reported device recency by age of snapshot",async({page})=>{
 const valid=snapshot();valid.observed_at=new Date(Date.now()-90000).toISOString();
 await setup(page,valid);
 await expect(page.locator("#brc-devices li").first()).toContainText(/Последний сигнал: ~\d+ с назад/);
 await expect(page.locator("#brc-devices li").first()).not.toContainText("Последнее наблюдение: 9 с");
 await expect(page.locator("#brc-diagnostic")).toContainText("Доступность инструментов и Git не проверены");
});
test("C reports partial reachability without promoting devices to command ready",async({page})=>{
 const value=snapshot();value.devices[1].status="offline";value.status="partial";
 await setup(page,value);
 await expect(page.locator("#brc-diagnostic")).toContainText("часть устройств недоступна");
 await expect(page.locator("#brc-device-count")).toHaveText("2/3");
 await expect(page.getByRole("button",{name:"Скопировать запрос проверки"})).toBeEnabled();
});

test("owner source-check confirms snapshot only and never enables commands",async({page})=>{
 await page.setViewportSize({width:320,height:844});
 await setup(page);
 const checked={
  schema:1,source:"hermes_brc_validated_snapshot",check:"snapshot_validity_only",
  checked_at:new Date().toISOString(),snapshot_age_seconds:5,status:"online",
  devices:devices.map(name=>({name,status:"online",last_seen_age_seconds:14,
   command_execution:"not_verified"})),
  verification:{snapshot:"valid",relay:"not_probed",oauth:"not_probed",
   tools:"not_probed",git:"not_probed",onboarding:"disabled",native_host:"disabled"}
 };
 let calls=0;
 await page.route("**/api/providers/hermes-brc/source-check",route=>{
  calls++;return route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify(checked)});
 });
 await page.getByRole("button",{name:"Проверить источник"}).click();
 await expect(page.locator("#brc-source-result")).toContainText("онлайн 3/3");
 await expect(page.locator("#brc-source-result")).toContainText("не проверялись");
 expect(calls).toBe(1);
 await expect(page.getByRole("button",{name:"Скопировать запрос проверки"})).toBeEnabled();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(321);
});
test("source-check denies optimistic status on forged flags or missing auth",async({page})=>{
 await setup(page);
 const b=page.getByRole("button",{name:"Проверить источник"});
 await page.route("**/api/providers/hermes-brc/source-check",route=>
  route.fulfill({status:401,contentType:"application/json",body:"{}"}));
 await b.click();
 await expect(page.locator("#brc-source-result")).toContainText("Требуется авторизация");
 await page.unroute("**/api/providers/hermes-brc/source-check");
 await page.route("**/api/providers/hermes-brc/source-check",route=>
  route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify({schema:1,source:"hermes_brc_validated_snapshot",check:"snapshot_validity_only",
    checked_at:new Date().toISOString(),snapshot_age_seconds:1,status:"online",
    devices:devices.map(name=>({name,status:"online",last_seen_age_seconds:1,
     command_execution:"verified"})),verification:{snapshot:"valid",relay:"not_probed",oauth:"not_probed",
      tools:"not_probed",git:"not_probed",onboarding:"disabled",native_host:"disabled"}})}));
 await b.click();
 await expect(page.locator("#brc-source-result")).toContainText("Некорректный ответ");
 await expect(page.getByRole("button",{name:"Скопировать запрос проверки"})).toBeEnabled();
});

test("guided check copies canonical read-only prompt for selected project",async({page})=>{
 await page.addInitScript(()=>{
   Object.defineProperty(navigator,"clipboard",{configurable:true,
    value:{writeText:async text=>{window.__h455Copied=text;}}});
 });
 await setup(page);
 await page.locator('button[data-project="ai-development-toolkit"]').click();
 await page.getByRole("button",{name:"Скопировать запрос проверки"}).click();
 await expect(page.locator("#brc-client-check-status")).toContainText("скопирован");
 const value=await page.evaluate(()=>window.__h455Copied);
 expect(value).toContain("ai-development-toolkit");
 expect(value).toContain("/workspace/projects/ai-development-toolkit");
 expect(value).toContain("list_devices");
 expect(value).toContain("list_workspaces");
 expect(value).toContain("resolve_workspace");
 expect(value).toContain("list_directory");
 expect(value).toContain("get_file_info");
 expect(value).toContain("\n");
 expect(value).not.toContain("h15-win-05be");
 expect(value).not.toContain("D:\\Pet-projects");
 expect(value).not.toContain("start_process");
 expect(value).not.toContain("write_file");
});
test("guided check stays non-executing with offline API and clipboard denial",async({page})=>{
 await page.setViewportSize({width:320,height:844});
 await page.addInitScript(()=>{
  Object.defineProperty(navigator,"clipboard",{configurable:true,
   value:{writeText:async()=>{throw Error("denied");}}});
 });
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({
  status:503,contentType:"application/json",body:'{"error":"unavailable"}'
 }));
 let otherCalls=0;
 await page.route("**/api/**",route=>{otherCalls++;return route.abort();});
 await page.goto("/hermes-brc");
 await page.getByRole("button",{name:"Скопировать запрос проверки"}).click();
 await expect(page.locator("#brc-client-check-status")).toContainText("Копирование недоступно");
 expect(otherCalls).toBe(0);
 await expect(page.locator("#brc-device-count")).toHaveText("—");
 const geometry=await page.evaluate(()=>({
  inner:window.innerWidth,scroll:document.documentElement.scrollWidth
 }));
 expect(geometry.scroll).toBeLessThanOrEqual(geometry.inner+1);
});
